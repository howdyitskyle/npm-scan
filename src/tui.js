import { createElement as h } from 'react';
import { render, Box, Text, Transform, useStdout } from 'ink';
import { Spinner } from '@inkjs/ui';
import gradient from 'gradient-string';
import { fmt, plural, sleep } from './util.js';

const MIN_DISPLAY_MS = 2000;

export function dotsFor(elapsedMs) {
  return '.'.repeat(1 + (Math.floor(elapsedMs / 300) % 3));
}

/* ---------- design tokens (Neon/Hacker) ---------- */
const T = {
  ok: '#00ff9c',
  info: '#00d4ff',
  accent: '#ff2ec4',
  danger: '#ff4d4d',
  warn: '#ffd166',
  dim: '#5a5a6e',
};

const CHIP_COLORS = { ok: T.ok, fail: T.danger, warn: T.warn, info: T.info, stale: T.dim };

export function isTuiEligible({ stdout, opts }) {
  return (
    Boolean(stdout) &&
    stdout.isTTY === true &&
    opts.format === 'pretty' &&
    !opts.noTui &&
    !process.env.CI &&
    process.env.TERM !== 'dumb'
  );
}

export function initialTuiState({ lockfile, version }) {
  return {
    lockfile,
    version,
    elapsedMs: 0,
    sources: [],
    sourcesDone: 0,
    sourcesTotal: 0,
    osv: { status: 'idle', done: 0, total: 0 },
    classify: null,
    enrich: null,
    done: null,
  };
}

export function reduceTuiState(state, ev) {
  switch (ev.phase) {
    case 'tick':
      return { ...state, elapsedMs: ev.elapsedMs };
    case 'sources': {
      if (ev.status === 'start') {
        return {
          ...state,
          sourcesTotal: state.sourcesTotal + 1,
          sources: [...state.sources, { id: ev.id, label: ev.label, status: 'downloading', entries: null }],
        };
      }
      if (ev.status === 'done' || ev.status === 'error') {
        const sources = state.sources.map((s) =>
          s.id === ev.id ? { ...s, status: ev.status, entries: ev.entries ?? s.entries } : s
        );
        return { ...state, sources, sourcesDone: state.sourcesDone + 1 };
      }
      return { ...state, sources: state.sources.map((s) => (s.id === ev.id ? { ...s, status: ev.status } : s)) };
    }
    case 'osv-batch':
      return { ...state, osv: { status: 'running', done: ev.done, total: ev.total } };
    case 'osv-classify':
      return { ...state, classify: { done: ev.done, total: ev.total } };
    case 'osv-enrich':
      return { ...state, enrich: { done: ev.done, total: ev.total } };
    case 'osv-status':
      return { ...state, osv: { ...state.osv, status: ev.status } };
    case 'done':
      return { ...state, done: { found: ev.found, scanned: ev.scanned, durationMs: ev.durationMs } };
    default:
      return state;
  }
}

/* ---------- responsive layout (pure, testable) ---------- */
export function layout(cols) {
  if (cols >= 110) return { frame: true, columns: 2 };
  if (cols >= 80) return { frame: true, columns: 1 };
  return { frame: false, columns: 1 };
}

/* ---------- building blocks ---------- */
function Rule({ width }) {
  return h(Text, { color: T.dim }, '\u2500'.repeat(Math.max(0, width)));
}

function Chip({ tone = 'info', children }) {
  const color = CHIP_COLORS[tone] || T.info;
  return h(
    Text,
    null,
    h(Text, { dimColor: true }, '['),
    h(Text, { color }, ` ${children} `),
    h(Text, { dimColor: true }, ']')
  );
}

function SourceRow({ s }) {
  if (s.status === 'done') {
    return h(
      Box,
      null,
      h(Text, { color: T.ok }, '\u2713 '),
      h(Text, null, s.label),
      s.entries != null && h(Text, { dimColor: true }, ` ${fmt(s.entries)} indicators`)
    );
  }
  if (s.status === 'error') {
    return h(
      Box,
      null,
      h(Text, { color: T.danger }, '\u2717 '),
      h(Text, null, s.label),
      h(Text, null, ' '),
      h(Chip, { tone: 'fail' }, 'FAIL')
    );
  }
  if (s.status === 'cached' || s.status === 'stale') {
    const color = s.status === 'stale' ? T.warn : T.ok;
    return h(
      Box,
      null,
      h(Text, { color }, '\u2713 '),
      h(Text, null, s.label),
      h(Text, null, ' '),
      h(Chip, { tone: s.status === 'stale' ? 'stale' : 'info' }, s.status.toUpperCase())
    );
  }
  return h(Spinner, { label: s.label });
}

export function ScanUi({ state }) {
  const { stdout } = useStdout();
  const cols = stdout.columns || 80;
  const { frame, columns } = layout(cols);
  const innerWidth = cols - (frame ? 4 : 0);

  const header = h(
    Box,
    null,
    h(Transform, { transform: (s) => gradient('cyan', '#ff2ec4')(s) }, `npm-scan v${state.version}`),
    h(Text, { dimColor: true }, ' '),
    h(Chip, { tone: 'info' }, `scanning ${state.lockfile}`)
  );

  const rule = h(Rule, { width: innerWidth });

  const sourcesBlock = [
    rule,
    h(
      Text,
      null,
      h(Text, { color: T.accent }, 'indicators'),
      h(Text, { dimColor: true }, ` \u00b7 ${state.sourcesDone}/${state.sourcesTotal} sources`)
    ),
    h(Box, { flexDirection: 'column' }, ...state.sources.map((s) => h(SourceRow, { key: s.id, s }))),
  ];

  const dots = dotsFor(state.elapsedMs);
  const phases = [];
  if (state.osv.status === 'running') {
    phases.push(h(Text, { color: T.info }, `osv check${dots}`));
  } else if (state.osv.status === 'done') {
    phases.push(h(Text, { color: T.ok }, '\u2713 osv check complete'));
  } else if (state.osv.status === 'skipped') {
    phases.push(h(Text, { color: T.warn }, '\u26a0 osv check skipped'));
  }
  if (state.classify) {
    phases.push(h(Spinner, { label: `classifying  ${state.classify.done}/${state.classify.total}` }));
  }
  if (state.enrich) {
    phases.push(h(Spinner, { label: `enriching  ${state.enrich.done}/${state.enrich.total}` }));
  }

  const phasesBlock = phases.length > 0 ? [rule, h(Box, { flexDirection: 'column' }, ...phases)] : [];

  const entriesTotal = state.sources.reduce((sum, s) => sum + (s.entries || 0), 0);
  const footer = h(
    Text,
    null,
    h(Text, { dimColor: true }, `scanned ${state.done ? state.done.scanned : state.sourcesDone} packages \u00b7 ${fmt(entriesTotal)} indicators \u00b7 `),
    h(Text, { color: T.info }, `${(state.elapsedMs / 1000).toFixed(1)}s`),
    h(Text, { dimColor: true }, ' \u00b7 '),
    state.done
      ? h(
          Text,
          { bold: true, color: state.done.found > 0 ? T.danger : T.ok },
          state.done.found > 0
            ? plural(state.done.found, 'malicious package')
            : 'no known malicious packages found'
        )
      : h(Text, { dimColor: true }, 'scanning\u2026')
  );

  const children = [header];
  if (columns === 2) {
    children.push(
      h(
        Box,
        { flexDirection: 'row' },
        h(Box, { flexDirection: 'column', width: '50%' }, ...sourcesBlock),
        h(Box, { flexDirection: 'column', width: '50%' }, ...phasesBlock)
      ),
      rule,
      footer
    );
  } else {
    children.push(...sourcesBlock, ...phasesBlock, rule, footer);
  }

  const root =
    frame
      ? h(Box, { borderStyle: 'round', borderColor: T.dim, flexDirection: 'column', paddingX: 1 }, ...children)
      : h(Box, { flexDirection: 'column' }, ...children);
  return root;
}

export async function runTui({ stdout, stderr, lockfile, version }, work) {
  let instance = null;
  let current = initialTuiState({ lockfile, version });
  let finished = false;
  const pending = [];
  const renderState = () => {
    try {
      if (instance) instance.rerender(h(ScanUi, { state: current }));
    } catch {}
  };
  const emit = (ev) => {
    const terminal = ev.phase === 'done' || (ev.phase === 'osv-status' && (ev.status === 'done' || ev.status === 'skipped'));
    if (!finished && terminal) {
      pending.push(ev);
      return;
    }
    current = reduceTuiState(current, ev);
    renderState();
  };
  const flushPending = () => {
    if (pending.length === 0) return;
    for (const ev of pending) current = reduceTuiState(current, ev);
    pending.length = 0;
    renderState();
  };
  const startedAt = Date.now();
  instance = render(h(ScanUi, { state: current }), { stdout, stderr });
  const timer = setInterval(() => {
    current = reduceTuiState(current, { phase: 'tick', elapsedMs: Date.now() - startedAt });
    if (!finished && Date.now() - startedAt >= MIN_DISPLAY_MS) flushPending();
    renderState();
  }, 200);
  try {
    const result = await work(emit);
    finished = true;
    const elapsed = Date.now() - startedAt;
    if (elapsed < MIN_DISPLAY_MS) await sleep(MIN_DISPLAY_MS - elapsed);
    flushPending();
    clearInterval(timer);
    instance.clear();
    instance.unmount();
    return result;
  } catch (e) {
    clearInterval(timer);
    instance.clear();
    instance.unmount();
    throw e;
  }
}
