import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { render } from 'ink';
import { createElement as h } from 'react';
import { main, runScan } from '../src/cli.js';
import { isTuiEligible, initialTuiState, reduceTuiState, layout, dotsFor, ScanUi } from '../src/tui.js';
import { setFetch } from '../src/util.js';
import { SOURCES } from '../src/sources.js';

const ADVISORIES = {
  'MAL-2026-11524': {
    summary: 'Malicious code in keyv',
    references: [{ url: 'https://www.npmjs.com/package/keyv/v/6.0.0' }],
    aliases: ['GHSA-3p9h-f68w-m6fx'],
    severity: [{ type: 'CVSS_V3', score: '7.5' }],
    affected: [
      {
        package: { ecosystem: 'npm', name: 'keyv' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.0.1' }] }],
      },
    ],
    database_specific: { type: 'MALICIOUS' },
  },
  'GHSA-evil-mmmm-cccc': {
    summary: 'Malicious code in evil',
    database_specific: { type: 'MALICIOUS' },
  },
};

const OSV_QUERIES = {
  'keyv@6.0.0': { vulns: [{ id: 'MAL-2026-11524' }] },
  'evil@1.0.0': { vulns: [{ id: 'GHSA-evil-mmmm-cccc' }] },
};

const CSV = {
  keyv: 'ecosystem,package,versions\nnpm,keyv,6.0.0\n',
  shai: 'package_name,package_versions,sources\nkeyv,6.0.0,campaign\n',
  axios: 'type,indicator,context\nnpm package,keyv@6.0.0,observed\n',
  teampcp: 'artifact_type,name,affected_versions\nnpm package,keyv,"6.0.0"\n',
};

const MOCK_CSV_URLS = {
  [SOURCES.keyv.url]: CSV.keyv,
  [SOURCES['shai-hulud'].url]: CSV.shai,
  [SOURCES.axios.url]: CSV.axios,
  [SOURCES.teampcp.url]: CSV.teampcp,
};

function mockFetch(url, opts = {}) {
  if (MOCK_CSV_URLS[url]) return Promise.resolve(new Response(MOCK_CSV_URLS[url], { status: 200 }));
  if (url.startsWith('https://api.osv.dev/v1/querybatch')) {
    const body = JSON.parse(opts.body || '{}');
    const results = (body.queries || []).map((q) => OSV_QUERIES[`${q.package.name}@${q.version}`] || {});
    return Promise.resolve(new Response(JSON.stringify({ results }), { status: 200 }));
  }
  const vulnMatch = url.match(/^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/);
  if (vulnMatch) {
    const adv = ADVISORIES[vulnMatch[1]];
    if (!adv) return Promise.resolve(new Response('not found', { status: 404 }));
    return Promise.resolve(new Response(JSON.stringify(adv), { status: 200 }));
  }
  return Promise.resolve(new Response('not found', { status: 404 }));
}

let dir;
let cacheDir;

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'npm-scan-tui-'));
  cacheDir = join(dir, 'cache');
  setFetch(mockFetch);
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

function capture(isTTY = false) {
  return {
    text: '',
    isTTY,
    columns: 120,
    rows: 30,
    write(s) {
      this.text += s;
    },
    on() {},
    off() {},
    setRawMode() {},
    clearLine() {},
    cursorTo() {},
  };
}

async function writeLock(name, packages) {
  const path = join(dir, name);
  await writeFile(
    path,
    JSON.stringify({
      name: 'tui',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: Object.fromEntries(Object.keys(packages).map((k) => [k, packages[k].version])) },
        ...Object.fromEntries(
          Object.entries(packages).map(([k, v]) => [`node_modules/${k}`, { version: v.version }])
        ),
      },
    })
  );
  return path;
}

function scanOpts(overrides = {}) {
  return {
    lockfile: null,
    sources: 'all',
    csv: [],
    noOsv: false,
    verbose: false,
    ttl: 0,
    cacheDir,
    format: 'pretty',
    retries: 0,
    timeoutMs: 30000,
    backoffMs: 100,
    noTui: false,
    ...overrides,
  };
}

test('isTuiEligible: requires TTY, pretty format, no --no-tui, no CI, sane TERM', () => {
  const opts = scanOpts();
  const savedCi = process.env.CI;
  const savedTerm = process.env.TERM;
  try {
    delete process.env.CI;
    delete process.env.TERM;
    assert.equal(isTuiEligible({ stdout: capture(true), opts }), true);
    assert.equal(isTuiEligible({ stdout: capture(false), opts }), false, 'non-TTY stdout must be ineligible');
    assert.equal(isTuiEligible({ stdout: null, opts }), false);
    assert.equal(isTuiEligible({ stdout: capture(true), opts: scanOpts({ format: 'json' }) }), false);
    assert.equal(isTuiEligible({ stdout: capture(true), opts: scanOpts({ noTui: true }) }), false);

    process.env.CI = 'true';
    assert.equal(isTuiEligible({ stdout: capture(true), opts }), false, 'CI must disable the TUI');
    delete process.env.CI;
    process.env.TERM = 'dumb';
    assert.equal(isTuiEligible({ stdout: capture(true), opts }), false, 'TERM=dumb must disable the TUI');
  } finally {
    if (savedCi === undefined) delete process.env.CI;
    else process.env.CI = savedCi;
    if (savedTerm === undefined) delete process.env.TERM;
    else process.env.TERM = savedTerm;
  }
});

test('reduceTuiState: tracks sources, osv, classify, enrich, done', () => {
  let s = initialTuiState({ lockfile: 'package-lock.json', version: '1.2.0' });
  s = reduceTuiState(s, { phase: 'sources', id: 'keyv', label: 'DataDog keyv-campaign', status: 'start' });
  assert.equal(s.sourcesTotal, 1);
  assert.equal(s.sources[0].status, 'downloading');
  s = reduceTuiState(s, { phase: 'sources', id: 'keyv', status: 'downloading' });
  s = reduceTuiState(s, { phase: 'sources', id: 'keyv', status: 'done', entries: 2234 });
  assert.equal(s.sources[0].status, 'done');
  assert.equal(s.sources[0].entries, 2234);
  assert.equal(s.sourcesDone, 1);
  s = reduceTuiState(s, { phase: 'osv-batch', done: 2, total: 3 });
  assert.deepEqual(s.osv, { status: 'running', done: 2, total: 3 });
  s = reduceTuiState(s, { phase: 'osv-classify', done: 1, total: 1 });
  assert.deepEqual(s.classify, { done: 1, total: 1 });
  s = reduceTuiState(s, { phase: 'osv-enrich', done: 2, total: 2 });
  assert.deepEqual(s.enrich, { done: 2, total: 2 });
  s = reduceTuiState(s, { phase: 'osv-status', status: 'done' });
  assert.equal(s.osv.status, 'done');
  s = reduceTuiState(s, { phase: 'done', found: 1, scanned: 5, durationMs: 123 });
  assert.deepEqual(s.done, { found: 1, scanned: 5, durationMs: 123 });
});

test('reduceTuiState: tick updates elapsedMs without touching other fields', () => {
  let s = initialTuiState({ lockfile: 'package-lock.json', version: '1.2.0' });
  s = reduceTuiState(s, { phase: 'sources', id: 'keyv', label: 'DataDog keyv-campaign', status: 'start' });
  s = reduceTuiState(s, { phase: 'tick', elapsedMs: 1420 });
  assert.equal(s.elapsedMs, 1420);
  assert.equal(s.sources.length, 1);
  assert.deepEqual(s.osv, { status: 'idle', done: 0, total: 0 });
});

test('reduceTuiState: completed source objects keep identity across later updates', () => {
  let s = initialTuiState({ lockfile: 'package-lock.json', version: '1.2.0' });
  for (const id of ['keyv', 'shai']) {
    s = reduceTuiState(s, { phase: 'sources', id, label: `src ${id}`, status: 'start' });
    s = reduceTuiState(s, { phase: 'sources', id, status: 'done', entries: 10 });
  }
  const first = s.sources[0];
  const second = s.sources[1];
  s = reduceTuiState(s, { phase: 'sources', id: 'axios', label: 'src axios', status: 'start' });
  s = reduceTuiState(s, { phase: 'sources', id: 'axios', status: 'done', entries: 3 });
  assert.equal(s.sources[0], first, 'already-completed sources must keep object identity');
  assert.equal(s.sources[1], second);
  assert.equal(s.sourcesDone, 3);
});

test('layout: responsive matrix maps columns to frame/columns', () => {
  assert.deepEqual(layout(120), { frame: true, columns: 2 });
  assert.deepEqual(layout(110), { frame: true, columns: 2 });
  assert.deepEqual(layout(100), { frame: true, columns: 1 });
  assert.deepEqual(layout(80), { frame: true, columns: 1 });
  assert.deepEqual(layout(70), { frame: false, columns: 1 });
  assert.deepEqual(layout(50), { frame: false, columns: 1 });
  assert.equal(layout(40).frame, false);
});

test('dotsFor: cycles one to three dots every 300ms', () => {
  assert.equal(dotsFor(0), '.');
  assert.equal(dotsFor(299), '.');
  assert.equal(dotsFor(300), '..');
  assert.equal(dotsFor(599), '..');
  assert.equal(dotsFor(600), '...');
  assert.equal(dotsFor(899), '...');
  assert.equal(dotsFor(900), '.');
  assert.equal(dotsFor(1200), '..');
});

test('runScan: emits progress events and reports matches', async () => {
  const lock = await writeLock('progress-lock.json', {
    keyv: { version: '6.0.0' },
    evil: { version: '1.0.0' },
  });
  const events = [];
  const warnings = [];
  const report = await runScan(
    scanOpts(),
    { retries: 0, timeoutMs: 30000, backoffMs: 100, verbose: false },
    {
      emit: (ev) => events.push(ev),
      log: () => {},
      warn: (m) => warnings.push(m),
      cwd: dir,
      displayPath: 'progress-lock.json',
      lockPath: lock,
      startedAt: Date.now(),
    }
  );

  assert.equal(report.summary.found, 2);
  assert.deepEqual(report.matches.map((m) => m.name).sort(), ['evil', 'keyv']);
  assert.equal(warnings.length, 0);

  const starts = events.filter((e) => e.phase === 'sources' && e.status === 'start');
  assert.equal(starts.length, 4, 'four built-in CSV sources must emit a start event');
  const done = events.filter((e) => e.phase === 'sources' && e.status === 'done');
  assert.equal(done.length, 4);
  assert.ok(done.every((e) => e.entries >= 1));

  const batches = events.filter((e) => e.phase === 'osv-batch');
  assert.ok(batches.length >= 1);
  assert.equal(batches[batches.length - 1].done, batches[batches.length - 1].total);

  const classify = events.filter((e) => e.phase === 'osv-classify');
  assert.ok(classify.length >= 1, 'GHSA classification must emit progress');
  assert.equal(classify[classify.length - 1].done, classify[classify.length - 1].total);

  const enrich = events.filter((e) => e.phase === 'osv-enrich');
  assert.ok(enrich.length >= 1, 'advisory enrichment must emit progress');

  const doneEv = events.find((e) => e.phase === 'done');
  assert.equal(doneEv.found, 2);
  assert.equal(doneEv.scanned, 2);
  assert.ok(typeof doneEv.durationMs === 'number');
});

test('runScan: --no-osv emits no OSV events', async () => {
  const lock = await writeLock('noosv-progress-lock.json', { keyv: { version: '6.0.0' } });
  const events = [];
  const report = await runScan(
    scanOpts({ noOsv: true }),
    { retries: 0, timeoutMs: 30000, backoffMs: 100, verbose: false },
    {
      emit: (ev) => events.push(ev),
      log: () => {},
      warn: () => {},
      cwd: dir,
      displayPath: 'noosv-progress-lock.json',
      lockPath: lock,
      startedAt: Date.now(),
    }
  );
  assert.equal(report.summary.found, 1);
  assert.equal(events.some((e) => e.phase.startsWith('osv')), false);
});

test('main: TUI eligible run renders and still exits with the report', async () => {
  const lock = await writeLock('tui-run-lock.json', { keyv: { version: '6.0.0' } });
  const savedCi = process.env.CI;
  const savedTerm = process.env.TERM;
  try {
    delete process.env.CI;
    delete process.env.TERM;
    const out = capture(true);
    const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--ttl', '0', '--retries', '0'], {
      stdout: out,
      stderr: capture(true),
      cwd: dir,
    });
    assert.equal(code, 1);
    assert.match(out.text, /\[ scanning .*lock/);
    assert.match(out.text, /indicators/);
    assert.match(out.text, /osv check/);
    assert.match(out.text, /\u2713 osv check complete/);
    assert.match(out.text, /Scanned: 1 package/);
    assert.match(out.text, /1 malicious package/);
  } finally {
    if (savedCi === undefined) delete process.env.CI;
    else process.env.CI = savedCi;
    if (savedTerm === undefined) delete process.env.TERM;
    else process.env.TERM = savedTerm;
  }
});

test('main: --no-tui on a TTY produces plain non-ANSI output', async () => {
  const lock = await writeLock('notui-lock.json', { keyv: { version: '6.0.0' } });
  const out = capture(true);
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--ttl', '0', '--retries', '0', '--no-tui'], {
    stdout: out,
    stderr: capture(true),
    cwd: dir,
  });
  assert.equal(code, 1);
  assert.ok(!/\u001b\[/.test(out.text), '--no-tui output must not contain ANSI escapes');
  assert.match(out.text, /Scanned: 1 package/);
  assert.match(out.text, /1 malicious package/);
});

test('main: TUI-eligible run hitting a ScanError exits 2 with the error', async () => {
  const root = await mkdtemp(join(tmpdir(), 'npm-scan-tui-err-'));
  await writeFile(join(root, 'package-lock.json'), '{not json');
  const savedCi = process.env.CI;
  const savedTerm = process.env.TERM;
  try {
    delete process.env.CI;
    delete process.env.TERM;
    const out = capture(true);
    const err = capture(true);
    const code = await main(['--cache-dir', cacheDir, '--ttl', '0', '--retries', '0'], {
      stdout: out,
      stderr: err,
      cwd: root,
    });
    assert.equal(code, 2);
    assert.match(err.text, /cannot read\/parse/);
  } finally {
    if (savedCi === undefined) delete process.env.CI;
    else process.env.CI = savedCi;
    if (savedTerm === undefined) delete process.env.TERM;
    else process.env.TERM = savedTerm;
    await rm(root, { recursive: true, force: true });
  }
});

function renderScanUi(state, { columns = 120 } = {}) {
  const stdout = capture(true);
  stdout.columns = columns;
  const instance = render(h(ScanUi, { state }), { stdout, stderr: capture(true) });
  instance.clear();
  instance.unmount();
  return stdout.text;
}

test('ScanUi: renders error, cached, and stale source rows', () => {
  const state = initialTuiState({ lockfile: 'package-lock.json', version: '1.2.0' });
  state.sources = [
    { id: 'a', label: 'DataDog keyv-campaign', status: 'error' },
    { id: 'b', label: 'DataDog TeamPCP', status: 'cached', entries: 4 },
    { id: 'c', label: 'custom', status: 'stale', entries: 2 },
  ];
  const text = renderScanUi(state);
  assert.match(text, /\u2717/);
  assert.match(text, /FAIL/);
  assert.match(text, /CACHED/);
  assert.match(text, /STALE/);
});

test('ScanUi: renders osv-skipped and classify phases and single-column layout', () => {
  const state = initialTuiState({ lockfile: 'package-lock.json', version: '1.2.0' });
  state.sources = [{ id: 'a', label: 'DataDog keyv-campaign', status: 'done', entries: 10 }];
  state.osv = { status: 'skipped', done: 0, total: 0 };
  state.classify = { done: 1, total: 3 };
  const text = renderScanUi(state, { columns: 90 });
  assert.match(text, /osv check skipped/);
  assert.match(text, /classifying/);
  assert.match(text, /1\/3/);
});

test('reduceTuiState: unknown phase returns the same state', () => {
  const s = initialTuiState({ lockfile: 'package-lock.json', version: '1.2.0' });
  assert.equal(reduceTuiState(s, { phase: 'bogus' }), s);
});
