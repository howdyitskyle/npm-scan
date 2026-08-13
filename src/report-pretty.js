import { basename } from 'node:path';
import gradient from 'gradient-string';
import { bold, dim, dimGray, red, green, yellow, cyan, magenta, useColor, stripAnsi, link } from './colors.js';
import { fmt, plural, truncate, wrapAnsi } from './util.js';
import { VERSION } from './version.js';
import { matchKindLabel, severityLabel } from './report-shared.js';

const wordmark = () => (useColor ? gradient('cyan', '#ff2ec4')('npm-scan') : 'npm-scan');

const padAnsi = (s, n) => {
  s = String(s);
  const vis = stripAnsi(s);
  return vis.length >= n ? s : s + ' '.repeat(n - vis.length);
};

export function clipAnsi(s, n) {
  s = String(s);
  const vis = stripAnsi(s);
  if (vis.length <= n) return s;
  const limit = Math.max(1, n - 1);
  let out = '';
  let count = 0;
  const stack = [];
  let openLinks = 0;
  let i = 0;
  while (i < s.length && count < limit) {
    const ch = s[i];
    if (ch === '\u001b') {
      const m = /^\u001b\[([0-9;]*)m/.exec(s.slice(i));
      if (m) {
        out += m[0];
        i += m[0].length;
        if (m[1] === '0') stack.length = 0;
        else stack.push(m[1]);
        continue;
      }
      const o = /^\u001b\][^\u0007\u001b]*\u0007/.exec(s.slice(i));
      if (o) {
        out += o[0];
        i += o[0].length;
        if (o[0].startsWith('\u001b]8;;') && o[0] !== '\u001b]8;;\u0007') openLinks++;
        continue;
      }
    }
    out += ch;
    count++;
    i++;
  }
  out += '\u2026';
  for (let k = 0; k < openLinks; k++) out += '\u001b]8;;\u0007';
  if (/\u001b\[/.test(s)) {
    for (const c of stack) out += `\u001b[${c}m`;
    out += '\u001b[0m';
  }
  return out;
}

function wrapFrame(text, cols) {
  if (cols < 80) {
    return text
      .split('\n')
      .map((line) => wrapAnsi(line, cols))
      .join('\n');
  }
  const W = cols - 4;
  const lines = text.split('\n');
  const top = dimGray(`\u256d${'\u2500'.repeat(cols - 2)}\u256e`);
  const bottom = dimGray(`\u2570${'\u2500'.repeat(cols - 2)}\u256f`);
  const mid = (line) =>
    wrapAnsi(line, W)
      .split('\n')
      .map((sub) => `${dimGray('\u2502')} ${padAnsi(clipAnsi(sub, W), W)} ${dimGray('\u2502')}`);
  return [top, ...lines.flatMap(mid), bottom].join('\n');
}

function band(title, width) {
  const t = bold(magenta(title));
  return `${t} ${dimGray('\u2500'.repeat(Math.max(2, width - stripAnsi(t).length - 1)))}`;
}

const chip = (text, color) => `${dim('[')} ${color(text)} ${dim(']')}`;

const labelW = 12;
const lbl = (t) => `${' '.repeat(labelW - stripAnsi(t).length)}${dim(t)}`;

function severityKind(m) {
  let best = null;
  for (const adv of m.advisories) {
    const raw = adv.severity?.score ?? adv.severity?.severity ?? adv.severity?.vector ?? null;
    if (raw == null) continue;
    const score = parseFloat(raw);
    if (Number.isFinite(score) && (best === null || score > best)) best = score;
  }
  if (best === null) return null;
  const text = best >= 9 ? 'CRITICAL' : best >= 7 ? 'HIGH' : best >= 4 ? 'MEDIUM' : 'LOW';
  const color = text === 'CRITICAL' ? red : text === 'HIGH' ? yellow : text === 'MEDIUM' ? cyan : dim;
  return { text, color };
}

function infoLines(summary, sources) {
  const L = [`${lbl('Lockfile:')} ${basename(summary.lockfile)}`];
  L.push(
    `${lbl('Scanned:')} ${plural(summary.scanned, 'package')}  ${lbl('Indicators:')} ${fmt(
      summary.indicators
    )} from ${plural(sources.length, 'source')}`
  );
  if (summary.iocScanned > 0) {
    L.push(`${lbl('Installed:')} ${plural(summary.iocScanned, 'package')} on disk (--iocs)`);
  }
  if (summary.osvSkipped) L.push(`${lbl('Note:')} ${yellow('OSV check skipped (network unavailable)')}`);
  if (summary.excluded > 0) {
    L.push(`${lbl('Note:')} ${dim(`${summary.excluded} match(es) excluded via --exclude-pkg`)}`);
  }
  if (summary.staleSources > 0) {
    L.push(
      `${lbl('Note:')} ${yellow(`${plural(summary.staleSources, 'source')} used stale cached data (network unavailable)`)}`
    );
  }
  return L;
}

export function renderPretty(report, { verbose = false } = {}) {
  const { summary, matches, iocMatches = [] } = report;
  const cols = process.stdout.columns || 80;
  const innerW = cols - 4;
  const contentW = cols >= 80 ? innerW : cols;
  const L = [];
  const push = (...parts) => L.push(parts.join(''));
  const rule = () => dimGray('\u2500'.repeat(innerW));
  const bandLine = (title) => band(title, innerW);

  const headerChip =
    matches.length === 0 && iocMatches.length === 0
      ? chip('clean', green)
      : chip(plural(matches.length + iocMatches.length, 'malicious package'), red);

  push(`${wordmark()} ${dim(`v${VERSION}`)}  ${headerChip}`);
  push(rule());
  for (const line of infoLines(summary, report.sources)) push(line);
  push('');

  if (matches.length === 0 && iocMatches.length === 0) {
    push(`${green('\u2714')} ${bold(green('No known malicious packages found'))} \u2014 your lock file looks clean.`);
    push('');
    push(rule());
    for (const line of footerLines(report, verbose, contentW)) push(line);
    return wrapFrame(L.join('\n'), cols);
  }

  if (matches.length > 0) {
    const rows = matches.map((m) => ({
      name: m.name,
      version: m.version,
      src: [...m.entry.sources].sort().join(', ') || (m.entry.osv.length ? 'osv' : '\u2014'),
      osv: [...m.entry.osv].sort().join(', '),
      sev: severityKind(m),
    }));

    const tableW = cols >= 80 ? innerW : cols;
    const wName = Math.max(7, ...rows.map((r) => r.name.length));
    const wVer = Math.max(7, ...rows.map((r) => r.version.length));
    const wSrc = Math.max(12, ...rows.map((r) => r.src.length));
    const wOsv = Math.max(12, ...rows.map((r) => r.osv.length));
    const wSev = Math.max(8, ...rows.map((r) => (r.sev ? r.sev.text.length + 4 : 1)));
    const gaps = 8;
    let widths = [wName, wVer, wSrc, wOsv, wSev];
    let total = widths.reduce((a, b) => a + b, 0) + gaps;
    if (total <= tableW) {
      const extra = tableW - total;
      const srcAdd = Math.floor(extra * 0.6);
      widths[2] += srcAdd;
      widths[3] += extra - srcAdd;
    } else {
      for (const i of [2, 3]) {
        const take = Math.min(widths[i] - 12, total - tableW);
        widths[i] -= take;
        total -= take;
      }
      for (const i of [0, 1]) {
        const take = Math.min(widths[i] - 5, total - tableW);
        widths[i] -= take;
        total -= take;
      }
      if (total > tableW) widths[4] -= Math.min(widths[4] - 8, total - tableW);
    }
    const [cName, cVer, cSrc, cOsv, cSev] = widths;

    const padL = (s, n) => {
      s = String(s);
      const vis = stripAnsi(s);
      return vis.length >= n ? s : ' '.repeat(n - vis.length) + s;
    };
    const header = `${padAnsi(bold('Package'), cName)}  ${padAnsi(bold('Version'), cVer)}  ${padAnsi(
      bold('Detected by'),
      cSrc
    )}  ${padAnsi(bold('Advisory'), cOsv)}  ${padL(bold('Severity'), cSev)}`;

    push(bandLine('Findings'));
    push('');
    push(header);
    push(dimGray('\u2500'.repeat(stripAnsi(header).length)));
    for (const r of rows) {
      const sevCell = r.sev ? chip(r.sev.text, r.sev.color) : dim('\u2014');
      push(
        `${padAnsi(red(r.name), cName)}  ${padAnsi(bold(r.version), cVer)}  ${padAnsi(
          truncate(r.src, cSrc),
          cSrc
        )}  ${padAnsi(truncate(r.osv || '\u2014', cOsv), cOsv)}  ${padL(sevCell, cSev)}`
      );
    }
    push('');

    push(bandLine('Details & links'));
    push('');
    for (const m of matches) {
      const sev = severityKind(m);
      push(`${magenta('\u25b8')} ${red(m.name)}@${bold(m.version)}${sev ? ` ${chip(sev.text, sev.color)}` : ''}`);
      const kind = matchKindLabel(m);
      if (kind) push(`  ${lbl('Dependency:')} ${kind}`);
      m.advisories.forEach((adv, ai) => {
        if (ai > 0) push('');
        push(
          `  ${lbl('Advisory:')} ${link(`https://api.osv.dev/v1/vulns/${adv.id}`, cyan(adv.id))}${
            adv.summary ? ` \u2014 ${truncate(adv.summary, 100)}` : ''
          }`
        );
        const label = severityLabel(adv.severity);
        if (label) push(`  ${lbl('Severity:')} ${label}`);
        if (adv.patched) push(`  ${lbl('Patched:')} ${green(adv.patched)}`);
        if (adv.aliases && adv.aliases.length) push(`  ${lbl('Aliases:')} ${adv.aliases.join(', ')}`);
        for (const u of adv.links) push(`    ${dim('\u2022')} ${link(u, cyan(u))}`);
      });
      if (m.advisories.length === 0) push(`  ${lbl('Notes:')} ${dim('no OSV advisory details available')}`);
      for (const u of m.sourceRefs) push(`  ${lbl('Campaign:')} ${link(u, cyan(u))}`);
      push('');
    }
  }

  if (iocMatches.length > 0) {
    push(bandLine('Installed packages (--iocs)'));
    push('');
    for (const m of iocMatches) {
      const srcs = [...m.entry.sources].sort().join(', ') || (m.entry.osv.length ? 'osv' : '\u2014');
      const ids = [...m.entry.osv].sort().join(', ');
      push(
        `${red('\u25b8')} ${red(m.name)}@${bold(m.version)} ${dim(`\u00b7 installed at ${m.path}`)}`
      );
      push(`  ${lbl('Detected by:')} ${srcs}${ids ? ` ${dim(`(${ids})`)}` : ''}`);
      const adv = m.advisories?.[0];
      if (adv) push(`  ${lbl('Advisory:')} ${link(`https://api.osv.dev/v1/vulns/${adv.id}`, cyan(adv.id))}`);
      push('');
    }
  }

  push(bandLine('Recommended actions'));
  push('');
  const actions = [
    `${bold('Update/pin')} each flagged package to a patched version listed in its advisory link above.`,
    `Run ${bold('`npm audit fix`')} then ${bold('`npm install`')} to re-resolve the dependency tree.`,
    `If a flagged package ${bold('ran install scripts or executed code')}, treat the machine as compromised \u2014 rotate npm / GitHub / cloud credentials and review published packages and git history.`,
    `Keep ${bold('`package-lock.json`')} committed and review dependency changes in every pull request.`,
  ];
  actions.forEach((a, i) => {
    const num = `${i + 1}.`;
    const wrapped = wrapAnsi(' '.repeat(num.length + 1) + a, contentW).split('\n');
    push(`${magenta(bold(num))} ${wrapped[0].slice(num.length + 1)}`);
    for (const line of wrapped.slice(1)) push(line);
  });
  push('');
  push(rule());
  for (const line of footerLines(report, verbose, contentW)) push(line);
  return wrapFrame(L.join('\n'), cols);
}

function footerLines(report, verbose = false, width = 0) {
  const { summary, sources, generatedAt } = report;
  const L = [];
  const left = `${wordmark()} ${VERSION} ${dim('\u00b7')} ${summary.durationMs}ms ${dim('\u00b7')} ${generatedAt}`;
  if (!verbose) {
    const total = sources.reduce((sum, s) => sum + (s.entries || 0), 0);
    const skipped = sources.filter((s) => s.skipped).length;
    const stale = sources.filter((s) => s.stale).length;
    const parts = [`${plural(sources.length, 'source')}`, `${fmt(total)} indicators`];
    if (skipped > 0) parts.push(red(`skipped: ${plural(skipped, 'source')}`));
    if (stale > 0) parts.push(yellow(`stale: ${plural(stale, 'source')}`));
    if (skipped === 0 && stale === 0) parts.push(dim('all fresh'));
    const right = parts.join(' \u00b7 ');
    const pad = Math.max(1, width - stripAnsi(left).length - stripAnsi(right).length);
    L.push(`${left}${' '.repeat(pad)}${right}`);
    return L;
  }
  L.push(left);
  for (const s of sources) {
    const status = s.skipped
      ? red(`skipped (${s.error})`)
      : `${s.stale ? yellow('stale ') : ''}${fmt(s.entries)} indicators${s.fetchedAt ? ` \u00b7 ${s.stale ? 'cached' : 'fetched'} ${s.fetchedAt}` : ''}`;
    const digest = s.sha256 ? ` \u00b7 sha256:${s.sha256.slice(0, 12)}\u2026` : '';
    L.push(`${dim('\u2022')} ${cyan(s.label)}: ${status}${digest}`);
  }
  return L;
}
