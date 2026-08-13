import { plural } from './util.js';
import { matchKindLabel, severityLabel } from './report-shared.js';
import { renderPretty } from './report-pretty.js';
import { renderMarkdown } from './report-markdown.js';
import { toSarif } from './report-sarif.js';

export { clipAnsi } from './report-pretty.js';

function renderCompact(report) {
  const { summary, matches, iocMatches = [] } = report;
  const L = [];
  if (matches.length === 0 && iocMatches.length === 0) {
    let msg = `npm-scan: clean \u2014 ${plural(summary.scanned, 'package')} scanned, no known malicious packages found\n`;
    if (summary.excluded > 0) msg += `note: ${summary.excluded} match(es) excluded via --exclude-pkg\n`;
    if (summary.staleSources > 0) {
      msg += `note: ${summary.staleSources} source(s) used stale cached data (network unavailable)\n`;
    }
    return msg;
  }
  for (const m of matches) {
    const srcs = [...m.entry.sources].sort().join(', ') || 'osv';
    const ids = [...m.entry.osv].sort().join(',');
    const kind = matchKindLabel(m) || 'unknown';
    L.push(`${m.name}@${m.version}: ${kind} \u2014 detected by ${srcs}${ids ? ` (${ids})` : ''}`);
  }
  for (const m of iocMatches) {
    const srcs = [...m.entry.sources].sort().join(', ') || 'osv';
    const ids = [...m.entry.osv].sort().join(',');
    L.push(`[installed] ${m.name}@${m.version} \u2014 detected by ${srcs}${ids ? ` (${ids})` : ''} (${m.path})`);
  }
  L.push(`${plural(matches.length + iocMatches.length, 'malicious package')} found`);
  if (summary.excluded > 0) L.push(`note: ${summary.excluded} match(es) excluded via --exclude-pkg`);
  if (summary.staleSources > 0) {
    L.push(`note: ${summary.staleSources} source(s) used stale cached data (network unavailable)`);
  }
  return L.join('\n') + '\n';
}

function renderGithubAnnotations(report) {
  const { summary, matches, iocMatches = [] } = report;
  const L = [];
  const all = matches.concat(iocMatches);
  if (all.length === 0) {
    L.push('::notice title=npm-scan::no known malicious packages found');
  } else {
    for (const m of all) {
      const srcs = [...m.entry.sources].sort().join(', ') || 'osv';
      const ids = [...m.entry.osv].sort().join(', ');
      const sev = m.advisories && m.advisories[0] ? severityLabel(m.advisories[0].severity) : null;
      let msg = `${m.name}@${m.version} is a known malicious package \u2014 detected by ${srcs}`;
      if (ids) msg += ` (${ids})`;
      if (sev) msg += ` \u2014 severity ${sev}`;
      const file = m.path ? `${m.path}/package.json` : summary.lockfile || 'package-lock.json';
      const props = [`title=npm-scan`, `file=${file}`];
      L.push(`::error ${props.join(',')}::${msg}`);
    }
  }
  if (summary.staleSources > 0) {
    L.push(`::warning title=npm-scan::${summary.staleSources} source(s) used stale cached data (network unavailable)`);
  }
  return L.join('\n') + '\n';
}

export function renderReport(report, { format = 'pretty', verbose = false } = {}) {
  switch (format) {
    case 'json':
      return JSON.stringify(report, null, 2) + '\n';
    case 'sarif':
      return JSON.stringify(toSarif(report), null, 2) + '\n';
    case 'markdown':
      return renderMarkdown(report);
    case 'compact':
      return renderCompact(report);
    case 'gh-annotations':
      return renderGithubAnnotations(report);
    default:
      return renderPretty(report, { verbose });
  }
}
