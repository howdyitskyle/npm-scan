import { fmt, plural } from './util.js';
import { matchKindLabel, severityLabel } from './report-shared.js';

export function renderMarkdown(report) {
  const { summary, matches, iocMatches = [], sources, generatedAt } = report;
  const L = [];
  L.push(`# npm-scan report`);
  L.push('');
  L.push(`- **Lockfile:** \`${summary.lockfile}\``);
  L.push(`- **Format:** ${summary.lockfileFormat}`);
  L.push(`- **Scanned:** ${plural(summary.scanned, 'package')}`);
  if (summary.iocScanned > 0) L.push(`- **Installed (--iocs):** ${plural(summary.iocScanned, 'package')} on disk`);
  L.push(`- **Indicators:** ${fmt(summary.indicators)} from ${plural(sources.length, 'source')}`);
  L.push(`- **Generated:** ${generatedAt} (${summary.durationMs}ms)`);
  if (summary.osvSkipped) L.push(`- **Note:** OSV check skipped (network unavailable)`);
  if (summary.excluded > 0) L.push(`- **Note:** ${summary.excluded} match(es) excluded via --exclude-pkg`);
  if (summary.staleSources > 0) L.push(`- **Note:** ${summary.staleSources} source(s) used stale cached data (network unavailable)`);
  L.push('');

  if (matches.length === 0 && iocMatches.length === 0) {
    L.push(`No known malicious packages found \u2014 your lock file looks clean.`);
    return L.join('\n') + '\n';
  }

  if (matches.length > 0) {
    L.push(`## Findings (${matches.length})`);
    L.push('');
    L.push('| Package | Version | Direct | Detected by | Advisory | Severity | Patched |');
    L.push('| --- | --- | --- | --- | --- | --- | --- |');
    for (const m of matches) {
      const srcs = [...m.entry.sources].sort().join(', ') || 'osv';
      const ids = [...m.entry.osv].sort().join(', ') || '\u2014';
      const kind = matchKindLabel(m) || '\u2014';
      const adv = m.advisories[0];
      const sev = adv ? severityLabel(adv.severity) || '\u2014' : '\u2014';
      const patched = adv?.patched || '\u2014';
      L.push(`| \`${m.name}\` | \`${m.version}\` | ${kind} | ${srcs} | ${ids} | ${sev} | ${patched} |`);
    }
    L.push('');
  }

  if (iocMatches.length > 0) {
    L.push(`## Installed packages (--iocs)`);
    L.push('');
    L.push('| Package | Version | Path | Detected by | Advisory |');
    L.push('| --- | --- | --- | --- | --- |');
    for (const m of iocMatches) {
      const srcs = [...m.entry.sources].sort().join(', ') || 'osv';
      const ids = [...m.entry.osv].sort().join(', ') || '\u2014';
      const adv = m.advisories?.[0];
      L.push(
        `| \`${m.name}\` | \`${m.version}\` | \`${m.path}\` | ${srcs} | ${adv ? adv.id : ids} |`
      );
    }
    L.push('');
  }

  if (matches.length > 0) {
    L.push(`## Details & links`);
    L.push('');
    for (const m of matches) {
      L.push(`### ${m.name}@${m.version}`);
      for (const adv of m.advisories) {
        L.push(`- **${adv.id}**${adv.summary ? `: ${adv.summary}` : ''}`);
        if (adv.patched) L.push(`  - Patched version: \`${adv.patched}\``);
        for (const u of adv.links) L.push(`  - ${u}`);
      }
      if (m.advisories.length === 0) L.push('- No OSV advisory details available.');
      for (const u of m.sourceRefs) L.push(`- Campaign: ${u}`);
      L.push('');
    }
  }

  L.push(`## Recommended actions`);
  L.push('');
  L.push(`1. Update/pin each flagged package to a patched version listed in its advisory link above.`);
  L.push(`2. Run \`npm audit fix\` then \`npm install\` to re-resolve the dependency tree.`);
  L.push(`3. If a flagged package ran install scripts or executed code, treat the machine as compromised \u2014 rotate npm / GitHub / cloud credentials and review published packages and git history.`);
  L.push(`4. Keep \`package-lock.json\` committed and review dependency changes in every pull request.`);
  L.push('');

  L.push(`## Sources`);
  L.push('');
  for (const s of sources) {
    const status = s.skipped
      ? `skipped (${s.error})`
      : `${s.stale ? 'stale - ' : ''}${fmt(s.entries)} indicators${s.sha256 ? ` (sha256 ${s.sha256.slice(0, 12)}\u2026)` : ''}`;
    L.push(`- **${s.label}:** ${status}`);
  }
  return L.join('\n') + '\n';
}
