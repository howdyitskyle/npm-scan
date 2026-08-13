import { VERSION } from './version.js';
import { severityLabel } from './report-shared.js';

export function toSarif(report) {
  const { summary, matches, iocMatches = [] } = report;
  const resultFor = (m) => ({
    ruleId: 'npm-scan/malicious-package',
    level: 'error',
    message: {
      text: `${m.name}@${m.version} is a known malicious npm package${
        m.entry.osv.length > 0 ? ` (advisories: ${[...m.entry.osv].sort().join(', ')})` : ''
      }.`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: m.path ? `${m.path}/package.json` : summary.lockfile },
          region: { startLine: 1 },
        },
      },
    ],
    properties: {
      name: m.name,
      version: m.version,
      direct: m.direct,
      via: m.via,
      installed: Boolean(m.path),
      sources: [...m.entry.sources].sort(),
      osv: [...m.entry.osv].sort(),
      advisories: m.advisories.map((a) => ({
        id: a.id,
        summary: a.summary,
        severity: severityLabel(a.severity),
        patched: a.patched,
      })),
    },
  });
  const results = [...matches.map(resultFor), ...iocMatches.map(resultFor)];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'npm-scan',
            version: VERSION,
            informationUri: 'https://github.com/kyle/npm-scan',
            rules: [
              {
                id: 'npm-scan/malicious-package',
                name: 'MaliciousNpmPackage',
                shortDescription: { text: 'Locked dependency matches a known malicious npm indicator.' },
                defaultConfiguration: { level: 'error' },
                helpUri: 'https://osv.dev',
              },
            ],
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: report.generatedAt,
            properties: {
              staleSources: summary.staleSources,
            },
          },
        ],
      },
    ],
  };
}
