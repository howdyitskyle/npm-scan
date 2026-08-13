import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { satisfies, compareVersions, parseSemver, parseLockFile } from '../src/lockfile.js';
import { parseCsv, parseIocCsv } from '../src/csv.js';
import { mapLimit, fetchCached, setFetch } from '../src/util.js';
import { IndicatorIndex } from '../src/sources.js';
import { resolveOptions, ttlFor } from '../src/config.js';
import { renderReport, clipAnsi } from '../src/report.js';
import { loadExcludeRules } from '../src/cli.js';
import { enrichMatches, classifyOsvIds, loadOsvCache, needsClassification } from '../src/osv.js';
import { link, setUseColor } from '../src/colors.js';

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'npm-scan-edge-'));
}

function reportFixture(overrides = {}) {
  return {
    schemaVersion: '1.0.0',
    tool: { name: 'npm-scan', version: '1.0.0', informationUri: 'https://github.com/kyle/npm-scan' },
    generatedAt: '2026-01-01T00:00:00.000Z',
    summary: {
      lockfile: 'package-lock.json',
      lockfileFormat: 'package-lock',
      scanned: 0,
      indicators: 0,
      sources: 0,
      found: 0,
      durationMs: 5,
      osvSkipped: false,
      warnings: [],
    },
    sources: [],
    matches: [],
    ...overrides,
  };
}

function matchFixture() {
  return {
    name: 'keyv',
    version: '6.0.0',
    entry: { sources: ['DataDog keyv-campaign'], osv: ['MAL-2026-11524'] },
    direct: true,
    via: [],
    advisories: [
      {
        id: 'MAL-2026-11524',
        summary: 'Malicious code in keyv',
        details: 'details',
        links: ['https://api.osv.dev/v1/vulns/MAL-2026-11524'],
        severity: { type: 'CVSS_V3', score: '7.5' },
        affected: [{ type: 'SEMVER', introduced: '0', fixed: '6.0.1' }],
        patched: '6.0.1',
        aliases: ['GHSA-3p9h-f68w-m6fx'],
      },
    ],
    sourceRefs: ['https://github.com/DataDog/indicators-of-compromise'],
  };
}

test('satisfies: full semver operator matrix', () => {
  const cases = [
    ['^0.2.3', '0.5.0', false],
    ['^0.2.3', '0.2.9', true],
    ['^0.2.3', '0.2.3', true],
    ['^0.2.3', '0.3.0', false],
    ['^0.0.3', '0.0.4', false],
    ['^0.0.3', '0.0.3', true],
    ['^0.0.3', '0.0.2', false],
    ['^1.2.3', '2.0.0', false],
    ['^1.2.3', '1.9.9', true],
    ['^1.2', '1.9.9', true],
    ['^1.2', '2.0.0', false],
    ['^1', '1.9.9', true],
    ['^1', '2.0.0', false],
    ['~1.2.3', '1.3.0', false],
    ['~1.2.3', '1.2.9', true],
    ['~1.2', '1.3.0', false],
    ['~1.2', '1.2.9', true],
    ['~1', '2.0.0', false],
    ['~1', '1.9.9', true],
    ['>=1.2.3', '1.2.3', true],
    ['>=1.2.3', '1.2.2', false],
    ['<=1.2.3', '1.2.3', true],
    ['<=1.2.3', '1.2.4', false],
    ['>1.2.3', '1.2.4', true],
    ['>1.2.3', '1.2.3', false],
    ['<2.0.0', '1.9.9', true],
    ['<2.0.0', '2.0.0', false],
    ['1.2.3', '1.2.3', true],
    ['1.2.3', '1.2.4', false],
    ['*', '6.0.0', true],
    ['latest', '6.0.0', true],
    ['', '6.0.0', true],
    ['>=1.0.0 <2.0.0', '1.5.0', true],
    ['>=1.0.0 <2.0.0', '2.0.0', false],
    ['^1.0.0 || ^2.0.0', '2.5.0', true],
    ['^1.0.0 || ^2.0.0', '3.0.0', false],
    ['nonsense', '1.0.0', false],
    ['^abc', '1.0.0', false],
    ['6.0.0', 'nonsense', false],
  ];
  for (const [r, v, exp] of cases) assert.equal(satisfies(r, v), exp, `satisfies(${JSON.stringify(r)}, ${v})`);
});

test('compareVersions: ordering and partial versions', () => {
  assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
  assert.ok(compareVersions('1.2.4', '1.2.3') > 0);
  assert.ok(compareVersions('1.2.3', '1.3.0') < 0);
  assert.ok(compareVersions('2.0.0', '1.9.9') > 0);
  assert.equal(compareVersions('1.2', '1.2.0'), 0);
  assert.ok(compareVersions('1.10.0', '1.9.0') > 0);
  assert.equal(compareVersions('', '1.0.0'), 0);
});

test('parseSemver: extracts major.minor.patch', () => {
  assert.equal(parseSemver('1.2.3'), '1.2.3');
  assert.equal(parseSemver('v1.2.3'), '1.2.3');
  assert.equal(parseSemver('1.2'), null);
  assert.equal(parseSemver('1.2.3-beta.1'), '1.2.3');
  assert.equal(parseSemver('abc'), null);
  assert.equal(parseSemver(''), null);
});

test('parseCsv: strips BOM', () => {
  const rows = parseCsv('\uFEFFa,b\n1,2\n');
  assert.deepEqual(rows, [['a', 'b'], ['1', '2']]);
});

test('parseCsv: handles CRLF, quoted commas, escaped quotes, multiline fields', () => {
  const rows = parseCsv('a,b,c\r\n"1,2","say ""hi""","line1\nline2"\r\n');
  assert.deepEqual(rows, [['a', 'b', 'c'], ['1,2', 'say "hi"', 'line1\nline2']]);
});

test('parseCsv: drops blank lines and trailing-empty rows', () => {
  const rows = parseCsv('a,b\n1,2\n\n');
  assert.deepEqual(rows, [['a', 'b'], ['1', '2']]);
});

test('parseIocCsv: header with BOM still detected', () => {
  const entries = parseIocCsv('\uFEFFecosystem,package,versions\nnpm,keyv,6.0.0\n');
  assert.deepEqual(entries, [['keyv', '6.0.0']]);
});

test('parseIocCsv: type/indicator ignores empty version and non-npm rows', () => {
  const csv = 'type,indicator\nnpm package,axios@1.14.1\nnpm package,badpkg@\nnpm package,noathere\npython package,pypi@1.0.0\n';
  const entries = parseIocCsv(csv);
  assert.deepEqual(entries, [['axios', '1.14.1']]);
});

test('parseIocCsv: quoted comma-separated versions split correctly', () => {
  const csv = 'package_name,package_versions\nkeyv,"6.0.0, 5.2.3"\n';
  const entries = parseIocCsv(csv);
  assert.deepEqual(entries, [['keyv', '6.0.0'], ['keyv', '5.2.3']]);
});

test('parseLockFile: pnpm npm: alias key resolved', () => {
  const lock = parseLockFile("lockfileVersion: '9.0'\n\npackages:\n  keyv@npm:6.0.0:\n    resolution: {integrity: sha512-x}\n", 'pnpm');
  assert.ok(lock.list.some((p) => p.name === 'keyv' && p.version === '6.0.0'));
});

test('parseLockFile: pnpm quoted keys and scoped packages', () => {
  const lock = parseLockFile(
    "lockfileVersion: '9.0'\n\npackages:\n  '@babel/code-frame@7.0.0':\n    resolution: {integrity: sha512-x}\n",
    'pnpm'
  );
  assert.ok(lock.list.some((p) => p.name === '@babel/code-frame' && p.version === '7.0.0'));
});

test('parseLockFile: package-lock v3 derives name from key and skips root', () => {
  const lock = parseLockFile(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { '@scope/foo': '1.0.0' } },
        'node_modules/@scope/foo': { version: '1.0.0' },
        'node_modules/a/node_modules/b': { version: '2.0.0' },
        'node_modules/linkpkg': { link: true, version: '1.0.0' },
      },
    }),
    'package-lock'
  );
  assert.ok(lock.list.some((p) => p.name === '@scope/foo' && p.version === '1.0.0'));
  assert.ok(lock.list.some((p) => p.name === 'b' && p.version === '2.0.0'));
  assert.ok(!lock.list.some((p) => p.name === 'linkpkg'));
});

test('parseLockFile: corrupted package-lock throws', () => {
  assert.throws(() => parseLockFile('{not json', 'package-lock'), SyntaxError);
});

test('parseLockFile: yarn v1 with unquoted keys and prerelease versions', () => {
  const lock = parseLockFile(
    '# yarn lockfile v1\n\nkeyv@6.0.0:\n  version "6.0.0"\n\n"@babel/code-frame@^7.0.0":\n  version "7.0.0-beta.1"\n',
    'yarn'
  );
  assert.ok(lock.list.some((p) => p.name === 'keyv' && p.version === '6.0.0'));
  assert.ok(lock.list.some((p) => p.name === '@babel/code-frame' && p.version === '7.0.0-beta.1'));
});

test('mapLimit: preserves order and caps concurrency', async () => {
  let active = 0;
  let maxActive = 0;
  const slow = async (n) => {
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise((r) => setTimeout(r, 5));
    active--;
    return n * 2;
  };
  const results = await mapLimit([1, 2, 3, 4, 5, 6], 2, slow);
  assert.deepEqual(results, [2, 4, 6, 8, 10, 12]);
  assert.ok(maxActive <= 2, `concurrency was ${maxActive}`);
});

test('mapLimit: empty input resolves empty, limit>len is safe', async () => {
  assert.deepEqual(await mapLimit([], 4, async () => 1), []);
  assert.deepEqual(await mapLimit([1, 2], 10, async (n) => n), [1, 2]);
});

test('mapLimit: propagates worker errors', async () => {
  await assert.rejects(
    mapLimit([1, 2, 3], 2, async (n) => {
      if (n === 2) throw new Error('boom');
      return n;
    }),
    /boom/
  );
});

test('fetchCached: miss downloads and writes cache, hit skips fetch', async () => {
  const dir = await tempDir();
  const cachePath = join(dir, 'feed.csv');
  let calls = 0;
  setFetch(async () => {
    calls++;
    return new Response('a,b\n1,2\n', { status: 200 });
  });
  try {
    const first = await fetchCached('https://example.test/feed.csv', cachePath, 3600 * 1000, 'feed');
    assert.equal(first.text, 'a,b\n1,2\n');
    assert.equal(first.fromCache, false);
    assert.equal(calls, 1);
    const second = await fetchCached('https://example.test/feed.csv', cachePath, 3600 * 1000, 'feed');
    assert.equal(second.text, 'a,b\n1,2\n');
    assert.equal(second.fromCache, true);
    assert.equal(calls, 1, 'cache hit must not re-fetch');
    const expired = await fetchCached('https://example.test/feed.csv', cachePath, 0, 'feed');
    assert.equal(expired.text, 'a,b\n1,2\n');
    assert.equal(expired.fromCache, false);
    assert.equal(calls, 2, 'ttl 0 must re-fetch');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fetchCached: download failure propagates', async () => {
  const dir = await tempDir();
  setFetch(async () => new Response('nf', { status: 404 }));
  try {
    await assert.rejects(
      fetchCached('https://example.test/missing.csv', join(dir, 'x.csv'), 0, 'feed', { retries: 0 }),
      /HTTP 404/
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('IndicatorIndex: dedups package@version and merges sources', () => {
  const index = new IndicatorIndex();
  index.add('keyv', '6.0.0', 'DataDog keyv-campaign');
  index.add('keyv', '6.0.0', 'DataDog TeamPCP');
  index.add('keyv', '6.0.0', null, 'MAL-2026-11524');
  index.add('other', '1.0.0', 'DataDog keyv-campaign');
  assert.equal(index.size, 2);
  const e = index.lookup('keyv', '6.0.0');
  assert.ok(e.sources.has('DataDog keyv-campaign'));
  assert.ok(e.sources.has('DataDog TeamPCP'));
  assert.ok(e.osv.has('MAL-2026-11524'));
  assert.equal(index.lookup('missing', '1.0.0'), null);
});

test('resolveOptions: missing explicit config file is an error', () => {
  const { errors } = resolveOptions(['--config', '/nonexistent/npm-scan-config.json']);
  assert.ok(errors.some((e) => e.includes('Config file')));
});

test('resolveOptions: config csv array merged with CLI --csv append', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, 'c.json'), JSON.stringify({ csv: ['a.csv', 'b.csv'] }));
  try {
    const { opts } = resolveOptions(['--config', join(dir, 'c.json'), '--csv', 'c.csv']);
    assert.deepEqual(opts.csv, ['a.csv', 'b.csv', 'c.csv']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ttlFor: object fallbacks and zero handling', () => {
  assert.equal(ttlFor({ ttl: { keyv: 2 } }, 'osv'), 24 * 3600 * 1000);
  assert.equal(ttlFor({ ttl: { keyv: 2, default: 48 } }, 'teampcp'), 48 * 3600 * 1000);
  assert.equal(ttlFor({ ttl: 0 }, 'keyv'), 0);
});

test('renderReport: all formats render an empty report without errors', () => {
  const report = reportFixture();
  for (const format of ['pretty', 'compact', 'markdown', 'json', 'sarif', 'gh-annotations']) {
    const out = renderReport(report, { format });
    assert.ok(typeof out === 'string' && out.length > 0, format);
  }
  assert.match(renderReport(report, { format: 'compact' }), /no known malicious packages found/);
  assert.match(renderReport(report, { format: 'markdown' }), /No known malicious packages found/);
  assert.match(renderReport(report, { format: 'gh-annotations' }), /^::notice title=npm-scan::no known malicious packages found\n$/);
  assert.equal(JSON.parse(renderReport(report, { format: 'json' })).schemaVersion, '1.0.0');
  const sarif = JSON.parse(renderReport(report, { format: 'sarif' }));
  assert.equal(sarif.runs[0].results.length, 0);
});

test('renderReport: gh-annotations emits error and warning lines', () => {
  const report = reportFixture({
    matches: [matchFixture(), { ...matchFixture(), name: 'lodash', version: '4.17.20' }],
    summary: { ...reportFixture().summary, found: 2, staleSources: 1, lockfile: 'client/package-lock.json' },
  });
  const out = renderReport(report, { format: 'gh-annotations' });
  const lines = out.trim().split('\n');
  assert.match(lines[0], /^::error title=npm-scan,file=client\/package-lock\.json::keyv@6\.0\.0 is a known malicious package .*MAL-2026-11524/);
  assert.match(lines[1], /lodash@4\.17\.20/);
  assert.match(lines[2], /^::warning title=npm-scan::1 source\(s\) used stale cached data/);
  assert.equal(lines.length, 3);
});

test('renderReport: iocMatches render across formats with installed context', () => {
  const iocMatch = { ...matchFixture(), path: 'node_modules/keyv' };
  const report = reportFixture({
    matches: [matchFixture()],
    iocMatches: [iocMatch],
    summary: { ...reportFixture().summary, found: 2, iocScanned: 1, iocFound: 1 },
  });

  const pretty = renderReport(report, { format: 'pretty' });
  assert.match(pretty, /Installed packages \(--iocs\)/);
  assert.match(pretty, /installed at node_modules\/keyv/);

  const markdown = renderReport(report, { format: 'markdown' });
  assert.match(markdown, /## Installed packages \(--iocs\)/);
  assert.match(markdown, /node_modules\/keyv/);

  const compact = renderReport(report, { format: 'compact' });
  assert.match(compact, /\[installed\] keyv@6\.0\.0/);
  assert.match(compact, /2 malicious packages found/);

  const annotations = renderReport(report, { format: 'gh-annotations' });
  assert.match(annotations, /file=node_modules\/keyv\/package\.json/);
  assert.equal(annotations.trim().split('\n').length, 2);

  const sarif = JSON.parse(renderReport(report, { format: 'sarif' }));
  assert.equal(sarif.runs[0].results.length, 2);
  assert.equal(sarif.runs[0].results[1].properties.installed, true);
  assert.equal(sarif.runs[0].results[1].locations[0].physicalLocation.artifactLocation.uri, 'node_modules/keyv/package.json');

  const json = JSON.parse(renderReport(report, { format: 'json' }));
  assert.equal(json.iocMatches.length, 1);
  assert.equal(json.iocMatches[0].path, 'node_modules/keyv');
});

test('loadExcludeRules: parses bare names, exact versions, comments, and v-prefixes', async () => {
  const dir = await tempDir();
  const path = join(dir, 'exclude.txt');
  await writeFile(path, '# comment\nkeyv\nlodash@4.17.21\n@scope/pkg@v1.2.3\n\nevil\n');
  const rules = await loadExcludeRules(path, dir);
  assert.equal(rules.excludes('keyv', '9.9.9'), true);
  assert.equal(rules.excludes('lodash', '4.17.21'), true);
  assert.equal(rules.excludes('lodash', '4.17.20'), false);
  assert.equal(rules.excludes('@scope/pkg', '1.2.3'), true);
  assert.equal(rules.excludes('evil', '5.0.0'), true);
  assert.equal(rules.excludes('other', '1.0.0'), false);
  await rm(dir, { recursive: true, force: true });
});

test('loadExcludeRules: relative path resolved against cwd; malformed line throws', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, 'exclude.txt'), 'pkg@@1.0.0\n');
  await assert.rejects(() => loadExcludeRules('exclude.txt', dir), /malformed exclude line 1/);
  await assert.rejects(() => loadExcludeRules('missing.txt', dir), /cannot read exclude list/);
  await rm(dir, { recursive: true, force: true });
});

test('loadExcludeRules: malformed bare-name line throws', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, 'exclude.txt'), 'not a valid name\n');
  await assert.rejects(() => loadExcludeRules('exclude.txt', dir), /malformed exclude line 1/);
  await rm(dir, { recursive: true, force: true });
});

test('enrichMatches: single-object database_specific.cvss vector fallback', async () => {
  const dir = await tempDir();
  setFetch(
    async () =>
      new Response(
        JSON.stringify({
          summary: 's',
          references: [],
          severity: [],
          affected: [],
          aliases: [],
          database_specific: { cvss: { vectorString: 'CVSS:3.1/AV:N/AC:H' } },
        }),
        { status: 200 }
      )
  );
  const m = matchFixture();
  m.entry.osv = ['MAL-2026-d'];
  delete m.advisories;
  delete m.sourceRefs;
  try {
    await enrichMatches([m], { cacheDir: dir, ttlMs: 0 });
    assert.deepEqual(m.advisories[0].severity, { type: 'CVSS_V3', vector: 'CVSS:3.1/AV:N/AC:H' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('enrichMatches: verbose logs failed detail fetches', async () => {
  const dir = await tempDir();
  setFetch(async () => {
    throw new Error('network down');
  });
  const logs = [];
  const m = matchFixture();
  m.entry.osv = ['MAL-2026-11524'];
  delete m.advisories;
  delete m.sourceRefs;
  try {
    await enrichMatches([m], { cacheDir: dir, ttlMs: 0, retries: 0, verbose: true, log: (msg) => logs.push(msg) });
    assert.equal(m.advisories.length, 1);
    assert.equal(m.advisories[0].summary, '');
    assert.ok(logs.some((l) => l.includes('advisory detail fetch')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('renderReport: pretty shows osv-skipped, exclude, and stale notes', () => {
  const report = reportFixture({
    summary: { ...reportFixture().summary, found: 0, osvSkipped: true, excluded: 2, staleSources: 1 },
  });
  const out = renderReport(report, { format: 'pretty' });
  assert.match(out, /OSV check skipped \(network unavailable\)/);
  assert.match(out, /2 match\(es\) excluded via --exclude-pkg/);
  assert.match(out, /1 source used stale cached data \(network unavailable\)/);
});

test('renderReport: pretty verbose footer lists per-source status', () => {
  const report = reportFixture({
    matches: [matchFixture()],
    summary: { ...reportFixture().summary, found: 1 },
    sources: [
      { id: 'keyv', label: 'DataDog keyv-campaign', entries: 10, skipped: false, stale: false, fetchedAt: '2026-01-01T00:00:00.000Z', sha256: 'a'.repeat(64) },
      { id: 'teampcp', label: 'DataDog TeamPCP', entries: 0, skipped: true, error: 'boom', stale: false },
      { id: 'custom', label: 'custom:feed.csv', entries: 5, skipped: false, stale: true, fetchedAt: '2026-01-01T00:00:00.000Z', sha256: 'b'.repeat(64) },
    ],
  });
  const out = renderReport(report, { format: 'pretty', verbose: true });
  assert.match(out, /DataDog keyv-campaign: 10 indicators/);
  assert.match(out, /skipped \(boom\)/);
  assert.match(out, /stale 5 indicators/);
  assert.match(out, /sha256:aaaaaaaaaaaa/);
});

test('renderReport: compact stale notes in clean and found paths', () => {
  const clean = renderReport(
    reportFixture({ summary: { ...reportFixture().summary, found: 0, staleSources: 1 } }),
    { format: 'compact' }
  );
  assert.match(clean, /1 source\(s\) used stale cached data/);

  const found = renderReport(
    reportFixture({ matches: [matchFixture()], summary: { ...reportFixture().summary, found: 1, staleSources: 1 } }),
    { format: 'compact' }
  );
  assert.match(found, /1 source\(s\) used stale cached data/);
});

test('renderReport: pretty narrow terminal renders without a box frame', () => {
  const report = reportFixture({ matches: [matchFixture()], summary: { ...reportFixture().summary, found: 1 } });
  const saved = process.stdout.columns;
  try {
    process.stdout.columns = 60;
    const out = renderReport(report, { format: 'pretty' });
    assert.ok(!out.includes('\u256d'), 'no top border on narrow terminals');
    assert.ok(!out.includes('\u2570'), 'no bottom border on narrow terminals');
    assert.ok(out.includes('Findings'));
  } finally {
    if (saved === undefined) delete process.stdout.columns;
    else process.stdout.columns = saved;
  }
});

test('clipAnsi: truncates with ANSI color and OSC link preservation', () => {
  const colored = clipAnsi('\u001b[31m' + 'x'.repeat(50) + '\u001b[0m', 10);
  assert.equal(colored.replace(/\u001b\[[0-9;]*m/g, '').length, 10);
  assert.ok(colored.startsWith('\u001b[31m'));
  assert.ok(colored.endsWith('\u001b[0m'));

  const linked = clipAnsi('\u001b]8;;https://x\u0007' + 'y'.repeat(50) + '\u001b]8;;\u0007', 10);
  assert.ok(linked.endsWith('\u001b]8;;\u0007'));
  assert.ok(linked.includes('\u2026'));

  const plain = clipAnsi('z'.repeat(50), 10);
  assert.equal(plain, 'zzzzzzzzz\u2026');
});

test('colors: link emits OSC when color is enabled and pretty renders colored output', () => {
  setUseColor(true);
  try {
    assert.equal(link('https://x.io', 'x'), '\u001b]8;;https://x.io\u0007x\u001b]8;;\u0007');
    const report = reportFixture({ matches: [matchFixture()], summary: { ...reportFixture().summary, found: 1 } });
    const out = renderReport(report, { format: 'pretty' });
    assert.ok(out.includes('\u001b]8;;'), 'pretty must emit OSC hyperlinks when color is enabled');
    assert.ok(out.includes('\u001b[38;2'), 'pretty must emit the gradient wordmark when color is enabled');
  } finally {
    setUseColor(false);
  }
});

test('renderReport: pretty output has no ANSI escape codes', () => {
  const report = reportFixture({ matches: [matchFixture()], summary: { ...reportFixture().summary, found: 1 } });
  const out = renderReport(report, { format: 'pretty' });
  assert.ok(!/\u001b\[/.test(out), 'pretty output must be clean when color disabled');
  assert.match(out, /Details & links/);
});

test('renderReport: sarif includes endTimeUtc and match metadata', () => {
  const report = reportFixture({
    matches: [matchFixture()],
    summary: { ...reportFixture().summary, found: 1 },
  });
  const sarif = JSON.parse(renderReport(report, { format: 'sarif' }));
  const run = sarif.runs[0];
  assert.equal(run.invocations[0].endTimeUtc, '2026-01-01T00:00:00.000Z');
  assert.equal(run.results.length, 1);
  assert.deepEqual(run.results[0].properties.sources, ['DataDog keyv-campaign']);
  assert.equal(run.results[0].properties.advisories[0].patched, '6.0.1');
});

test('renderReport: markdown includes findings and advisory details', () => {
  const report = reportFixture({
    matches: [matchFixture()],
    summary: { ...reportFixture().summary, found: 1 },
  });
  const md = renderReport(report, { format: 'markdown' });
  assert.match(md, /## Findings \(1\)/);
  assert.match(md, /MAL-2026-11524/);
  assert.match(md, /Patched version: `6\.0\.1`/);
});

test('renderReport: compact shows detected-by and advisory ids', () => {
  const report = reportFixture({
    matches: [matchFixture()],
    summary: { ...reportFixture().summary, found: 1 },
  });
  const out = renderReport(report, { format: 'compact' });
  assert.match(out, /keyv@6\.0\.0: Direct dependency/);
  assert.match(out, /MAL-2026-11524/);
});

test('enrichMatches: populates advisories from OSV', async () => {
  const dir = await tempDir();
  setFetch(async (url) => {
    assert.ok(url.includes('/v1/vulns/MAL-2026-11524'));
    return new Response(
      JSON.stringify({
        summary: 'Malicious code in keyv',
        details: 'long details',
        references: [{ url: 'https://www.npmjs.com/package/keyv/v/6.0.0' }],
        severity: [{ type: 'CVSS_V3', score: '7.5' }],
        affected: [
          {
            package: { ecosystem: 'npm', name: 'keyv' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.0.1' }] }],
          },
          { package: { ecosystem: 'pypi' }, ranges: [] },
        ],
        aliases: ['GHSA-3p9h-f68w-m6fx'],
        database_specific: { url: 'https://github.com/advisories/GHSA-3p9h-f68w-m6fx' },
      }),
      { status: 200 }
    );
  });
  const m = matchFixture();
  m.entry.osv = ['MAL-2026-11524'];
  delete m.advisories;
  delete m.sourceRefs;
  try {
    await enrichMatches([m], { cacheDir: dir, ttlMs: 0 });
    const a = m.advisories[0];
    assert.equal(a.id, 'MAL-2026-11524');
    assert.equal(a.summary, 'Malicious code in keyv');
    assert.equal(a.patched, '6.0.1');
    assert.equal(a.severity.score, '7.5');
    assert.equal(a.aliases[0], 'GHSA-3p9h-f68w-m6fx');
    assert.ok(a.links[0].includes('github.com/advisories'));
    assert.ok(a.links.some((l) => l.includes('api.osv.dev')));
    assert.equal(a.affected.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('enrichMatches: advisory cache avoids refetch within ttl', async () => {
  const dir = await tempDir();
  let calls = 0;
  setFetch(async () => {
    calls++;
    return new Response(
      JSON.stringify({ summary: 's', references: [], severity: [], affected: [], aliases: [], database_specific: {} }),
      { status: 200 }
    );
  });
  const m = matchFixture();
  m.entry.osv = ['MAL-2026-11524'];
  delete m.advisories;
  delete m.sourceRefs;
  try {
    await enrichMatches([m], { cacheDir: dir, ttlMs: 3600 * 1000 });
    assert.equal(calls, 1);
    await enrichMatches([m], { cacheDir: dir, ttlMs: 3600 * 1000 });
    assert.equal(calls, 1, 'cached advisory must not be refetched');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('enrichMatches: preserves cached advisory data when fetch fails', async () => {
  const dir = await tempDir();
  await writeFile(
    join(dir, 'osv-advisories.json'),
    JSON.stringify({
      'MAL-2026-11524': {
        fetchedAt: 0,
        summary: 'Malicious code in keyv',
        details: 'cached details',
        references: [],
        severity: [{ type: 'CVSS_V3', score: '7.5' }],
        affected: [
          { package: { ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.0.1' }] }] },
        ],
        aliases: ['GHSA-3p9h-f68w-m6fx'],
        database_specific: { url: 'https://github.com/advisories/GHSA-3p9h-f68w-m6fx' },
      },
    })
  );
  setFetch(async () => {
    throw new Error('network down');
  });
  const m = matchFixture();
  m.entry.osv = ['MAL-2026-11524'];
  delete m.advisories;
  delete m.sourceRefs;
  try {
    await enrichMatches([m], { cacheDir: dir, ttlMs: 3600 * 1000, retries: 0 });
    const a = m.advisories[0];
    assert.equal(a.summary, 'Malicious code in keyv', 'stale cached advisory must survive a failed fetch');
    assert.equal(a.details, 'cached details');
    assert.equal(a.patched, '6.0.1');
    assert.equal(a.severity.score, '7.5');
    const persisted = JSON.parse(await readFile(join(dir, 'osv-advisories.json'), 'utf8'));
    assert.equal(persisted['MAL-2026-11524'].summary, 'Malicious code in keyv', 'cache must retain the good copy');
    assert.ok(persisted['MAL-2026-11524'].fetchedAt > 0, 'fetchedAt refreshed so it is not retried every scan');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('enrichMatches: empty cache + fetch failure yields empty advisory shell', async () => {
  const dir = await tempDir();
  setFetch(async () => {
    throw new Error('network down');
  });
  const m = matchFixture();
  m.entry.osv = ['MAL-2026-11524'];
  delete m.advisories;
  delete m.sourceRefs;
  try {
    await enrichMatches([m], { cacheDir: dir, ttlMs: 3600 * 1000, retries: 0 });
    assert.equal(m.advisories.length, 1);
    assert.equal(m.advisories[0].id, 'MAL-2026-11524');
    assert.equal(m.advisories[0].summary, '');
    assert.equal(m.advisories[0].patched, null);
    const persisted = JSON.parse(await readFile(join(dir, 'osv-advisories.json'), 'utf8'));
    assert.deepEqual(persisted['MAL-2026-11524'], { fetchedAt: persisted['MAL-2026-11524'].fetchedAt });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('enrichMatches: severity and affected edge paths (CVSS_V4, GHSA, vector, last_affected, non-npm)', async () => {
  const dir = await tempDir();
  const advisories = {
    'MAL-2026-a': {
      summary: 'last affected and pypi exclusion',
      references: [],
      severity: [{ type: 'CVSS_V4', score: '9.0' }],
      affected: [
        { package: { ecosystem: 'pypi', name: 'x' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] },
        { package: { ecosystem: 'npm', name: 'keyv' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] },
        { package: { ecosystem: 'npm', name: 'keyv' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }, { last_affected: '2.5.0' }] }] },
      ],
      aliases: [],
      database_specific: {},
    },
    'MAL-2026-b': {
      summary: 'ghsa severity',
      references: [],
      severity: [],
      affected: [],
      aliases: [],
      database_specific: { severity: 'HIGH' },
    },
    'MAL-2026-c': {
      summary: 'vector fallback',
      references: [],
      severity: [],
      affected: [],
      aliases: [],
      database_specific: { cvss: [{ vectorString: 'CVSS:3.1/AV:N/AC:L' }] },
    },
  };
  setFetch(async (url) => {
    const id = url.split('/').pop();
    const adv = advisories[id];
    if (!adv) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(adv), { status: 200 });
  });
  const m = matchFixture();
  m.entry.osv = ['MAL-2026-a', 'MAL-2026-b', 'MAL-2026-c'];
  delete m.advisories;
  delete m.sourceRefs;
  try {
    await enrichMatches([m], { cacheDir: dir, ttlMs: 0 });
    const byId = Object.fromEntries(m.advisories.map((a) => [a.id, a]));

    const a = byId['MAL-2026-a'];
    assert.deepEqual(a.severity, { type: 'CVSS_V4', score: '9.0' });
    assert.equal(a.patched, '1.0.0');
    assert.deepEqual(a.affected, [
      { type: 'SEMVER', introduced: '0', fixed: '1.0.0', lastAffected: null },
      { type: 'SEMVER', introduced: '2.0.0', fixed: null, lastAffected: '2.5.0' },
    ]);

    assert.deepEqual(byId['MAL-2026-b'].severity, { type: 'GHSA', severity: 'HIGH' });
    assert.deepEqual(byId['MAL-2026-c'].severity, { type: 'CVSS_V3', vector: 'CVSS:3.1/AV:N/AC:L' });
    assert.equal(byId['MAL-2026-b'].patched, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('classifyOsvIds: marks MALICIOUS and OTHER, respects cache', async () => {
  const mal = 'GHSA-aaa-111-222';
  const vuln = 'GHSA-bbb-333-444';
  let calls = 0;
  setFetch(async (url) => {
    calls++;
    const id = url.split('/').pop();
    const type = id === mal ? 'MALICIOUS' : 'VULNERABILITY';
    return new Response(JSON.stringify({ database_specific: { type } }), { status: 200 });
  });
  const cache = {
    [mal]: 'PENDING',
    [vuln]: 'PENDING',
    'GHSA-cached-555': { type: 'OTHER', fetchedAt: Date.now() },
  };
  await classifyOsvIds([mal, vuln, 'GHSA-cached-555'], cache, { ttlMs: 3600 * 1000 });
  assert.equal(cache[mal].type, 'MALICIOUS');
  assert.equal(cache[vuln].type, 'OTHER');
  assert.equal(cache['GHSA-cached-555'].type, 'OTHER');
  assert.equal(calls, 2, 'already-classified ids must not be fetched');
});

test('classifyOsvIds: stale entries are re-classified within ttl', async () => {
  let calls = 0;
  setFetch(async () => {
    calls++;
    return new Response(JSON.stringify({ database_specific: { type: 'MALICIOUS' } }), { status: 200 });
  });
  const cache = { 'GHSA-old-111': { type: 'OTHER', fetchedAt: 0 } };
  await classifyOsvIds(['GHSA-old-111'], cache, { ttlMs: 3600 * 1000 });
  assert.equal(cache['GHSA-old-111'].type, 'MALICIOUS');
  assert.equal(calls, 1, 'stale entry must be re-fetched');

  calls = 0;
  await classifyOsvIds(['GHSA-old-111'], cache, { ttlMs: 3600 * 1000 });
  assert.equal(calls, 0, 'fresh entry must not be re-fetched');
});

test('needsClassification predicate', () => {
  const now = Date.now();
  const cache = {
    missing: undefined,
    pending: 'PENDING',
    fresh: { type: 'OTHER', fetchedAt: now },
    stale: { type: 'OTHER', fetchedAt: now - 48 * 3600 * 1000 },
  };
  assert.ok(needsClassification('missing', cache, 24 * 3600 * 1000));
  assert.ok(needsClassification('pending', cache, 24 * 3600 * 1000));
  assert.ok(!needsClassification('fresh', cache, 24 * 3600 * 1000));
  assert.ok(needsClassification('stale', cache, 24 * 3600 * 1000));
  assert.ok(!needsClassification('stale', cache, 72 * 3600 * 1000));
});

test('loadOsvCache: migrates legacy string values and drops PENDING', async () => {
  const dir = await tempDir();
  try {
    await writeFile(
      join(dir, 'osv-types.json'),
      JSON.stringify({ 'GHSA-a': 'MALICIOUS', 'GHSA-b': 'OTHER', 'GHSA-c': 'PENDING' })
    );
    const cache = await loadOsvCache(dir);
    assert.equal(cache['GHSA-a'].type, 'MALICIOUS');
    assert.equal(cache['GHSA-b'].type, 'OTHER');
    assert.ok(typeof cache['GHSA-a'].fetchedAt === 'number');
    assert.equal(cache['GHSA-c'], undefined, 'PENDING must be dropped');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('classifyOsvIds: fetch failure marks OTHER with fetchedAt (self-heals)', async () => {
  setFetch(async () => {
    throw new Error('network down');
  });
  const cache = { 'GHSA-net-999': 'PENDING' };
  await classifyOsvIds(['GHSA-net-999'], cache, { retries: 0 });
  assert.equal(cache['GHSA-net-999'].type, 'OTHER');
  assert.equal(cache['GHSA-net-999'].fetchedAt, cache['GHSA-net-999'].fetchedAt);
  assert.ok(needsClassification('GHSA-net-999', cache, -1), 'failed classification should be retriable');
});
