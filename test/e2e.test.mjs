import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../src/cli.js';
import { setFetch } from '../src/util.js';
import { SOURCES } from '../src/sources.js';
import { zipSync, strToU8 } from 'fflate';

const ADVISORIES = {
  'MAL-2026-11524': {
    summary: 'Malicious code in keyv (npm)',
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
  'GHSA-3p9h-f68w-m6fx': {
    summary: 'Malicious code in keyv (npm)',
    database_specific: { type: 'MALICIOUS' },
  },
  'GHSA-evil-mmmm-cccc': {
    summary: 'Malicious code in evil',
    database_specific: { type: 'MALICIOUS' },
  },
  'GHSA-vvvv-bbbb-nnnn': {
    summary: 'Prototype pollution in left-pad',
    database_specific: { type: 'VULNERABILITY' },
  },
};

const OSV_QUERIES = {
  'keyv@6.0.0': { vulns: [{ id: 'MAL-2026-11524' }] },
  'evil@1.0.0': { vulns: [{ id: 'GHSA-evil-mmmm-cccc' }] },
  'express@4.19.2': { vulns: [{ id: 'GHSA-vvvv-bbbb-nnnn' }] },
};

const CSV = {
  keyv: 'ecosystem,package,versions\nnpm,keyv,6.0.0|5.2.3\n',
  shai: 'package_name,package_versions,sources\nkeyv,6.0.0,campaign\n',
  axios: 'type,indicator,context\nnpm package,axios@1.14.1,observed\nnpm package,keyv@6.0.0,observed\n',
  teampcp: 'artifact_type,name,affected_versions\nnpm package,keyv,"6.0.0, 5.2.3"\n',
  custom: 'name,version\ncustom-evil,1.0.0\n',
};

const MOCK_CSV_URLS = {
  [SOURCES.keyv.url]: CSV.keyv,
  [SOURCES['shai-hulud'].url]: CSV.shai,
  [SOURCES.axios.url]: CSV.axios,
  [SOURCES.teampcp.url]: CSV.teampcp,
  'https://example.test/custom.csv': CSV.custom,
};

const OSV_DB_ZIP = zipSync({
  'MAL-2026-11524.json': strToU8(
    JSON.stringify({
      id: 'MAL-2026-11524',
      summary: 'Malicious code in keyv (npm)',
      database_specific: { type: 'MALICIOUS' },
      affected: [
        { package: { ecosystem: 'npm', name: 'keyv' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.0.1' }] }] },
      ],
    })
  ),
  'GHSA-evil-mmmm-cccc.json': strToU8(
    JSON.stringify({
      id: 'GHSA-evil-mmmm-cccc',
      summary: 'Malicious code in evil',
      database_specific: { type: 'MALICIOUS' },
      affected: [
        { package: { ecosystem: 'npm', name: 'evil' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] },
      ],
    })
  ),
});

let requests = [];
let failOsv = false;
let failOsvDb = false;
let failCsv = false;
function mockFetch(url, opts = {}) {
  requests.push(url);
  if (failOsv && url.includes('api.osv.dev/v1/querybatch')) {
    return Promise.reject(new Error('network down'));
  }
  if (failOsvDb && url === 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip') {
    return Promise.reject(new Error('db network down'));
  }
  if (failCsv && (MOCK_CSV_URLS[url] || url === 'https://example.test/custom.csv')) {
    return Promise.reject(new Error('csv network down'));
  }
  if (MOCK_CSV_URLS[url]) return Promise.resolve(new Response(MOCK_CSV_URLS[url], { status: 200 }));
  if (url === 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip') {
    return Promise.resolve(new Response(OSV_DB_ZIP, { status: 200 }));
  }
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
  dir = await mkdtemp(join(tmpdir(), 'npm-scan-e2e-'));
  cacheDir = join(dir, 'cache');
  setFetch(mockFetch);
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

function capture() {
  const stream = { text: '', write(s) { this.text += s; } };
  return stream;
}

async function writeLock(name, packages, base = dir) {
  const path = join(base, name);
  await writeFile(
    path,
    JSON.stringify({
      name: 'e2e',
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

const run = (args) =>
  main(args, {
    stdout: capture(),
    stderr: capture(),
    cwd: dir,
  });

test('e2e: flags keyv and evil, ignores benign GHSA, exit 1', async () => {
  const lock = await writeLock('package-lock.json', {
    keyv: { version: '6.0.0' },
    express: { version: '4.19.2' },
    evil: { version: '1.0.0' },
  });
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const report = JSON.parse(out.text);
  assert.equal(report.summary.found, 2);
  const names = report.matches.map((m) => m.name);
  assert.deepEqual(names.sort(), ['evil', 'keyv']);
  assert.equal(report.matches.length, 2);

  const keyv = report.matches.find((m) => m.name === 'keyv');
  assert.equal(keyv.direct, true);
  assert.ok(keyv.entry.osv.includes('MAL-2026-11524'));
  assert.ok(keyv.entry.sources.includes('DataDog keyv-campaign'));
  assert.equal(keyv.advisories[0].id, 'MAL-2026-11524');
  assert.equal(keyv.advisories[0].patched, '6.0.1');
  assert.equal(keyv.advisories[0].severity.score, '7.5');

  const evil = report.matches.find((m) => m.name === 'evil');
  assert.ok(evil.entry.osv.includes('GHSA-evil-mmmm-cccc'));
  assert.equal(evil.entry.sources.length, 0);

  assert.ok(!names.includes('express'));
});

test('e2e: clean lockfile exits 0', async () => {
  const lock = await writeLock('clean-lock.json', {
    'left-pad': { version: '1.3.0' },
    express: { version: '4.19.2' },
  });
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 0);
  assert.equal(JSON.parse(out.text).summary.found, 0);
});

test('e2e: missing lockfile exits 2', async () => {
  const code = await run(['--lockfile', join(dir, 'nope.json'), '--cache-dir', cacheDir, '--ttl', '0', '--retries', '0']);
  assert.equal(code, 2);
});

test('e2e: --no-osv skips OSV, CSV-only matches still found', async () => {
  const lock = await writeLock('noosv-lock.json', {
    keyv: { version: '6.0.0' },
    evil: { version: '1.0.0' },
  });
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--no-osv', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const report = JSON.parse(out.text);
  assert.equal(report.summary.osvSkipped, false);
  const names = report.matches.map((m) => m.name);
  assert.deepEqual(names, ['keyv']);
});

test('e2e: --sources keyv limits to keyv source (OSV off)', async () => {
  const lock = await writeLock('sources-lock.json', {
    keyv: { version: '6.0.0' },
    evil: { version: '1.0.0' },
  });
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--sources', 'keyv', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const report = JSON.parse(out.text);
  assert.equal(report.summary.sources, 1);
  assert.equal(report.summary.found, 1);
  assert.equal(report.matches[0].name, 'keyv');
});

test('e2e: custom --csv URL is loaded and matched', async () => {
  const lock = await writeLock('custom-lock.json', {
    'custom-evil': { version: '1.0.0' },
  });
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--csv', 'https://example.test/custom.csv', '--no-osv', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const report = JSON.parse(out.text);
  assert.equal(report.matches[0].name, 'custom-evil');
  assert.equal(report.summary.sources, 5);
});

test('e2e: all output formats render', async () => {
  const lock = await writeLock('formats-lock.json', {
    keyv: { version: '6.0.0' },
  });
  const base = ['--lockfile', lock, '--cache-dir', cacheDir, '--ttl', '0', '--retries', '0'];

  for (const format of ['pretty', 'compact', 'markdown', 'json', 'sarif', 'gh-annotations']) {
    const out = capture();
    const code = await main([...base, '--format', format], { stdout: out, stderr: capture(), cwd: dir });
    assert.equal(code, 1, `format ${format} should exit 1`);
    assert.ok(out.text.length > 0, `format ${format} produced output`);
    if (format === 'json') {
      const r = JSON.parse(out.text);
      assert.equal(r.summary.found, 1);
    }
    if (format === 'sarif') {
      const r = JSON.parse(out.text);
      assert.equal(r.version, '2.1.0');
      assert.equal(r.runs[0].results.length, 1);
    }
    if (format === 'markdown') assert.match(out.text, /# npm-scan report/);
    if (format === 'compact') assert.match(out.text, /1 malicious package found/);
    if (format === 'gh-annotations') {
      assert.match(out.text, /^::error title=npm-scan,file=.*formats-lock\.json::keyv@6\.0\.0 is a known malicious package/m);
      assert.doesNotMatch(out.text, /::notice/);
    }
  }
});

test('e2e: gh-annotations clean run emits a notice', async () => {
  const lock = await writeLock('gh-clean-lock.json', {
    'left-pad': { version: '1.3.0' },
  });
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'gh-annotations', '--ttl', '0', '--no-osv', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 0);
  assert.match(out.text, /^::notice title=npm-scan::no known malicious packages found\n+\s*$/);
});

test('e2e: yarn.lock and pnpm-lock.yaml scanned offline', async () => {
  const yarnLock = join(dir, 'yarn.lock');
  await writeFile(
    yarnLock,
    `# yarn lockfile v1\n\n"keyv@6.0.0":\n  version "6.0.0"\n  resolved "https://registry.yarnpkg.com/keyv/-/keyv-6.0.0.tgz"\n`
  );
  const out = capture();
  const code = await main(['--lockfile', yarnLock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--no-osv', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  assert.equal(JSON.parse(out.text).matches[0].name, 'keyv');

  const pnpmLock = join(dir, 'pnpm-lock.yaml');
  await writeFile(
    pnpmLock,
    `lockfileVersion: '9.0'\n\npackages:\n  keyv@6.0.0:\n    resolution: {integrity: sha512-x}\n`
  );
  const out2 = capture();
  const code2 = await main(['--lockfile', pnpmLock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--no-osv', '--retries', '0'], { stdout: out2, stderr: capture(), cwd: dir });
  assert.equal(code2, 1);
  assert.equal(JSON.parse(out2.text).matches[0].name, 'keyv');
});

test('e2e: auto-detect package-lock.json in cwd', async () => {
  await writeLock('package-lock.json', { keyv: { version: '6.0.0' } });
  const out = capture();
  const code = await main(['--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  assert.equal(JSON.parse(out.text).summary.found, 1);
});

test('e2e: .npmscanrc.json config file honored', async () => {
  await writeLock('package-lock.json', { keyv: { version: '6.0.0' } });
  await writeFile(join(dir, '.npmscanrc.json'), JSON.stringify({ format: 'json', noOsv: true }));
  const out = capture();
  const code = await main(['--cache-dir', cacheDir, '--ttl', '0', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const report = JSON.parse(out.text);
  assert.equal(report.summary.found, 1);
  await rm(join(dir, '.npmscanrc.json'));
});

test('e2e: invalid format exits 2', async () => {
  const code = await run(['--format', 'yaml', '--cache-dir', cacheDir, '--retries', '0']);
  assert.equal(code, 2);
});

test('e2e: unknown source exits 2', async () => {
  const code = await run(['--sources', 'keyv,banana', '--cache-dir', cacheDir, '--retries', '0']);
  assert.equal(code, 2);
});

test('e2e: --sources osv uses OSV only, no CSV sources', async () => {
  const lock = await writeLock('osvonly-lock.json', {
    evil: { version: '1.0.0' },
    'left-pad': { version: '1.3.0' },
  });
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--sources', 'osv', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const report = JSON.parse(out.text);
  assert.deepEqual(report.matches.map((m) => m.name), ['evil']);
  assert.equal(report.summary.sources, 1);
});

test('e2e: custom local CSV file matched', async () => {
  const lock = await writeLock('localcsv-lock.json', { 'custom-evil': { version: '1.0.0' } });
  const csvPath = join(dir, 'local-iocs.csv');
  await writeFile(csvPath, 'name,version\ncustom-evil,1.0.0\n');
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--csv', csvPath, '--no-osv', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  assert.equal(JSON.parse(out.text).matches[0].name, 'custom-evil');
});

test('e2e: unreadable custom CSV warns and continues without failing', async () => {
  const lock = await writeLock('boguscsv-lock.json', { 'left-pad': { version: '1.3.0' } });
  const err = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--csv', 'https://example.test/bogus.csv', '--no-osv', '--retries', '0'], { stdout: capture(), stderr: err, cwd: dir });
  assert.equal(code, 0);
  assert.match(err.text, /warn/);
});

test('e2e: OSV unavailable falls back to CSV matches and sets osvSkipped', async () => {
  const lock = await writeLock('osvfail-lock.json', {
    keyv: { version: '6.0.0' },
    evil: { version: '1.0.0' },
  });
  failOsv = true;
  try {
    const out = capture();
    const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
    assert.equal(code, 1);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.osvSkipped, true);
    assert.deepEqual(report.matches.map((m) => m.name), ['keyv']);
  } finally {
    failOsv = false;
  }
});

test('e2e: --exclude-pkg drops exact, bare, and all matches; all-excluded exits 0', async () => {
  const lock = await writeLock('exclude-lock.json', {
    keyv: { version: '6.0.0' },
    evil: { version: '1.0.0' },
  });
  const exPath = join(dir, 'exclude.txt');
  await writeFile(exPath, '# ignore keyv only at 6.0.0 and evil at any version\nkeyv@6.0.0\nevil\n');
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--exclude-pkg', exPath, '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 0);
  const report = JSON.parse(out.text);
  assert.equal(report.summary.found, 0);
  assert.equal(report.summary.excluded, 2);
  assert.equal(report.matches.length, 0);
});

test('e2e: --exclude-pkg exact-version mismatch still flags the package', async () => {
  const lock = await writeLock('exclude-miss-lock.json', {
    keyv: { version: '6.0.0' },
  });
  const exPath = join(dir, 'exclude-miss.txt');
  await writeFile(exPath, 'keyv@5.0.0\n');
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--exclude-pkg', exPath, '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const report = JSON.parse(out.text);
  assert.equal(report.summary.found, 1);
  assert.equal(report.summary.excluded, 0);
});

test('e2e: --exclude-pkg missing or malformed file exits 2', async () => {
  const lock = await writeLock('exclude-bad-lock.json', { keyv: { version: '6.0.0' } });
  const missing = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--ttl', '0', '--exclude-pkg', join(dir, 'nope.txt'), '--retries', '0'], { stdout: capture(), stderr: capture(), cwd: dir });
  assert.equal(missing, 2);

  const badPath = join(dir, 'bad.txt');
  await writeFile(badPath, 'keyv@@6.0.0\n');
  const bad = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--ttl', '0', '--exclude-pkg', badPath, '--retries', '0'], { stdout: capture(), stderr: capture(), cwd: dir });
  assert.equal(bad, 2);
});

test('e2e: --exclude-pkg note appears in compact output', async () => {
  const lock = await writeLock('exclude-clean-lock.json', {
    evil: { version: '1.0.0' },
  });
  const exPath = join(dir, 'exclude-all.txt');
  await writeFile(exPath, 'evil\n');
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'compact', '--ttl', '0', '--exclude-pkg', exPath, '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 0);
  assert.match(out.text, /excluded via --exclude-pkg/);
});

test('e2e: --exclude-pkg also excludes installed --iocs matches', async () => {
  const root = await freshRoot();
  try {
    const lock = await writeLock('exclude-ioc-lock.json', {
      keyv: { version: '6.0.0' },
    }, root);
    await mkdir(join(root, 'node_modules', 'keyv'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'keyv', 'package.json'), JSON.stringify({ name: 'keyv', version: '6.0.0' }));
    await mkdir(join(root, 'node_modules', 'evil'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'evil', 'package.json'), JSON.stringify({ name: 'evil', version: '1.0.0' }));

    const exPath = join(dir, 'exclude-ioc.txt');
    await writeFile(exPath, 'keyv\nevil\n');
    const out = capture();
    const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--iocs', '--iocs-roots', root, '--exclude-pkg', exPath, '--retries', '0'], { stdout: out, stderr: capture(), cwd: root });
    assert.equal(code, 0);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.found, 0);
    assert.equal(report.summary.iocScanned, 2);
    assert.equal(report.summary.excluded, 3, 'lockfile keyv + installed keyv + installed evil');
    assert.equal(report.matches.length, 0);
    assert.equal(report.iocMatches.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

const freshRoot = () => mkdtemp(join(tmpdir(), 'npm-scan-ioc-root-'));

test('e2e: --exclude-pkg does not count excluded-but-clean installed packages', async () => {
  const root = await freshRoot();
  try {
    const lock = await writeLock('exclude-clean-ioc-lock.json', {
      'left-pad': { version: '1.3.0' },
    }, root);
    await mkdir(join(root, 'node_modules', 'benign'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'benign', 'package.json'), JSON.stringify({ name: 'benign', version: '2.0.0' }));
    await mkdir(join(root, 'node_modules', 'keyv'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'keyv', 'package.json'), JSON.stringify({ name: 'keyv', version: '6.0.0' }));

    const exPath = join(dir, 'exclude-clean-ioc.txt');
    await writeFile(exPath, 'benign\nkeyv\n');
    const out = capture();
    const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--iocs', '--iocs-roots', root, '--exclude-pkg', exPath, '--retries', '0'], { stdout: out, stderr: capture(), cwd: root });
    assert.equal(code, 0);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.found, 0);
    assert.equal(report.summary.excluded, 1, 'only the flagged keyv is counted; clean benign is not');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('e2e: --iocs flags installed packages in node_modules, deduped against lockfile', async () => {
  const root = await freshRoot();
  try {
    const lock = await writeLock('iocs-lock.json', {
      keyv: { version: '6.0.0' },
      'left-pad': { version: '1.3.0' },
    }, root);
    await mkdir(join(root, 'node_modules', 'evil'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'evil', 'package.json'), JSON.stringify({ name: 'evil', version: '1.0.0' }));
    await mkdir(join(root, 'node_modules', 'keyv'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'keyv', 'package.json'), JSON.stringify({ name: 'keyv', version: '6.0.0' }));

    const out = capture();
    const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--iocs', '--retries', '0'], { stdout: out, stderr: capture(), cwd: root });
    assert.equal(code, 1);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.found, 2);
    assert.equal(report.summary.iocScanned, 2);
    assert.equal(report.matches.length, 1);
    assert.equal(report.matches[0].name, 'keyv');
    assert.equal(report.iocMatches.length, 1);
    assert.equal(report.iocMatches[0].name, 'evil');
    assert.equal(report.iocMatches[0].path, join(root, 'node_modules', 'evil'));
    assert.ok(report.iocMatches[0].entry.osv.includes('GHSA-evil-mmmm-cccc'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('e2e: --iocs finds nothing when feeds are clean (exit 0)', async () => {
  const root = await freshRoot();
  try {
    const lock = await writeLock('iocs-clean-lock.json', {
      'left-pad': { version: '1.3.0' },
    }, root);
    await mkdir(join(root, 'node_modules', 'benign'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'benign', 'package.json'), JSON.stringify({ name: 'benign', version: '2.0.0' }));

    const out = capture();
    const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--iocs', '--retries', '0'], { stdout: out, stderr: capture(), cwd: root });
    assert.equal(code, 0);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.found, 0);
    assert.equal(report.summary.iocScanned, 1);
    assert.equal(report.iocMatches.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('e2e: --iocs-roots points at a different directory', async () => {
  const root = await freshRoot();
  try {
    const lock = await writeLock('iocs-roots-lock.json', {
      'left-pad': { version: '1.3.0' },
    }, root);
    const other = join(root, 'other-app');
    await mkdir(join(other, 'node_modules', 'evil'), { recursive: true });
    await writeFile(join(other, 'node_modules', 'evil', 'package.json'), JSON.stringify({ name: 'evil', version: '1.0.0' }));

    const out = capture();
    const code = await main(['--lockfile', lock, '--cache-dir', cacheDir, '--format', 'json', '--ttl', '0', '--iocs', '--iocs-roots', other, '--retries', '0'], { stdout: out, stderr: capture(), cwd: root });
    assert.equal(code, 1);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.iocScanned, 1);
    assert.equal(report.iocMatches[0].name, 'evil');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('e2e: --download-osv-db downloads the db and exits 0, then offline scan works with zero OSV calls', async () => {
  const cache = join(dir, 'offline-cache');
  await rm(cache, { recursive: true, force: true });

  requests = [];
  const dl = capture();
  const dlErr = capture();
  let code = await main(['--download-osv-db', '--cache-dir', cache, '--retries', '0'], { stdout: dl, stderr: dlErr, cwd: dir });
  assert.equal(code, 0);
  assert.match(dl.text, /Downloaded 2 malicious advisory records/);
  assert.ok(requests.includes('https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip'));

  const lock = await writeLock('offline-lock.json', { keyv: { version: '6.0.0' }, evil: { version: '1.0.0' } });
  requests = [];
  const out = capture();
  code = await main(['--lockfile', lock, '--cache-dir', cache, '--format', 'json', '--ttl', '0', '--osv-offline', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  assert.equal(requests.filter((u) => u.includes('api.osv.dev')).length, 0, 'offline mode must not call the OSV API');
  const report = JSON.parse(out.text);
  assert.equal(report.summary.found, 2);
  assert.equal(report.summary.osvSkipped, false);
  const keyv = report.matches.find((m) => m.name === 'keyv');
  assert.ok(keyv.entry.osv.includes('MAL-2026-11524'));
  assert.equal(keyv.advisories[0].id, 'MAL-2026-11524');
  assert.equal(keyv.advisories[0].summary, 'Malicious code in keyv (npm)');
  const evil = report.matches.find((m) => m.name === 'evil');
  assert.ok(evil.entry.osv.includes('GHSA-evil-mmmm-cccc'));
});

test('e2e: --osv-offline without a downloaded db exits 2 with guidance', async () => {
  const cache = join(dir, 'offline-missing-cache');
  await rm(cache, { recursive: true, force: true });
  const lock = await writeLock('offline-missing-lock.json', { keyv: { version: '6.0.0' } });
  const err = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cache, '--osv-offline', '--retries', '0'], { stdout: capture(), stderr: err, cwd: dir });
  assert.equal(code, 2);
  assert.match(err.text, /--download-osv-db/);
});

test('e2e: --osv-offline conflicts with --no-osv', async () => {
  const code = await run(['--osv-offline', '--no-osv', '--cache-dir', cacheDir, '--retries', '0']);
  assert.equal(code, 2);
});

test('e2e: advisory details cached between runs', async () => {
  const lock = await writeLock('cache-lock.json', { keyv: { version: '6.0.0' } });
  const isolatedCache = join(dir, 'cache-isolated');
  const base = ['--lockfile', lock, '--cache-dir', isolatedCache, '--format', 'json', '--retries', '0'];
  requests = [];
  let code = await main([...base], { stdout: capture(), stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const vulnFetches1 = requests.filter((u) => u.includes('/v1/vulns/')).length;
  assert.ok(vulnFetches1 >= 1);

  requests = [];
  code = await main([...base], { stdout: capture(), stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  const vulnFetches2 = requests.filter((u) => u.includes('/v1/vulns/')).length;
  assert.equal(vulnFetches2, 0, 'second run must reuse the advisory cache');
});

test('e2e: yarn v2 lockfile warns on stderr and exits 0', async () => {
  const yarnLock = join(dir, 'yarn-v2.lock');
  await writeFile(yarnLock, '# yarn lockfile v2\n\n__metadata:\n  version: 8\n');
  const err = capture();
  const code = await main(['--lockfile', yarnLock, '--cache-dir', cacheDir, '--format', 'json', '--no-osv', '--retries', '0'], { stdout: capture(), stderr: err, cwd: dir });
  assert.equal(code, 0);
  assert.match(err.text, /v2\/v3/);
});

test('e2e: --help prints usage and exits 0', async () => {
  const out = capture();
  const code = await main(['--help'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 0);
  assert.match(out.text, /npm-scan/);
  assert.match(out.text, /--lockfile/);
  assert.match(out.text, /--exclude-pkg/);
  assert.match(out.text, /--osv-offline/);
});

test('e2e: --version prints the version and exits 0', async () => {
  const out = capture();
  const code = await main(['--version'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 0);
  assert.match(out.text, /^npm-scan \d+\.\d+\.\d+\n$/);
});

test('e2e: --download-osv-db combined with --osv-offline refreshes and scans', async () => {
  const cache = join(dir, 'offline-combo-cache');
  await rm(cache, { recursive: true, force: true });
  const lock = await writeLock('offline-combo-lock.json', { keyv: { version: '6.0.0' } });
  requests = [];
  const out = capture();
  const code = await main(['--lockfile', lock, '--cache-dir', cache, '--format', 'json', '--ttl', '0', '--download-osv-db', '--osv-offline', '--retries', '0'], { stdout: out, stderr: capture(), cwd: dir });
  assert.equal(code, 1);
  assert.match(out.text, /Downloaded 2 malicious advisory records/);
  assert.equal(requests.filter((u) => u.includes('api.osv.dev')).length, 0, 'refresh + offline scan must not call the OSV API');
  const report = JSON.parse(out.text.slice(out.text.indexOf('\n') + 1));
  assert.equal(report.summary.found, 1);
  assert.ok(report.matches[0].entry.osv.includes('MAL-2026-11524'));
});

test('e2e: --download-osv-db network failure exits 2', async () => {
  const err = capture();
  failOsvDb = true;
  try {
    const code = await main(['--download-osv-db', '--cache-dir', join(dir, 'db-fail-cache'), '--retries', '0'], { stdout: capture(), stderr: err, cwd: dir });
    assert.equal(code, 2);
    assert.match(err.text, /db network down/);
  } finally {
    failOsvDb = false;
  }
});

test('e2e: no lockfile present exits 2 and lists candidates', async () => {
  const empty = await freshRoot();
  try {
    const err = capture();
    const code = await main(['--cache-dir', cacheDir, '--ttl', '0', '--retries', '0'], { stdout: capture(), stderr: err, cwd: empty });
    assert.equal(code, 2);
    assert.match(err.text, /no lock file found/);
    assert.match(err.text, /package-lock\.json, yarn\.lock, pnpm-lock\.yaml, bun\.lock/);
  } finally {
    await rm(empty, { recursive: true, force: true });
  }
});

test('e2e: a failing indicator source is skipped with a warning', async () => {
  const lock = await writeLock('failcsv-lock.json', { keyv: { version: '6.0.0' } });
  const cache = join(dir, 'failcsv-cache');
  await rm(cache, { recursive: true, force: true });
  const out = capture();
  const err = capture();
  failCsv = true;
  try {
    const code = await main(['--lockfile', lock, '--cache-dir', cache, '--format', 'json', '--ttl', '0', '--no-osv', '--retries', '0'], { stdout: out, stderr: err, cwd: dir });
    assert.equal(code, 0);
    assert.match(err.text, /skipping source/);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.sources, 0);
    assert.equal(report.sources.length, 4);
    assert.ok(report.sources.every((s) => s.skipped === true));
  } finally {
    failCsv = false;
  }
});

test('e2e: built-in and custom sources fall back to stale cached copies', async () => {
  const cache = join(dir, 'stale-cache');
  await rm(cache, { recursive: true, force: true });
  const lock = await writeLock('stale-lock.json', {
    keyv: { version: '6.0.0' },
    'custom-evil': { version: '1.0.0' },
  });
  const base = ['--lockfile', lock, '--cache-dir', cache, '--format', 'json', '--ttl', '0', '--no-osv', '--retries', '0'];
  const prime = await main([...base, '--csv', 'https://example.test/custom.csv'], { stdout: capture(), stderr: capture(), cwd: dir });
  assert.equal(prime, 1, 'prime run should match keyv + custom-evil');

  const out = capture();
  const err = capture();
  failCsv = true;
  try {
    const code = await main([...base, '--csv', 'https://example.test/custom.csv'], { stdout: out, stderr: err, cwd: dir });
    assert.equal(code, 1);
    assert.match(err.text, /using stale cached copy/);
    const report = JSON.parse(out.text);
    assert.equal(report.summary.staleSources, 5);
    assert.equal(report.summary.found, 2);
    assert.ok(report.sources.every((s) => s.stale === true));
  } finally {
    failCsv = false;
  }
});
