import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { detectFormat, parseLockFile, loadLockfile, satisfies, compareVersions } from '../src/lockfile.js';

const FIX = (...p) => join(process.cwd(), 'test', 'fixtures', ...p);

function contains(list, name, version) {
  return list.some((p) => p.name === name && p.version === version);
}

async function fix(name) {
  return readFile(FIX(name), 'utf8');
}

test('detectFormat by basename', () => {
  assert.equal(detectFormat('package-lock.json'), 'package-lock');
  assert.equal(detectFormat('yarn.lock'), 'yarn');
  assert.equal(detectFormat('pnpm-lock.yaml'), 'pnpm');
  assert.equal(detectFormat('pnpm-lock.yml'), 'pnpm');
  assert.equal(detectFormat('bun.lock'), 'bun');
  assert.equal(detectFormat('bun.lockb'), 'bun-binary');
  assert.equal(detectFormat('other.lock'), null);
});

test('loadLockfile sniffs content when basename is unrecognized', async () => {
  const yarn = await loadLockfile(FIX('yarn-v1.lock'));
  assert.equal(yarn.format, 'yarn');
  assert.ok(contains(yarn.list, 'keyv', '6.0.0'));

  const pnpm = await loadLockfile(FIX('pnpm-lock.yaml'));
  assert.equal(pnpm.format, 'pnpm');
  assert.ok(contains(pnpm.list, 'keyv', '6.0.0'));

  const bogus = join(process.cwd(), 'test', 'fixtures', 'bogus.lock');
  await writeFile(bogus, 'not a lock file: ???\n');
  try {
    await assert.rejects(() => loadLockfile(bogus), /Unrecognized lock file format/);
  } finally {
    await rm(bogus, { force: true });
  }
});

test('parseLockFile: package-lock v3', async () => {
  const lock = parseLockFile(await fix('malicious-v3.json'), 'package-lock');
  assert.equal(lock.format, 'package-lock');
  assert.equal(lock.version, 3);
  assert.ok(contains(lock.list, 'keyv', '6.0.0'));
  assert.ok(contains(lock.list, 'proxy-from-env', '1.1.0'));
  assert.equal(lock.list.length, 6);
  assert.ok(lock.graph.directNames.has('keyv'));
  assert.ok(lock.graph.directNames.has('axios'));
});

test('parseLockFile: package-lock v1 nested deps build graph', async () => {
  const lock = parseLockFile(await fix('malicious-v1.json'), 'package-lock');
  assert.equal(lock.version, 1);
  assert.ok(contains(lock.list, 'keyv', '6.0.0'));
  assert.ok(contains(lock.list, '@emilgroup/accounting-sdk', '1.27.3'));
  assert.ok(lock.graph.directNames.has('keyv'));
  const dependents = lock.graph.dependents.get('@emilgroup/accounting-sdk@1.27.3');
  assert.ok(dependents && dependents.has('keyv'));
});

test('parseLockFile: package-lock v2 with link entries is skipped', () => {
  const json = {
    lockfileVersion: 2,
    packages: {
      '': { dependencies: { a: '1.0.0' } },
      'node_modules/a': { version: '1.0.0', link: true },
      'node_modules/b': { version: '2.0.0' },
    },
  };
  const lock = parseLockFile(JSON.stringify(json), 'package-lock');
  assert.ok(!lock.list.some((p) => p.name === 'a'));
  assert.ok(lock.list.some((p) => p.name === 'b'));
});

test('parseLockFile: yarn v1', async () => {
  const lock = parseLockFile(await fix('yarn-v1.lock'), 'yarn');
  assert.equal(lock.format, 'yarn');
  assert.ok(contains(lock.list, 'keyv', '6.0.0'));
  assert.ok(lock.list.some((p) => p.name === 'lodash' && p.version === '4.17.21'));
  assert.ok(lock.list.some((p) => p.name === '@babel/code-frame' && p.version === '7.0.0'));
});

test('parseLockFile: yarn v2 warns and returns no packages', async () => {
  const lock = parseLockFile(await fix('yarn-v2.lock'), 'yarn');
  assert.equal(lock.list.length, 0);
  assert.ok(lock.warnings.some((w) => w.includes('v2/v3')));
});

test('parseLockFile: pnpm v9', async () => {
  const lock = parseLockFile(await fix('pnpm-lock.yaml'), 'pnpm');
  assert.equal(lock.format, 'pnpm');
  assert.ok(contains(lock.list, 'keyv', '6.0.0'));
  assert.ok(lock.list.some((p) => p.name === '@babel/code-frame' && p.version === '7.0.0'));
  assert.ok(lock.list.some((p) => p.name === 'left-pad' && p.version === '1.3.0'));
});

test('parseLockFile: pnpm peer-dependency keys are split on the package version', () => {
  const text = [
    'lockfileVersion: 9.0',
    '',
    'packages:',
    '',
    "  foo@1.0.0(bar@2.0.0):",
    "    resolution: {integrity: sha512-AAAA}",
    "  '@scope/pkg@3.2.1(@types/peer@4.0.0)':",
    "    resolution: {integrity: sha512-BBBB}",
    '',
    'snapshots:',
    '  foo@1.0.0(bar@2.0.0): {}',
  ].join('\n');
  const lock = parseLockFile(text, 'pnpm');
  assert.ok(contains(lock.list, 'foo', '1.0.0'));
  assert.ok(contains(lock.list, '@scope/pkg', '3.2.1'));
  assert.equal(lock.list.some((p) => p.name.includes('(')), false);
});

test('parseLockFile: bun.lock (JSONC text format)', async () => {
  const lock = parseLockFile(await fix('bun.lock'), 'bun');
  assert.equal(lock.format, 'bun');
  assert.ok(contains(lock.list, 'keyv', '6.0.0'));
  assert.ok(contains(lock.list, 'left-pad', '1.3.0'));
  assert.ok(lock.graph.directNames.has('keyv'));
  assert.ok(lock.graph.directNames.has('left-pad'));
  assert.ok(lock.warnings.some((w) => w.includes('non-semver')));
});

test('parseLockFile: bun.lock tolerates // comments and trailing commas', () => {
  const text = [
    '{',
    '  // top comment',
    '  "lockfileVersion": 1,',
    '  "packages": {',
    '    "left-pad": ["left-pad@1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", {}, "sha512-x"],',
    '  },',
    '}',
  ].join('\n');
  const lock = parseLockFile(text, 'bun');
  assert.ok(contains(lock.list, 'left-pad', '1.3.0'));
});

test('parseLockFile: bun.lock tolerates /* block comments */', () => {
  const text = [
    '{',
    '  /* block',
    '     comment */',
    '  "lockfileVersion": 1,',
    '  "packages": {',
    '    "left-pad": ["left-pad@1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", {}, "sha512-x"],',
    '  },',
    '}',
  ].join('\n');
  const lock = parseLockFile(text, 'bun');
  assert.ok(contains(lock.list, 'left-pad', '1.3.0'));
});

test('parseLockFile: bun.lock that is not valid JSON throws JSONC error', () => {
  assert.throws(() => parseLockFile('{oops not json', 'bun'), /bun\.lock is not valid JSON \(JSONC\)/);
});

test('parseLockFile: bun-binary format throws guidance', () => {
  assert.throws(() => parseLockFile('', 'bun-binary'), /binary bun\.lockb is not supported/);
});

test('parseLockFile: unknown format throws', () => {
  assert.throws(() => parseLockFile('x', 'yaml'), /Unsupported lock file format: yaml/);
});

test('satisfies: common ranges', () => {
  assert.ok(satisfies('^1.2.3', '1.9.0'));
  assert.ok(!satisfies('^1.2.3', '2.0.0'));
  assert.ok(satisfies('~1.2.0', '1.2.9'));
  assert.ok(!satisfies('~1.2.0', '1.3.0'));
  assert.ok(satisfies('1.2.3', '1.2.3'));
  assert.ok(!satisfies('1.2.3', '1.2.4'));
  assert.ok(satisfies('*', '9.9.9'));
  assert.ok(satisfies('>=1.0.0', '1.5.0'));
  assert.ok(!satisfies('<1.0.0', '1.0.0'));
  assert.ok(satisfies('>=1.0.0 <2.0.0', '1.5.0'));
  assert.ok(!satisfies('>=1.0.0 <2.0.0', '2.5.0'));
  assert.ok(satisfies('^1.0.0 || ^2.0.0', '2.3.0'));
});

test('satisfies: x-ranges and partial versions', () => {
  assert.ok(satisfies('1.x', '1.5.0'));
  assert.ok(!satisfies('1.x', '2.0.0'));
  assert.ok(satisfies('1.2.x', '1.2.9'));
  assert.ok(!satisfies('1.2.x', '1.3.0'));
  assert.ok(satisfies('1', '1.9.0'));
  assert.ok(!satisfies('1', '2.0.0'));
  assert.ok(satisfies('1.2', '1.2.7'));
  assert.ok(!satisfies('1.2', '1.3.0'));
  assert.ok(satisfies('~1.x', '1.9.0'));
  assert.ok(!satisfies('~1.x', '2.0.0'));
  assert.ok(satisfies('~1.2.x', '1.2.9'));
  assert.ok(!satisfies('~1.2.x', '1.3.0'));
  assert.ok(satisfies('^1.x', '1.9.0'));
  assert.ok(satisfies('^1.2.x', '1.9.0'));
  assert.ok(!satisfies('^1.2.x', '2.0.0'));
  assert.ok(satisfies('^0.x', '0.5.0'));
  assert.ok(!satisfies('^0.x', '1.0.0'));
});

test('satisfies: prerelease and build metadata ranges', () => {
  assert.ok(satisfies('^1.2.3-beta.1', '1.2.3'));
  assert.ok(satisfies('^1.2.3-beta.1', '1.4.0'));
  assert.ok(!satisfies('^1.2.3-beta.1', '2.0.0'));
  assert.ok(satisfies('>=1.0.0-alpha', '1.0.0'));
  assert.ok(!satisfies('>=1.1.0', '1.0.9'));
  assert.ok(satisfies('1.2.3+build.5', '1.2.3'));
});

test('compareVersions', () => {
  assert.ok(compareVersions('1.2.3', '1.2.4') < 0);
  assert.ok(compareVersions('2.0.0', '1.9.9') > 0);
  assert.equal(compareVersions('1.0.0', '1.0.0'), 0);
});
