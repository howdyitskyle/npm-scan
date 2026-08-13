import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { walkInstalledPackages } from '../src/iocs.js';

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'npm-scan-iocs-'));
}

async function writePkg(root, relDir, name, version) {
  const dir = join(root, relDir);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'package.json'), JSON.stringify({ name, version }));
  return dir;
}

test('walkInstalledPackages: finds root manifest, node_modules, scoped, and nested deps', async () => {
  const dir = await tempDir();
  try {
    await writePkg(dir, '.', 'my-app', '1.0.0');
    const evilDir = await writePkg(dir, 'node_modules/evil', 'evil', '1.0.0');
    await writePkg(dir, 'node_modules/@scope/left-pad', '@scope/left-pad', '2.0.0');
    await writePkg(dir, 'node_modules/evil/node_modules/keyv', 'keyv', '6.0.0');
    await writePkg(dir, 'lib/helper', 'lib-helper', '0.1.0');

    const pkgs = await walkInstalledPackages([dir]);
    const byName = Object.fromEntries(pkgs.map((p) => [p.name, p]));
    assert.deepEqual(Object.keys(byName).sort(), ['@scope/left-pad', 'evil', 'keyv', 'lib-helper', 'my-app']);
    assert.equal(byName.evil.path, evilDir);
    assert.equal(byName['@scope/left-pad'].version, '2.0.0');
    assert.equal(byName.keyv.version, '6.0.0');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('walkInstalledPackages: skips hidden dirs, .git, and ignores invalid manifests', async () => {
  const dir = await tempDir();
  try {
    await writePkg(dir, 'node_modules/ok', 'ok', '1.0.0');
    await writePkg(dir, 'node_modules/bad', 'bad', '1.0.0');
    await writeFile(join(dir, 'node_modules/bad', 'package.json'), 'not json');
    await writePkg(dir, '.hidden', 'sneaky', '9.9.9');
    await mkdir(join(dir, '.git'), { recursive: true });
    await writePkg(dir, '.git/hooks', 'git-hook', '1.0.0');

    const pkgs = await walkInstalledPackages([dir]);
    assert.deepEqual(pkgs.map((p) => p.name), ['ok']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('walkInstalledPackages: dedupes name@version keeping first path', async () => {
  const dir = await tempDir();
  try {
    const rootPkg = await writePkg(dir, '.', 'evil', '1.0.0');
    const nmPkg = await writePkg(dir, 'node_modules/evil', 'evil', '1.0.0');
    const pkgs = await walkInstalledPackages([dir]);
    assert.equal(pkgs.length, 1);
    assert.ok([rootPkg, nmPkg].includes(pkgs[0].path), `unexpected path ${pkgs[0].path}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('walkInstalledPackages: pnpm virtual store packages are found', async () => {
  const dir = await tempDir();
  try {
    const dirs = [
      await writePkg(dir, 'node_modules/.pnpm/keyv@6.0.0/node_modules/keyv', 'keyv', '6.0.0'),
      await writePkg(dir, 'node_modules/.pnpm/left-pad@1.3.0/node_modules/left-pad', 'left-pad', '1.3.0'),
    ];
    const pkgs = await walkInstalledPackages([dir]);
    const byName = Object.fromEntries(pkgs.map((p) => [p.name, p]));
    assert.deepEqual(Object.keys(byName).sort(), ['keyv', 'left-pad']);
    assert.ok(dirs.includes(byName.keyv.path));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('walkInstalledPackages: unreadable roots are skipped, multiple roots merged', async () => {
  const dir = await tempDir();
  try {
    await writePkg(dir, 'one/node_modules/alpha', 'alpha', '1.0.0');
    await writePkg(dir, 'two/node_modules/beta', 'beta', '2.0.0');
    const pkgs = await walkInstalledPackages([join(dir, 'one'), join(dir, 'two'), join(dir, 'missing')]);
    assert.deepEqual(pkgs.map((p) => p.name).sort(), ['alpha', 'beta']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('walkInstalledPackages: warns and returns partial results past the file cap', async () => {
  const dir = await tempDir();
  try {
    await writePkg(dir, 'node_modules/a', 'a', '1.0.0');
    await writePkg(dir, 'node_modules/b', 'b', '1.0.0');
    await writePkg(dir, 'node_modules/c', 'c', '1.0.0');
    const warnings = [];
    const pkgs = await walkInstalledPackages([dir], { warn: (m) => warnings.push(m), maxFiles: 3 });
    assert.deepEqual(pkgs.map((p) => p.name).sort(), ['a', 'b']);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /file walk exceeded 3 entries/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('walkInstalledPackages: skips hidden entries inside node_modules', async () => {
  const dir = await tempDir();
  try {
    await writePkg(dir, 'node_modules/ok', 'ok', '1.0.0');
    await writePkg(dir, 'node_modules/.cache', 'sneaky', '9.9.9');
    const pkgs = await walkInstalledPackages([dir]);
    assert.deepEqual(pkgs.map((p) => p.name), ['ok']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('walkInstalledPackages: file cap trips on top-level entries returning partial results', async () => {
  const dir = await tempDir();
  try {
    await writePkg(dir, 'a', 'a', '1.0.0');
    await writePkg(dir, 'b', 'b', '1.0.0');
    await writePkg(dir, 'c', 'c', '1.0.0');
    await writePkg(dir, 'd', 'd', '1.0.0');
    const warnings = [];
    const pkgs = await walkInstalledPackages([dir], { warn: (m) => warnings.push(m), maxFiles: 3 });
    assert.equal(pkgs.length, 0);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /file walk exceeded 3 entries/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
