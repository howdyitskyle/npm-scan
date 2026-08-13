import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { zipSync, strToU8 } from 'fflate';
import { setFetch } from '../src/util.js';
import { downloadOsvDb, loadOsvDb, queryLocalOsv, OSV_DB_FILE, OSV_DB_META_FILE } from '../src/osvdb.js';

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'npm-scan-osvdb-'));
}

const RECORDS = [
  {
    id: 'MAL-keyv',
    summary: 'bad keyv',
    affected: [
      { package: { ecosystem: 'npm', name: 'keyv' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.0.1' }] }] },
    ],
  },
  {
    id: 'GHSA-old',
    summary: 'old vuln',
    affected: [{ package: { name: 'legacy' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { last_affected: '2.5.0' }] }] }],
  },
  {
    id: 'GHSA-pypi',
    affected: [{ package: { ecosystem: 'pypi', name: 'evil' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
  },
  {
    id: 'MAL-ecosystem-range',
    affected: [{ package: { name: 'barepkg' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }] }],
  },
  {
    id: 'MAL-multi-range',
    affected: [
      { package: { ecosystem: 'npm', name: 'multi' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] },
      { package: { ecosystem: 'npm', name: 'multi' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }, { fixed: '3.0.0' }] }] },
    ],
  },
  {
    id: 'MAL-fixed-only',
    summary: 'fixed only',
    affected: [{ package: { ecosystem: 'npm', name: 'fixedonly' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '2.0.0' }] }] }],
  },
  {
    id: 'MAL-no-range-type',
    summary: 'no range type',
    affected: [{ package: { ecosystem: 'npm', name: 'notype' }, ranges: [{ events: [{ introduced: '0' }] }] }],
  },
  { summary: 'missing id' },
  null,
];

test('downloadOsvDb: keeps MAL-* and malicious GHSA only, writes db + meta', async () => {
  const dir = await tempDir();
  const adv = (id, dbSpecific, affected = []) =>
    JSON.stringify({ id, summary: `summary ${id}`, database_specific: dbSpecific, affected });
  const zipBytes = zipSync({
    'MAL-2026-11524.json': strToU8(adv('MAL-2026-11524', { type: 'MALICIOUS' }, [
      { package: { ecosystem: 'npm', name: 'keyv' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.0.1' }] }] },
    ])),
    'GHSA-evil.json': strToU8(adv('GHSA-evil-mmmm-cccc', { type: 'MALICIOUS' })),
    'GHSA-benign.json': strToU8(adv('GHSA-pppp-qqqq-rrrr', { type: 'VULNERABILITY' })),
    'MAL-no-details.json': strToU8(adv('MAL-2026-99999', { type: 'MALICIOUS' })),
    'no-id.json': strToU8(JSON.stringify({ summary: 'missing id' })),
    'null.json': strToU8('null'),
    'not-json.json': strToU8('garbage'),
    'README.txt': strToU8('skip me'),
  });
  setFetch(() => Promise.resolve(new Response(zipBytes, { status: 200 })));
  try {
    const res = await downloadOsvDb({ dir });
    assert.equal(res.count, 3);
    const records = JSON.parse(await readFile(join(dir, OSV_DB_FILE), 'utf8'));
    assert.deepEqual(records.map((r) => r.id).sort(), ['GHSA-evil-mmmm-cccc', 'MAL-2026-11524', 'MAL-2026-99999']);
    const meta = JSON.parse(await readFile(join(dir, OSV_DB_META_FILE), 'utf8'));
    assert.equal(meta.count, 3);
    assert.ok(meta.downloadedAt);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('downloadOsvDb: download failure rejects', async () => {
  setFetch(() => Promise.reject(new Error('network down')));
  const dir = await tempDir();
  try {
    await assert.rejects(() => downloadOsvDb({ dir, retries: 0, backoffMs: 1 }), /network down/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('downloadOsvDb: corrupt zip rejects with unzip guidance', async () => {
  setFetch(() => Promise.resolve(new Response(new Uint8Array([1, 2, 3, 4]), { status: 200 })));
  const dir = await tempDir();
  try {
    await assert.rejects(() => downloadOsvDb({ dir, retries: 0, backoffMs: 1 }), /cannot unzip OSV database/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('loadOsvDb: missing file returns null', async () => {
  const dir = await tempDir();
  try {
    assert.equal(await loadOsvDb(dir), null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('queryLocalOsv: matches within introduced/fixed and last_affected ranges', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, OSV_DB_FILE), JSON.stringify(RECORDS));
  try {
    const db = await loadOsvDb(dir);
    assert.ok(db);
    assert.equal(db.byId.size, 7);
    assert.deepEqual(queryLocalOsv(db, 'keyv', '6.0.0').sort(), ['MAL-keyv']);
    assert.deepEqual(queryLocalOsv(db, 'keyv', '6.0.1'), []);
    assert.deepEqual(queryLocalOsv(db, 'keyv', '0.5.0'), ['MAL-keyv']);
    assert.deepEqual(queryLocalOsv(db, 'legacy', '2.5.0'), ['GHSA-old']);
    assert.deepEqual(queryLocalOsv(db, 'legacy', '2.5.1'), []);
    assert.deepEqual(queryLocalOsv(db, 'legacy', '0.9.0'), []);
    assert.deepEqual(queryLocalOsv(db, 'multi', '0.5.0'), ['MAL-multi-range']);
    assert.deepEqual(queryLocalOsv(db, 'multi', '2.5.0'), ['MAL-multi-range']);
    assert.deepEqual(queryLocalOsv(db, 'multi', '1.5.0'), []);
    assert.deepEqual(queryLocalOsv(db, 'fixedonly', '1.5.0'), ['MAL-fixed-only']);
    assert.deepEqual(queryLocalOsv(db, 'fixedonly', '2.0.0'), []);
    assert.deepEqual(queryLocalOsv(db, 'notype', '1.0.0'), ['MAL-no-range-type']);
    assert.deepEqual(queryLocalOsv(db, 'evil', '1.0.0'), [], 'pypi ecosystem excluded');
    assert.deepEqual(queryLocalOsv(db, 'barepkg', '1.0.0'), [], 'non-SEMVER range excluded');
    assert.deepEqual(queryLocalOsv(db, 'unknown', '1.0.0'), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
