import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseCsv, parseIocCsv } from '../src/csv.js';
import { join } from 'node:path';

const FIX = (...p) => join(process.cwd(), 'test', 'fixtures', ...p);

function contains(entries, name, version) {
  return entries.some(([n, v]) => n === name && v === version);
}

test('parseCsv handles quoted fields and escaped quotes', () => {
  const text = 'a,b,c\n"1,2",x,"say ""hi"""\n';
  const rows = parseCsv(text);
  assert.deepEqual(rows, [
    ['a', 'b', 'c'],
    ['1,2', 'x', 'say "hi"'],
  ]);
});

test('parseIocCsv: keyv schema (ecosystem/package/versions)', async () => {
  const entries = parseIocCsv(await readFile(FIX('iocs-keyv.csv'), 'utf8'));
  assert.ok(contains(entries, 'keyv', '6.0.0'));
  assert.ok(contains(entries, 'keyv', '5.2.3'));
  assert.ok(contains(entries, '@scope/foo', '1.0.0'));
  assert.ok(contains(entries, '@scope/foo', '2.0.0'));
  assert.ok(!entries.some(([n]) => n === 'express'));
});

test('parseIocCsv: shai-hulud schema (package_name/package_versions)', async () => {
  const entries = parseIocCsv(await readFile(FIX('iocs-shai-hulud.csv'), 'utf8'));
  assert.ok(contains(entries, 'keyv', '6.0.0'));
});

test('parseIocCsv: axios schema (type/indicator) parses name@version', async () => {
  const entries = parseIocCsv(await readFile(FIX('iocs-axios.csv'), 'utf8'));
  assert.ok(contains(entries, 'axios', '1.14.1'));
  assert.ok(contains(entries, 'keyv', '6.0.0'));
});

test('parseIocCsv: teampcp schema (artifact_type/name/affected_versions) with quoted versions', async () => {
  const entries = parseIocCsv(await readFile(FIX('iocs-teampcp.csv'), 'utf8'));
  assert.ok(contains(entries, 'keyv', '6.0.0'));
  assert.ok(contains(entries, 'keyv', '5.2.3'));
  assert.ok(contains(entries, 'axios', '1.14.1'));
});

test('parseIocCsv: generic name/version schema', async () => {
  const entries = parseIocCsv(await readFile(FIX('iocs-generic.csv'), 'utf8'));
  assert.ok(contains(entries, 'custom-evil', '1.0.0'));
  assert.ok(contains(entries, 'custom-other', '2.1.0'));
});

test('parseIocCsv: filters non-npm rows', () => {
  const csv = 'artifact_type,name,affected_versions\nnpm package,a,1.0.0\nnuget package,b,2.0.0\n';
  const entries = parseIocCsv(csv);
  assert.deepEqual(entries, [['a', '1.0.0']]);
});

test('parseIocCsv: unrecognized schema throws', () => {
  assert.throws(() => parseIocCsv('foo,bar\n1,2\n'), /Unrecognized CSV schema/);
});

test('parseIocCsv: skips header-only and n/a versions', () => {
  const csv = 'package_name,package_versions\nkeyv,n/a\n';
  assert.deepEqual(parseIocCsv(csv), []);
});

test('parseCsv: trailing record without a newline is emitted', () => {
  const rows = parseCsv('a,b\n1,2');
  assert.deepEqual(rows, [
    ['a', 'b'],
    ['1', '2'],
  ]);
});
