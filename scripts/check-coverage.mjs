import { spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const testDir = fileURLToPath(new URL('../test/', import.meta.url));
const srcDir = fileURLToPath(new URL('../src/', import.meta.url));

const files = (await readdir(testDir))
  .filter((f) => f.endsWith('.test.mjs'))
  .sort()
  .map((f) => join(testDir, f));

const res = spawnSync(process.execPath, ['--test', '--experimental-test-coverage', ...files], {
  encoding: 'utf8',
});
const output = `${res.stdout}\n${res.stderr}`;
if (res.status !== 0) {
  process.stderr.write(output);
  process.exit(1);
}

const srcFiles = new Set((await readdir(srcDir)).filter((f) => f.endsWith('.js')));
const seen = new Set();
let failed = false;
const rows = [];
for (const line of output.split('\n')) {
  const m = line.match(/^(?:#|\u2139)\s+(\S+)\s+\|\s+([\d.]+)\s+\|/);
  if (!m || !srcFiles.has(m[1])) continue;
  seen.add(m[1]);
  rows.push([m[1], m[2]]);
  if (m[2] !== '100.00') {
    failed = true;
    process.stderr.write(`FAIL: ${m[1]} is at ${m[2]}% line coverage (target 100.00%)\n`);
  }
}

for (const f of srcFiles) {
  if (!seen.has(f)) {
    failed = true;
    process.stderr.write(`FAIL: ${f} was not reported by the coverage run\n`);
  }
}

if (!failed) {
  for (const [file, pct] of rows.sort()) {
    process.stdout.write(`${file}: ${pct}% line coverage\n`);
  }
  process.stdout.write(`coverage OK (${rows.length} src files at 100%)\n`);
}
process.exit(failed ? 1 : 0);
