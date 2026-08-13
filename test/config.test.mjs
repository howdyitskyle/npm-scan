import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, resolveOptions, ttlFor, FORMATS } from '../src/config.js';

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'npm-scan-config-'));
}

test('parseArgs: parses flags and repeated csv', () => {
  const { flags, errors, help } = parseArgs([
    '--lockfile', 'a.json',
    '--csv', 'one.csv',
    '--csv', 'two.csv',
    '--no-osv',
    '--format', 'json',
    '--verbose',
  ]);
  assert.equal(errors.length, 0);
  assert.equal(help, false);
  assert.equal(flags.lockfile, 'a.json');
  assert.deepEqual(flags.csv, ['one.csv', 'two.csv']);
  assert.equal(flags.noOsv, true);
  assert.equal(flags.format, 'json');
  assert.equal(flags.verbose, true);
});

test('parseArgs: unknown option sets help and error', () => {
  const { errors, help } = parseArgs(['--bogus']);
  assert.equal(help, true);
  assert.ok(errors.some((e) => e.includes('--bogus')));
});

test('parseArgs: missing value reports error', () => {
  const { errors } = parseArgs(['--lockfile']);
  assert.ok(errors.some((e) => e.includes('requires a value')));
});

test('resolveOptions: defaults', () => {
  const { opts, errors } = resolveOptions([]);
  assert.equal(errors.length, 0);
  assert.equal(opts.format, 'pretty');
  assert.equal(opts.ttl, 24);
  assert.equal(opts.noOsv, false);
});

test('resolveOptions: config file merge with CLI precedence', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, '.npmscanrc.json'), JSON.stringify({
    lockfile: 'from-config.json',
    format: 'markdown',
    verbose: true,
    ttl: 6,
  }));
  const { opts } = resolveOptions(['--config', join(dir, '.npmscanrc.json'), '--format', 'sarif']);
  assert.equal(opts.lockfile, 'from-config.json');
  assert.equal(opts.format, 'sarif');
  assert.equal(opts.verbose, true);
  assert.equal(opts.ttl, 6);
});

test('resolveOptions: config osv:false sets noOsv, --osv overrides', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, '.npmscanrc.json'), JSON.stringify({ osv: false }));
  const cfg = join(dir, '.npmscanrc.json');
  assert.equal(resolveOptions(['--config', cfg]).opts.noOsv, true);
  assert.equal(resolveOptions(['--config', cfg, '--osv']).opts.noOsv, false);
});

test('resolveOptions: invalid format rejected', () => {
  const { errors } = resolveOptions(['--format', 'yaml']);
  assert.ok(errors.some((e) => e.includes('Unknown format')));
});

test('resolveOptions: invalid source rejected', () => {
  const { errors } = resolveOptions(['--sources', 'keyv,banana']);
  assert.ok(errors.some((e) => e.includes('banana')));
});

test('resolveOptions: sources array in config joins to comma list', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, '.npmscanrc.json'), JSON.stringify({ sources: ['keyv', 'teampcp'] }));
  const { opts } = resolveOptions(['--config', join(dir, '.npmscanrc.json')]);
  assert.equal(opts.sources, 'keyv,teampcp');
});

test('ttlFor: number vs per-source object', () => {
  assert.equal(ttlFor({ ttl: 24 }, 'keyv'), 24 * 3600 * 1000);
  assert.equal(ttlFor({ ttl: { keyv: 2, default: 48 } }, 'keyv'), 2 * 3600 * 1000);
  assert.equal(ttlFor({ ttl: { keyv: 2, default: 48 } }, 'osv'), 48 * 3600 * 1000);
  assert.equal(ttlFor({ ttl: 0 }, 'keyv'), 0);
});

test('parseArgs: parses --json, --timeout-ms, --backoff-ms, and --retries', () => {
  const { flags, errors } = parseArgs(['--json', '--timeout-ms', '15000', '--backoff-ms', '250', '--retries', '5']);
  assert.equal(errors.length, 0);
  assert.equal(flags.json, true);
  assert.equal(flags.timeoutMs, 15000);
  assert.equal(flags.backoffMs, 250);
  assert.equal(flags.retries, 5);
});

test('resolveOptions: --json shortcuts to json format', () => {
  const { opts, errors } = resolveOptions(['--json']);
  assert.equal(errors.length, 0);
  assert.equal(opts.format, 'json');
});

test('resolveOptions: invalid ttl rejected', () => {
  assert.ok(resolveOptions(['--ttl', '-5']).errors.some((e) => e.includes('Invalid --ttl')));
  assert.ok(resolveOptions(['--ttl', 'abc']).errors.some((e) => e.includes('Invalid --ttl')));
  assert.equal(resolveOptions(['--ttl', '0']).errors.length, 0);
});

test('resolveOptions: invalid retries/timeout/backoff rejected', () => {
  assert.ok(resolveOptions(['--retries', 'abc']).errors.some((e) => e.includes('Invalid --retries')));
  assert.ok(resolveOptions(['--retries', '-1']).errors.some((e) => e.includes('Invalid --retries')));
  assert.ok(resolveOptions(['--timeout-ms', 'abc']).errors.some((e) => e.includes('Invalid --timeout-ms')));
  assert.ok(resolveOptions(['--backoff-ms', '-5']).errors.some((e) => e.includes('Invalid --backoff-ms')));
  assert.equal(resolveOptions(['--retries', '3', '--timeout-ms', '0', '--backoff-ms', '0']).errors.length, 0);
});

test('FORMATS includes all output formats', () => {
  assert.deepEqual(FORMATS, ['pretty', 'compact', 'markdown', 'json', 'sarif', 'gh-annotations']);
});
