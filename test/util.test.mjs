import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, stat, utimes, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chunk, padEnd, truncate, sha256, fetchWithRetry, fetchCached, wrapAnsi, truncateAnsi } from '../src/util.js';
import { setFetch } from '../src/util.js';

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'npm-scan-util-'));
}

test('chunk splits arrays', () => {
  assert.deepEqual(chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
});

test('padEnd pads and truncates naturally', () => {
  assert.equal(padEnd('ab', 4), 'ab  ');
  assert.equal(padEnd('abcd', 2), 'abcd');
});

test('truncate adds ellipsis', () => {
  assert.equal(truncate('hello world', 8), 'hello w\u2026');
  assert.equal(truncate('short', 10), 'short');
});

test('sha256 is stable hex', () => {
  assert.equal(sha256('abc').length, 64);
  assert.equal(sha256('abc'), sha256('abc'));
  assert.notEqual(sha256('abc'), sha256('abd'));
});

test('fetchWithRetry returns response on ok', async () => {
  setFetch(async () => new Response('ok', { status: 200 }));
  const res = await fetchWithRetry('https://example.test/data', { retries: 0 });
  assert.equal(await res.text(), 'ok');
});

test('fetchWithRetry retries then succeeds', async () => {
  let calls = 0;
  setFetch(async () => {
    calls++;
    if (calls < 3) return new Response('fail', { status: 503 });
    return new Response('ok', { status: 200 });
  });
  const res = await fetchWithRetry('https://example.test/data', { retries: 3, backoffMs: 1 });
  assert.equal(await res.text(), 'ok');
  assert.equal(calls, 3);
});

test('fetchWithRetry throws after exhausting retries', async () => {
  setFetch(async () => new Response('fail', { status: 500 }));
  await assert.rejects(
    () => fetchWithRetry('https://example.test/data', { retries: 2, backoffMs: 1 }),
    /HTTP 500/
  );
});

test('fetchWithRetry passes POST body', async () => {
  let seenBody = null;
  setFetch(async (_url, opts) => {
    seenBody = opts.body;
    return new Response('{}', { status: 200 });
  });
  await fetchWithRetry('https://example.test/api', {
    method: 'POST',
    body: JSON.stringify({ a: 1 }),
    retries: 0,
  });
  assert.equal(seenBody, '{"a":1}');
});

test('fetchWithRetry sends a versioned user-agent', async () => {
  let seenHeaders = null;
  setFetch(async (_url, opts) => {
    seenHeaders = opts.headers;
    return new Response('ok', { status: 200 });
  });
  await fetchWithRetry('https://example.test/data', { retries: 0 });
  assert.match(seenHeaders['user-agent'], /^npm-scan\/\d+\.\d+\.\d+$/);
});

test('fetchWithRetry aborts on timeout', async () => {
  setFetch(
    (_url, opts) =>
      new Promise((_resolve, reject) => {
        opts.signal.addEventListener('abort', () => reject(new Error('aborted')));
      })
  );
  await assert.rejects(
    () => fetchWithRetry('https://example.test/slow', { retries: 0, timeoutMs: 50 }),
    /aborted/
  );
});

test('fetchWithRetry retries on network errors, not just HTTP status', async () => {
  let calls = 0;
  setFetch(async () => {
    calls++;
    if (calls < 2) throw new Error('ECONNRESET');
    return new Response('ok', { status: 200 });
  });
  const res = await fetchWithRetry('https://example.test/data', { retries: 2, backoffMs: 1 });
  assert.equal(await res.text(), 'ok');
  assert.equal(calls, 2);
});

test('fetchCached: serves fresh cache without downloading', async () => {
  const dir = await tempDir();
  const cachePath = join(dir, 'feed.csv');
  await mkdir(dir, { recursive: true });
  await writeFile(cachePath, 'a,1.0.0\n');
  let calls = 0;
  setFetch(async () => {
    calls++;
    return new Response('never', { status: 200 });
  });
  try {
    const result = await fetchCached('https://example.test/feed.csv', cachePath, 24 * 3600 * 1000, 'feed');
    assert.equal(result.text, 'a,1.0.0\n');
    assert.equal(result.fromCache, true);
    assert.equal(result.stale, false);
    assert.equal(calls, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fetchCached: downloads when cache is stale and stores it', async () => {
  const dir = await tempDir();
  const cachePath = join(dir, 'feed.csv');
  await mkdir(dir, { recursive: true });
  await writeFile(cachePath, 'a,1.0.0\n');
  const old = new Date(Date.now() - 48 * 3600 * 1000);
  await utimes(cachePath, old, old);
  setFetch(async () => new Response('b,2.0.0\n', { status: 200 }));
  try {
    const result = await fetchCached('https://example.test/feed.csv', cachePath, 24 * 3600 * 1000, 'feed', { retries: 0 });
    assert.equal(result.text, 'b,2.0.0\n');
    assert.equal(result.fromCache, false);
    assert.equal(result.stale, false);
    const st = await stat(cachePath);
    assert.equal(st.mtimeMs, result.mtimeMs);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fetchCached: network failure falls back to stale cached copy with stale flag', async () => {
  const dir = await tempDir();
  const cachePath = join(dir, 'feed.csv');
  await mkdir(dir, { recursive: true });
  await writeFile(cachePath, 'a,1.0.0\n');
  const old = new Date(Date.now() - 48 * 3600 * 1000);
  await utimes(cachePath, old, old);
  const st = await stat(cachePath);
  setFetch(async () => {
    throw new Error('ECONNREFUSED');
  });
  try {
    const result = await fetchCached('https://example.test/feed.csv', cachePath, 1, 'feed', { retries: 0 });
    assert.equal(result.text, 'a,1.0.0\n');
    assert.equal(result.fromCache, true);
    assert.equal(result.stale, true);
    assert.equal(result.mtimeMs, st.mtimeMs);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fetchCached: throws when nothing is cached and network fails', async () => {
  const dir = await tempDir();
  const cachePath = join(dir, 'never-downloaded.csv');
  setFetch(async () => {
    throw new Error('ENOTFOUND');
  });
  try {
    await assert.rejects(
      () => fetchCached('https://example.test/feed.csv', cachePath, 1, 'feed', { retries: 0 }),
      /ENOTFOUND/
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const visible = (s) => s.replace(/\u001b\[[0-9;]*m|\u001b\][^\u0007\u001b]*\u0007/g, '');

test('wrapAnsi: returns text unchanged when it fits', () => {
  assert.equal(wrapAnsi('short line', 80), 'short line');
});

test('wrapAnsi: flushes the current line before an overlong URL', () => {
  const out = wrapAnsi('xxxxxxxxxxxx https://a.io', 14);
  assert.deepEqual(out.split('\n'), ['xxxxxxxxxxxx', 'https://a.io']);
});

test('wrapAnsi: wraps to a new line when adding a word would overflow', () => {
  assert.deepEqual(wrapAnsi('aaaa bbbb', 5).split('\n'), ['aaaa', 'bbbb']);
});

test('wrapAnsi: preserves leading indent on every wrapped line', () => {
  const out = wrapAnsi('   aaa bbb ccc', 6);
  assert.ok(out.split('\n').every((l) => l.startsWith('   ')));
});

test('wrapAnsi: hard-splits unbreakable words longer than the width', () => {
  const out = wrapAnsi('aaa ' + 'b'.repeat(25), 10);
  const lines = out.split('\n');
  assert.equal(visible(lines[0]), 'aaa');
  for (const line of lines.slice(1)) {
    assert.ok(visible(line).length <= 10, `line too long: ${JSON.stringify(line)}`);
  }
  assert.equal(visible(lines.join('')).length, 28);
});

test('wrapAnsi: hardSplit preserves ANSI colors across chunk boundaries', () => {
  const out = wrapAnsi('\u001b[1m' + 'a'.repeat(30) + '\u001b[0m', 10);
  const lines = out.split('\n');
  assert.equal(lines.length, 3);
  assert.ok(lines.every((l) => l.startsWith('\u001b[1m') && l.endsWith('\u001b[0m')));
  assert.equal(visible(lines.join('')).length, 30);
});

test('wrapAnsi: hardSplit keeps OSC links active across chunks', () => {
  const out = wrapAnsi('\u001b]8;;httpsx\u0007' + 'a'.repeat(30) + '\u001b]8;;\u0007', 10);
  const lines = out.split('\n');
  assert.equal(lines.length, 3);
  assert.ok(lines.every((l) => l.startsWith('\u001b]8;;httpsx\u0007') && l.endsWith('\u001b]8;;\u0007')));
  assert.equal(visible(lines.join('')).length, 30);
});

test('truncateAnsi: ANSI colors are preserved and reset at the cut', () => {
  const out = truncateAnsi('\u001b[31m' + 'x'.repeat(50) + '\u001b[0m', 10);
  assert.equal(visible(out).length, 11);
  assert.ok(out.includes('\u001b[31m'));
  assert.ok(out.endsWith('\u001b[0m'));
  assert.ok(out.includes('\u2026'));
});

test('truncateAnsi: reset code clears the style stack', () => {
  const out = truncateAnsi('\u001b[0m' + 'z'.repeat(50), 10);
  assert.equal(visible(out).length, 11);
  assert.ok(!out.includes('\u001b[0m\u001b[0m'));
});

test('truncateAnsi: OSC links are closed at the cut', () => {
  const out = truncateAnsi('\u001b]8;;https://x\u0007' + 'y'.repeat(50) + '\u001b]8;;\u0007', 10);
  assert.equal(visible(out).length, 11);
  assert.ok(out.endsWith('\u001b]8;;\u0007'));
});
