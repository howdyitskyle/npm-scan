import { createHash } from 'node:crypto';
import { readFile, stat, writeFile } from 'node:fs/promises';
import { VERSION } from './version.js';

export function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

export function padEnd(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

export function truncate(s, n) {
  s = String(s);
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + '\u2026';
}

const ANSI = /^\u001b\[([0-9;]*)m/;
const OSC = /^\u001b\][^\u0007\u001b]*\u0007/;
const isLinkStart = (o) => o.startsWith('\u001b]8;;') && o !== '\u001b]8;;\u0007';

function visibleLength(s) {
  return String(s).replace(/\u001b\[[0-9;]*m|\u001b\][^\u0007\u001b]*\u0007/g, '').length;
}

export function truncateAnsi(s, n) {
  const stack = [];
  let openLinks = 0;
  let out = '';
  let count = 0;
  let i = 0;
  while (i < s.length && count < n) {
    const ch = s[i];
    if (ch === '\u001b') {
      const m = ANSI.exec(s.slice(i));
      if (m) {
        out += m[0];
        i += m[0].length;
        if (m[1] === '0') stack.length = 0;
        else stack.push(m[1]);
        continue;
      }
      const o = OSC.exec(s.slice(i));
      if (o) {
        out += o[0];
        i += o[0].length;
        if (isLinkStart(o[0])) openLinks++;
        continue;
      }
    }
    out += ch;
    count++;
    i++;
  }
  out += '\u2026';
  for (let k = 0; k < openLinks; k++) out += '\u001b]8;;\u0007';
  if (stack.length) out += '\u001b[0m';
  return out;
}

const isUrl = (w) => w.includes('://');

export function wrapAnsi(text, width) {
  text = String(text);
  if (visibleLength(text) <= width) return text;
  const indentMatch = /^ +/.exec(text);
  const indent = indentMatch ? indentMatch[0].length : 0;
  const avail = Math.max(1, width - indent);
  const words = text.slice(indent).split(' ');
  const out = [];
  let cur = '';
  let curLen = 0;
  const flush = () => {
    if (curLen > 0) {
      out.push(' '.repeat(indent) + cur);
      cur = '';
      curLen = 0;
    }
  };
  for (const word of words) {
    const wv = visibleLength(word);
    if (wv > avail) {
      if (isUrl(word)) {
        if (curLen > 0) {
          cur += ' ' + truncateAnsi(word, avail - curLen);
          curLen = avail;
        } else {
          out.push(' '.repeat(indent) + truncateAnsi(word, avail));
        }
      } else {
        flush();
        for (const c of hardSplit(word, avail)) out.push(' '.repeat(indent) + c);
      }
      continue;
    }
    if (isUrl(word) && curLen > 0 && wv > avail - curLen) {
      flush();
    }
    const add = curLen === 0 ? wv : curLen + 1 + wv;
    if (add <= avail) {
      cur = curLen === 0 ? word : cur + ' ' + word;
      curLen = add;
    } else {
      flush();
      cur = word;
      curLen = wv;
    }
  }
  flush();
  return out.join('\n');
}

function hardSplit(word, width) {
  const chunks = [];
  let chunk = '';
  let count = 0;
  const stack = [];
  const links = [];
  let i = 0;
  while (i < word.length) {
    const ch = word[i];
    if (ch === '\u001b') {
      const m = ANSI.exec(word.slice(i));
      if (m) {
        chunk += m[0];
        i += m[0].length;
        if (m[1] === '0') stack.length = 0;
        else stack.push(m[1]);
        continue;
      }
      const o = OSC.exec(word.slice(i));
      if (o) {
        chunk += o[0];
        i += o[0].length;
        if (isLinkStart(o[0])) links.push(o[0].slice(5, -1));
        continue;
      }
    }
    chunk += ch;
    count++;
    i++;
    if (count === width) {
      for (let k = 0; k < links.length; k++) chunk += '\u001b]8;;\u0007';
      if (stack.length) chunk += '\u001b[0m';
      chunks.push(chunk);
      chunk = links.map((u) => `\u001b]8;;${u}\u0007`).join('') + stack.map((c) => `\u001b[${c}m`).join('');
      count = 0;
    }
  }
  if (count > 0) {
    for (let k = 0; k < links.length; k++) chunk += '\u001b]8;;\u0007';
    if (stack.length) chunk += '\u001b[0m';
    chunks.push(chunk);
  }
  return chunks;
}

export function fmt(n) {
  return Number.isFinite(n) ? n.toLocaleString('en-US') : String(n);
}

export function plural(n, word) {
  if (word === 'entry') return `${n} ${n === 1 ? 'entry' : 'entries'}`;
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

export function sha256(text) {
  return createHash('sha256').update(String(text)).digest('hex');
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      while (next < items.length) {
        const i = next++;
        results[i] = await fn(items[i], i);
      }
    }
  );
  await Promise.all(workers);
  return results;
}

let _fetch = globalThis.fetch;
export function setFetch(fn) {
  _fetch = fn;
}

export async function fetchWithRetry(
  url,
  { method = 'GET', body, headers = {}, retries = 3, timeoutMs = 30000, backoffMs = 1000, verbose = false, log = console.error } = {}
) {
  let lastErr = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await _fetch(url, {
        method,
        body,
        headers: { 'user-agent': `npm-scan/${VERSION}`, accept: '*/*', ...headers },
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;
      const delay = backoffMs * 2 ** attempt;
      if (verbose) log(`[retry] ${url}: ${err.message}; retrying in ${delay}ms (${attempt + 1}/${retries})`);
      await sleep(delay);
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastErr;
}

export async function fetchCached(
  url,
  cachePath,
  ttlMs,
  label,
  { verbose = false, retries, timeoutMs, backoffMs, log = console.error, onEvent } = {}
) {
  let cached = null;
  try {
    const st = await stat(cachePath);
    cached = st;
    const ageMs = Date.now() - st.mtimeMs;
    if (ttlMs > 0 && ageMs < ttlMs) {
      if (verbose) log(`[cache] ${label}: using cached copy`);
      onEvent?.('cached');
      return { text: await readFile(cachePath, 'utf8'), fromCache: true, stale: false, mtimeMs: st.mtimeMs };
    }
  } catch {}
  if (verbose) log(`[fetch] ${label}: downloading`);
  onEvent?.('downloading');
  try {
    const res = await fetchWithRetry(url, { retries, timeoutMs, backoffMs, verbose, log });
    const text = await res.text();
    try {
      await writeFile(cachePath, text);
    } catch {}
    let mtimeMs = Date.now();
    try {
      mtimeMs = (await stat(cachePath)).mtimeMs;
    } catch {}
    return { text, fromCache: false, stale: false, mtimeMs };
  } catch (err) {
    if (cached) {
      if (verbose) log(`[cache] ${label}: fetch failed (${err.message}); serving stale cached copy`);
      onEvent?.('stale');
      return {
        text: await readFile(cachePath, 'utf8'),
        fromCache: true,
        stale: true,
        mtimeMs: cached.mtimeMs,
      };
    }
    throw err;
  }
}
