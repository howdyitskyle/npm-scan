import { readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chunk, fetchWithRetry } from './util.js';
import { refForLabel } from './sources.js';

export const OSV_QUERY_BATCH = 1000;
export const OSV_CONCURRENCY = 8;
export const OSV_TYPES_FILE = 'osv-types.json';
const OSV_ADVISORIES_FILE = 'osv-advisories.json';
const OSV_API = 'https://api.osv.dev/v1';

export function needsClassification(id, cache, ttlMs = 0) {
  const v = cache[id];
  if (v === undefined || v === 'PENDING') return true;
  if (typeof v === 'string') return true;
  return typeof v.fetchedAt !== 'number' || Date.now() - v.fetchedAt >= ttlMs;
}

export async function loadOsvCache(dir) {
  const file = join(dir, OSV_TYPES_FILE);
  let mtimeMs = 0;
  try {
    mtimeMs = (await stat(file)).mtimeMs;
  } catch {}
  try {
    const json = JSON.parse(await readFile(file, 'utf8'));
    for (const k of Object.keys(json)) {
      const v = json[k];
      if (v === 'PENDING') delete json[k];
      else if (typeof v === 'string') {
        json[k] = { type: v === 'MALICIOUS' ? 'MALICIOUS' : 'OTHER', fetchedAt: mtimeMs };
      } else if (v && typeof v === 'object' && typeof v.type === 'string') {
        if (typeof v.fetchedAt !== 'number') v.fetchedAt = mtimeMs;
      } else {
        delete json[k];
      }
    }
    return json;
  } catch {
    return {};
  }
}

export async function queryOsvBatch(queries, netOpts = {}) {
  const res = await fetchWithRetry(`${OSV_API}/querybatch`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ queries }),
    ...netOpts,
  });
  return res.json();
}

export async function classifyOsvIds(ids, cache, { ttlMs = 0, verbose = false, log = console.error, onProgress, ...netOpts } = {}) {
  const pending = ids.filter((id) => needsClassification(id, cache, ttlMs));
  if (pending.length === 0) return;
  if (verbose) log(`[osv] classifying ${pending.length} GHSA advisory(ies)`);
  let failed = 0;
  let done = 0;
  const total = chunk(pending, OSV_CONCURRENCY).length;
  for (const batch of chunk(pending, OSV_CONCURRENCY)) {
    await Promise.all(
      batch.map(async (id) => {
        try {
          const res = await fetchWithRetry(`${OSV_API}/vulns/${id}`, { ...netOpts, verbose, log });
          const json = await res.json();
          cache[id] = {
            type: json.database_specific?.type === 'MALICIOUS' ? 'MALICIOUS' : 'OTHER',
            fetchedAt: Date.now(),
          };
        } catch {
          failed++;
          cache[id] = { type: 'OTHER', fetchedAt: Date.now() };
        }
      })
    );
    onProgress?.({ done: ++done, total });
  }
  if (failed > 0 && verbose) log(`[osv] ${failed} GHSA classification(s) failed; retried next scan`);
}

function severityOf(adv) {
  const sev = adv.severity || [];
  for (const s of sev) {
    if (s.type === 'CVSS_V3' || (s.type && s.type.startsWith('CVSS_'))) {
      return { type: s.type, score: s.score };
    }
  }
  const ds = adv.database_specific || {};
  if (typeof ds.severity === 'string') return { type: 'GHSA', severity: ds.severity };
  const cvss = ds.cvss;
  if (Array.isArray(cvss)) {
    const v3 = cvss.find((x) => x.vectorString && x.vectorString.includes('CVSS:3'));
    if (v3) return { type: 'CVSS_V3', vector: v3.vectorString };
  } else if (cvss && typeof cvss === 'object' && cvss.vectorString) {
    return { type: 'CVSS_V3', vector: cvss.vectorString };
  }
  return null;
}

function affectedOf(adv) {
  const ranges = [];
  let patched = null;
  for (const a of adv.affected || []) {
    if (a.package && a.package.ecosystem && a.package.ecosystem !== 'npm') continue;
    for (const r of a.ranges || []) {
      let introduced = null;
      let fixed = null;
      let lastAffected = null;
      for (const ev of r.events || []) {
        if (ev.introduced) introduced = ev.introduced;
        if (ev.fixed) fixed = ev.fixed;
        if (ev.last_affected) lastAffected = ev.last_affected;
      }
      if (introduced !== null || fixed !== null || lastAffected !== null) {
        ranges.push({ type: r.type || 'SEMVER', introduced, fixed, lastAffected });
        if (fixed && (!patched || fixed < patched)) patched = fixed;
      }
    }
  }
  return { ranges, patched };
}

function linksOf(id, a) {
  const links = [];
  const ghsaUrl = a.database_specific?.url;
  if (ghsaUrl) links.push(ghsaUrl);
  links.push(`${OSV_API}/vulns/${id}`);
  for (const r of a.references || []) {
    if (r.url && !links.includes(r.url)) links.push(r.url);
  }
  return links.slice(0, 4);
}

export async function enrichMatches(matches, { cacheDir, ttlMs, verbose = false, log = console.error, onProgress, preloaded = null, ...netOpts } = {}) {
  for (const m of matches) {
    m.advisories = [];
    m.sourceRefs = [...new Set([...m.entry.sources].map(refForLabel).filter(Boolean))].slice(0, 2);
  }
  const ids = [...new Set(matches.flatMap((m) => [...m.entry.osv]))];
  if (ids.length === 0) return;

  const cachePath = join(cacheDir, OSV_ADVISORIES_FILE);
  let cache = preloaded || {};
  if (!preloaded) {
    try {
      cache = JSON.parse(await readFile(cachePath, 'utf8'));
    } catch {}
  }

  const need = ids.filter((id) => !cache[id] || Date.now() - cache[id].fetchedAt >= ttlMs);
  let failed = 0;
  if (need.length > 0) {
    if (verbose) log(`[osv] fetching ${need.length} advisory detail(s)`);
    let done = 0;
    const total = chunk(need, OSV_CONCURRENCY).length;
    for (const batch of chunk(need, OSV_CONCURRENCY)) {
      await Promise.all(
        batch.map(async (id) => {
          try {
            const res = await fetchWithRetry(`${OSV_API}/vulns/${id}`, { ...netOpts, log });
            const j = await res.json();
            cache[id] = {
              fetchedAt: Date.now(),
              summary: j.summary || '',
              details: j.details || '',
              references: j.references || [],
              severity: j.severity || [],
              affected: j.affected || [],
              aliases: j.aliases || [],
              database_specific: j.database_specific || {},
            };
          } catch {
            failed++;
            const prev = cache[id];
            cache[id] =
              prev && typeof prev.fetchedAt === 'number'
                ? { ...prev, fetchedAt: Date.now() }
                : { fetchedAt: Date.now() };
          }
        })
      );
      onProgress?.({ done: ++done, total });
    }
    if (!preloaded) {
      try {
        await writeFile(cachePath, JSON.stringify(cache));
      } catch {}
    }
  }
  if (failed > 0 && verbose) {
    log(`[osv] ${failed} advisory detail fetch(es) failed; using cached copies`);
  }

  for (const m of matches) {
    m.advisories = [...m.entry.osv].sort().map((id) => {
      const a = cache[id] || {};
      const affected = affectedOf(a);
      return {
        id,
        summary: a.summary || '',
        details: a.details || '',
        links: linksOf(id, a),
        severity: severityOf(a),
        affected: affected.ranges,
        patched: affected.patched,
        aliases: a.aliases || [],
      };
    });
  }
}
