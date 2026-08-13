import { readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { ttlFor } from './config.js';
import { SOURCES, SRC_IDS, IndicatorIndex } from './sources.js';
import { loadLockfile } from './lockfile.js';
import { chunk, fetchCached, mapLimit, sha256 } from './util.js';
import { parseIocCsv } from './csv.js';
import {
  OSV_QUERY_BATCH,
  OSV_TYPES_FILE,
  classifyOsvIds,
  enrichMatches,
  loadOsvCache,
  needsClassification,
  queryOsvBatch,
} from './osv.js';
import { walkInstalledPackages } from './iocs.js';
import { loadOsvDb, queryLocalOsv } from './osvdb.js';
import { ScanError } from './errors.js';
import { loadExcludeRules } from './exclude.js';
import { VERSION } from './version.js';

export async function runScan(opts, netOpts, { emit, log, warn, cwd, displayPath, lockPath, startedAt }) {
  const index = new IndicatorIndex();
  const sourceStats = [];
  const usedLabels = [];

  const activeCsv = new Set();
  let osvActive = !opts.noOsv;
  if (opts.sources && opts.sources !== 'all') {
    osvActive = false;
    const requested = opts.sources
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    for (const s of requested) {
      if (s === 'osv') {
        osvActive = !opts.noOsv;
        continue;
      }
      activeCsv.add(s);
    }
  } else {
    for (const s of SRC_IDS) if (s !== 'osv') activeCsv.add(s);
  }

  const sourceResults = await mapLimit([...activeCsv], 4, async (src) => {
    const def = SOURCES[src];
    emit?.({ phase: 'sources', id: src, label: def.label, status: 'start' });
    try {
      const fetched = await fetchCached(
        def.url,
        join(opts.cacheDir, def.cacheFile),
        ttlFor(opts, src),
        def.label,
        { ...netOpts, onEvent: (s) => emit?.({ phase: 'sources', id: src, status: s }) }
      );
      return { id: src, label: def.label, entries: parseIocCsv(fetched.text), ...fetched };
    } catch (e) {
      return { id: src, label: def.label, error: e.message };
    }
  });

  for (const result of sourceResults) {
    if (result.error) {
      warn(`[warn] ${result.label}: ${result.error}; skipping source`);
      emit?.({ phase: 'sources', id: result.id, status: 'error' });
      sourceStats.push({ id: result.id, label: result.label, entries: 0, skipped: true, error: result.error });
      continue;
    }
    usedLabels.push(result.label);
    for (const [name, ver] of result.entries) index.add(name, ver, result.label);
    emit?.({ phase: 'sources', id: result.id, status: 'done', entries: result.entries.length });
    sourceStats.push({
      id: result.id,
      label: result.label,
      entries: result.entries.length,
      fetchedAt: new Date(result.mtimeMs ?? Date.now()).toISOString(),
      sha256: sha256(result.text),
      skipped: false,
      stale: Boolean(result.stale),
    });
    if (result.stale) {
      warn(
        `[warn] ${result.label}: network fetch failed; using stale cached copy from ${new Date(result.mtimeMs).toISOString()}`
      );
    }
    if (opts.verbose) log(`[load] ${result.label}: ${result.entries.length} package@version entries`);
  }

  for (const csvArg of opts.csv) {
    const isUrl = /^https?:\/\//.test(csvArg);
    const label = `custom:${csvArg}`;
    emit?.({ phase: 'sources', id: `custom:${csvArg}`, label, status: 'start' });
    let text;
    let fetched = null;
    try {
      if (isUrl) {
        const cacheName = `custom-${Buffer.from(csvArg).toString('base64url').slice(0, 40)}.csv`;
        fetched = await fetchCached(
          csvArg,
          join(opts.cacheDir, cacheName),
          ttlFor(opts, 'custom'),
          label,
          { ...netOpts, onEvent: (s) => emit?.({ phase: 'sources', id: `custom:${csvArg}`, status: s }) }
        );
        text = fetched.text;
      } else {
        const path = isAbsolute(csvArg) ? csvArg : join(cwd, csvArg);
        text = readFileSync(path, 'utf8');
      }
    } catch (e) {
      emit?.({ phase: 'sources', id: `custom:${csvArg}`, status: 'error' });
      warn(`[warn] ${label}: ${e.message}; skipping source`);
      continue;
    }
    let entries;
    try {
      entries = parseIocCsv(text);
    } catch (e) {
      emit?.({ phase: 'sources', id: `custom:${csvArg}`, status: 'error' });
      warn(`[warn] ${label}: ${e.message}; skipping source`);
      continue;
    }
    usedLabels.push(label);
    for (const [name, ver] of entries) index.add(name, ver, label);
    emit?.({ phase: 'sources', id: `custom:${csvArg}`, status: 'done', entries: entries.length });
    if (fetched?.stale) {
      warn(`[warn] ${label}: network fetch failed; using stale cached copy from ${new Date(fetched.mtimeMs).toISOString()}`);
    }
    sourceStats.push({
      id: `custom:${csvArg}`,
      label,
      entries: entries.length,
      fetchedAt: fetched ? new Date(fetched.mtimeMs).toISOString() : undefined,
      sha256: fetched ? sha256(fetched.text) : undefined,
      skipped: false,
      stale: Boolean(fetched?.stale),
    });
    if (opts.verbose) log(`[load] ${label}: ${entries.length} package@version entries`);
  }

  let lock;
  try {
    lock = await loadLockfile(lockPath);
  } catch (e) {
    throw new ScanError(`Error: cannot read/parse ${displayPath}: ${e.message}`);
  }
  for (const w of lock.warnings || []) warn(`[warn] ${w}`);
  if (opts.verbose) log(`[scan] ${lock.list.length} unique package@version entries in ${displayPath} (${lock.format})`);

  let installed = [];
  if (opts.iocs) {
    const roots = (opts.iocsRoots || '')
      .split(',')
      .map((r) => r.trim())
      .filter(Boolean)
      .map((r) => (isAbsolute(r) ? r : join(cwd, r)));
    if (roots.length === 0) roots.push(cwd);
    installed = await walkInstalledPackages(roots, { warn });
    if (opts.verbose) log(`[iocs] found ${installed.length} installed package(s) across ${roots.length} root(s)`);
  }

  const osvPkgs = new Map();
  for (const p of lock.list) osvPkgs.set(`${p.name}@${p.version}`, p);
  for (const p of installed) {
    const key = `${p.name}@${p.version}`;
    if (!osvPkgs.has(key)) osvPkgs.set(key, p);
  }

  const osvMatches = new Map();
  let osvSkipped = false;
  let osvOfflineDb = null;
  if (opts.osvOffline) {
    usedLabels.push(SOURCES.osv.label);
    osvOfflineDb = await loadOsvDb(opts.cacheDir);
    if (!osvOfflineDb) {
      throw new ScanError(
        `Error: offline OSV database not found in ${opts.cacheDir}. Run --download-osv-db once first (one-time ~100-300 MB download).`
      );
    }
    for (const [key, p] of osvPkgs) {
      const ids = queryLocalOsv(osvOfflineDb, p.name, p.version);
      if (ids.length > 0) osvMatches.set(key, new Set(ids));
    }
    emit?.({ phase: 'osv-status', status: 'done' });
  } else if (osvActive) {
    const osvCache = await loadOsvCache(opts.cacheDir);
    const ghsaByPkg = new Map();
    try {
      usedLabels.push(SOURCES.osv.label);
      const queries = [...osvPkgs.values()].map((p) => ({
        package: { name: p.name, ecosystem: 'npm' },
        version: p.version,
      }));
      const batches = chunk(queries, OSV_QUERY_BATCH);
      let batchesDone = 0;
      await mapLimit(batches, 4, async (batch) => {
        const resp = await queryOsvBatch(batch, netOpts);
        const results = resp.results || [];
        for (let i = 0; i < results.length; i++) {
          const item = results[i];
          if (!item || !Array.isArray(item.vulns)) continue;
          const key = `${batch[i].package.name}@${batch[i].version}`;
          for (const v of item.vulns) {
            const id = v.id;
            if (id.startsWith('MAL-')) {
              let s = osvMatches.get(key);
              if (!s) {
                s = new Set();
                osvMatches.set(key, s);
              }
              s.add(id);
            } else if (id.startsWith('GHSA-')) {
              let s = ghsaByPkg.get(key);
              if (!s) {
                s = new Set();
                ghsaByPkg.set(key, s);
              }
              s.add(id);
              if (osvCache[id] === undefined) osvCache[id] = 'PENDING';
            }
          }
        }
        emit?.({ phase: 'osv-batch', done: ++batchesDone, total: batches.length });
        return null;
      });
      const ghsaIds = [...new Set([...ghsaByPkg.values()].flatMap((s) => [...s]))].filter((id) =>
        needsClassification(id, osvCache, ttlFor(opts, 'osv'))
      );
      await classifyOsvIds(ghsaIds, osvCache, {
        ...netOpts,
        ttlMs: ttlFor(opts, 'osv'),
        onProgress: (p) => emit?.({ phase: 'osv-classify', ...p }),
      });
      for (const [key, ids] of ghsaByPkg) {
        for (const id of ids) {
          if (osvCache[id]?.type !== 'MALICIOUS') continue;
          let s = osvMatches.get(key);
          if (!s) {
            s = new Set();
            osvMatches.set(key, s);
          }
          s.add(id);
        }
      }
      for (const k of Object.keys(osvCache)) if (osvCache[k] === 'PENDING') delete osvCache[k];
      try {
        await writeFile(join(opts.cacheDir, OSV_TYPES_FILE), JSON.stringify(osvCache));
      } catch {}
      emit?.({ phase: 'osv-status', status: 'done' });
    } catch (e) {
      osvSkipped = true;
      emit?.({ phase: 'osv-status', status: 'skipped' });
      warn(`[warn] OSV unavailable: ${e.message}; skipping OSV check`);
    }
  }

  for (const [key, p] of osvPkgs) {
    const ids = osvMatches.get(key);
    if (ids) for (const id of ids) index.add(p.name, p.version, null, id);
  }

  const hasGraph = lock.graph !== null;
  const graph = hasGraph
    ? lock.graph
    : { directNames: new Set(), dependents: new Map() };
  let matches = [];
  for (const p of lock.list) {
    const rawEntry = index.lookup(p.name, p.version);
    if (!rawEntry) continue;
    const key = `${p.name}@${p.version}`;
    matches.push({
      name: p.name,
      version: p.version,
      entry: { sources: [...rawEntry.sources], osv: [...rawEntry.osv] },
      direct: hasGraph ? graph.directNames.has(p.name) : undefined,
      via: hasGraph ? [...(graph.dependents.get(key) || [])].sort() : undefined,
    });
  }
  matches.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  let excludedCount = 0;
  let excludeRules = null;
  if (opts.excludePkg) {
    excludeRules = await loadExcludeRules(opts.excludePkg, cwd);
    const before = matches.length;
    matches = matches.filter((m) => !excludeRules.excludes(m.name, m.version));
    excludedCount = before - matches.length;
    if (opts.verbose) log(`[exclude] dropped ${excludedCount} match(es) via ${excludeRules.path}`);
  }

  const iocMatches = [];
  const iocScanned = installed.length;
  if (opts.iocs) {
    const seen = new Set(matches.map((m) => `${m.name}@${m.version}`));
    for (const p of installed) {
      const rawEntry = index.lookup(p.name, p.version);
      if (!rawEntry) continue;
      if (excludeRules?.excludes(p.name, p.version)) {
        excludedCount++;
        continue;
      }
      const key = `${p.name}@${p.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      iocMatches.push({
        name: p.name,
        version: p.version,
        path: p.path,
        entry: { sources: [...rawEntry.sources], osv: [...rawEntry.osv] },
        direct: undefined,
        via: undefined,
        advisories: [],
        sourceRefs: [],
      });
    }
    if (opts.verbose) log(`[iocs] ${iocMatches.length} installed package(s) flagged`);
  }

  const allMatches = [...matches, ...iocMatches];
  if (allMatches.length > 0) {
    await enrichMatches(allMatches, {
      cacheDir: opts.cacheDir,
      ttlMs: ttlFor(opts, 'osv'),
      preloaded: osvOfflineDb ? Object.fromEntries(osvOfflineDb.byId) : null,
      ...netOpts,
      onProgress: (p) => emit?.({ phase: 'osv-enrich', ...p }),
    });
  }

  const report = {
    schemaVersion: '1.0.0',
    tool: { name: 'npm-scan', version: VERSION, informationUri: 'https://github.com/kyle/npm-scan' },
    generatedAt: new Date().toISOString(),
    summary: {
      lockfile: displayPath,
      lockfileFormat: lock.format,
      scanned: lock.list.length,
      iocScanned,
      indicators: index.size,
      sources: usedLabels.length,
      found: matches.length + iocMatches.length,
      excluded: excludedCount,
      durationMs: Date.now() - startedAt,
      osvSkipped: Boolean(osvSkipped),
      staleSources: sourceStats.filter((s) => s.stale).length,
      warnings: lock.warnings || [],
    },
    sources: sourceStats,
    matches,
    iocMatches,
  };

  emit?.({
    phase: 'done',
    found: matches.length + iocMatches.length,
    scanned: lock.list.length,
    durationMs: Date.now() - startedAt,
  });
  return report;
}
