import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { unzipSync, strFromU8 } from 'fflate';
import { fetchWithRetry } from './util.js';
import { satisfies } from './lockfile.js';

export const OSV_DB_FILE = 'osv-db.json';
export const OSV_DB_META_FILE = 'osv-db-meta.json';
export const OSV_DB_URL = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip';

function malicious(adv) {
  return adv.id.startsWith('MAL-') || adv.database_specific?.type === 'MALICIOUS';
}

function compactRecord(adv) {
  return {
    id: adv.id,
    summary: adv.summary || '',
    details: adv.details || '',
    references: adv.references || [],
    severity: adv.severity || [],
    affected: adv.affected || [],
    aliases: adv.aliases || [],
    database_specific: adv.database_specific || {},
  };
}

export async function downloadOsvDb({ dir, url = OSV_DB_URL, log = console.error, retries = 2, timeoutMs = 120000, backoffMs = 2000 } = {}) {
  log(`[osv-db] downloading ${url}`);
  const res = await fetchWithRetry(url, { retries, timeoutMs, backoffMs, log });
  const buf = new Uint8Array(await res.arrayBuffer());
  let entries;
  try {
    entries = unzipSync(buf);
  } catch (e) {
    throw new Error(`cannot unzip OSV database: ${e.message}`, { cause: e });
  }
  const records = [];
  for (const [name, data] of Object.entries(entries)) {
    if (!name.endsWith('.json')) continue;
    let adv;
    try {
      adv = JSON.parse(strFromU8(data));
    } catch {
      continue;
    }
    if (!adv || !adv.id || !malicious(adv)) continue;
    records.push(compactRecord(adv));
  }
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, OSV_DB_FILE), JSON.stringify(records));
  await writeFile(
    join(dir, OSV_DB_META_FILE),
    JSON.stringify({ url, downloadedAt: new Date().toISOString(), count: records.length })
  );
  log(`[osv-db] kept ${records.length} malicious record(s) from the npm dump`);
  return { count: records.length, path: join(dir, OSV_DB_FILE) };
}

function rangeString(introduced, fixed, lastAffected) {
  let s = introduced !== null && introduced !== undefined ? `>=${introduced}` : '>=0';
  if (fixed !== null && fixed !== undefined) s += ` <${fixed}`;
  else if (lastAffected !== null && lastAffected !== undefined) s += ` <=${lastAffected}`;
  return s;
}

function rangesOf(adv) {
  const ranges = [];
  for (const aff of adv.affected || []) {
    if (aff.package && aff.package.ecosystem && aff.package.ecosystem !== 'npm') continue;
    for (const r of aff.ranges || []) {
      if (r.type && r.type !== 'SEMVER') continue;
      let introduced = null;
      let fixed = null;
      let lastAffected = null;
      for (const ev of r.events || []) {
        if (ev.introduced !== undefined) introduced = ev.introduced;
        if (ev.fixed !== undefined) fixed = ev.fixed;
        if (ev.last_affected !== undefined) lastAffected = ev.last_affected;
      }
      if (introduced !== null || fixed !== null || lastAffected !== null) {
        ranges.push(rangeString(introduced, fixed, lastAffected));
      }
    }
  }
  return ranges;
}

export async function loadOsvDb(dir) {
  let records;
  try {
    records = JSON.parse(await readFile(join(dir, OSV_DB_FILE), 'utf8'));
  } catch {
    return null;
  }
  const byId = new Map();
  const byPackage = new Map();
  for (const rec of records) {
    if (!rec || !rec.id) continue;
    byId.set(rec.id, rec);
    const ranges = rangesOf(rec);
    for (const aff of rec.affected || []) {
      if (aff.package && aff.package.ecosystem && aff.package.ecosystem !== 'npm') continue;
      const name = aff.package?.name;
      if (!name) continue;
      let list = byPackage.get(name);
      if (!list) {
        list = [];
        byPackage.set(name, list);
      }
      list.push({ id: rec.id, ranges });
    }
  }
  return { byId, byPackage };
}

export function queryLocalOsv(db, name, version) {
  const candidates = db.byPackage.get(name);
  if (!candidates) return [];
  const hits = new Set();
  for (const c of candidates) {
    if (c.ranges.some((r) => satisfies(r, version))) hits.add(c.id);
  }
  return [...hits];
}
