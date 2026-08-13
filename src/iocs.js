import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

export const IOCS_MAX_FILES = 200_000;
export const IOCS_SKIP_DIRS = new Set(['.git', '.hg', '.svn', 'bower_components']);

export async function walkInstalledPackages(roots, { warn = () => {}, maxFiles = IOCS_MAX_FILES } = {}) {
  const seen = new Map();
  let files = 0;
  const overLimit = () => {
    warn(`[iocs] file walk exceeded ${maxFiles} entries; returning partial results`);
    return true;
  };
  const record = (name, version, dir) => {
    if (!name || !version) return;
    const key = `${name}@${version}`;
    if (!seen.has(key)) seen.set(key, { name, version, path: dir });
  };
  const readManifest = async (dir) => {
    if (++files > maxFiles) return overLimit();
    try {
      const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8'));
      record(pkg.name, pkg.version, dir);
    } catch {}
    return false;
  };
  const scanNodeModules = async (dir) => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (e.name === '.pnpm') {
        let sub;
        try {
          sub = await readdir(join(dir, e.name), { withFileTypes: true });
        } catch {
          continue;
        }
        for (const s of sub) {
          if (!s.isDirectory()) continue;
          if (await scanPackage(join(dir, e.name, s.name))) return;
        }
      } else if (e.name.startsWith('.')) {
        continue;
      } else if (e.name.startsWith('@')) {
        let sub;
        try {
          sub = await readdir(join(dir, e.name), { withFileTypes: true });
        } catch {
          continue;
        }
        for (const s of sub) {
          if (!s.isDirectory() && !s.isSymbolicLink()) continue;
          if (await scanPackage(join(dir, e.name, s.name))) return;
        }
      } else if (await scanPackage(join(dir, e.name))) {
        return;
      }
    }
  };
  const scanPackage = async (pkgDir) => {
    if (await readManifest(pkgDir)) return true;
    await scanNodeModules(join(pkgDir, 'node_modules'));
    return false;
  };
  const stack = [...roots];
  const visited = new Set();
  while (stack.length > 0) {
    const dir = stack.pop();
    if (visited.has(dir)) continue;
    visited.add(dir);
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (++files > maxFiles) {
        overLimit();
        return [...seen.values()];
      }
      if (e.isFile() && e.name === 'package.json') {
        try {
          const pkg = JSON.parse(await readFile(join(dir, e.name), 'utf8'));
          record(pkg.name, pkg.version, dir);
        } catch {}
        continue;
      }
      if (!e.isDirectory()) continue;
      if (e.name === 'node_modules') {
        await scanNodeModules(join(dir, e.name));
        continue;
      }
      if (e.name.startsWith('.')) continue;
      if (IOCS_SKIP_DIRS.has(e.name)) continue;
      stack.push(join(dir, e.name));
    }
  }
  return [...seen.values()];
}
