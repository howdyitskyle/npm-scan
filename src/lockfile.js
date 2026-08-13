import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';

export function detectFormat(filePath) {
  const base = basename(filePath);
  if (base === 'package-lock.json') return 'package-lock';
  if (base === 'yarn.lock') return 'yarn';
  if (base === 'pnpm-lock.yaml' || base === 'pnpm-lock.yml') return 'pnpm';
  if (base === 'bun.lock') return 'bun';
  if (base === 'bun.lockb') return 'bun-binary';
  return null;
}

function toArr(version) {
  return String(version)
    .split('.')
    .map((part) => {
      const m = part.match(/^\d+/);
      return m ? Number(m[0]) : 0;
    });
}

export function compareVersions(a, b) {
  if (!a || !b) return 0;
  const [aa, bb] = [toArr(a), toArr(b)];
  const len = Math.max(aa.length, bb.length);
  for (let i = 0; i < len; i++) {
    const diff = (aa[i] || 0) - (bb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

export function parseSemver(version) {
  const m = String(version).match(/^v?(\d+)\.(\d+)\.(\d+)/);
  return m ? `${m[1]}.${m[2]}.${m[3]}` : null;
}

function stripSuffix(target) {
  return String(target).replace(/\+[^+]*$/, '').replace(/-[^-]*$/, '');
}

function rangeParts(target) {
  const t = stripSuffix(target);
  const m = String(t).match(/^v?(\d+)(?:\.([xX*]|\d+))?(?:\.([xX*]|\d+))?$/);
  if (!m) return null;
  const isX = (v) => v === undefined || v === 'x' || v === 'X' || v === '*';
  return {
    major: Number(m[1]),
    minor: isX(m[2]) ? 'x' : Number(m[2]),
    patch: isX(m[3]) ? 'x' : Number(m[3]),
  };
}

export function satisfies(range, version) {
  const r = String(range).trim();
  if (!r || r === '*' || r === 'latest') return true;
  const v = parseSemver(version);
  if (!v) return false;
  if (r.includes('||')) return r.split('||').some((p) => satisfies(p, version));
  const ands = r.split(/\s+/).filter(Boolean);
  if (ands.length > 1) return ands.every((p) => satisfies(p, version));

  const cmp = ands[0].match(/^(\^|~|>=|<=|>|<)?(.*)$/);
  const op = cmp[1] || '';
  const target = cmp[2].trim();
  const base = rangeParts(target);
  if (!base) return false;

  const lo = `${base.major}.${base.minor === 'x' ? 0 : base.minor}.${base.patch === 'x' ? 0 : base.patch}`;
  const majorOnly = base.minor === 'x';
  const minorOnly = !majorOnly && base.patch === 'x';
  const tildeHi = majorOnly ? `${base.major + 1}.0.0` : `${base.major}.${base.minor + 1}.0`;
  const caretHi =
    majorOnly || base.major > 0
      ? `${base.major + 1}.0.0`
      : base.minor > 0
        ? `0.${base.minor + 1}.0`
        : `0.0.${base.patch + 1}`;

  if (op === '^') return compareVersions(v, lo) >= 0 && compareVersions(v, caretHi) < 0;
  if (op === '~') return compareVersions(v, lo) >= 0 && compareVersions(v, tildeHi) < 0;
  if (op === '>=') return compareVersions(v, lo) >= 0;
  if (op === '<=') return compareVersions(v, lo) <= 0;
  if (op === '>') return compareVersions(v, lo) > 0;
  if (op === '<') return compareVersions(v, lo) < 0;
  if (majorOnly || minorOnly) return compareVersions(v, lo) >= 0 && compareVersions(v, tildeHi) < 0;
  return compareVersions(v, lo) === 0;
}

function resolveDep(name, range, pkgs) {
  const candidates = pkgs.filter((p) => p.name === name);
  if (candidates.length === 0) return null;
  const exact = candidates.find((p) => p.version === range);
  if (exact) return exact;
  return candidates.find((p) => satisfies(range, p.version)) || null;
}

function buildGraph(entries) {
  const pkgs = entries.map((e) => ({ name: e.name, version: e.version }));
  const dependents = new Map();
  for (const e of entries) {
    for (const [depName, range] of Object.entries(e.deps || {})) {
      const resolved = resolveDep(depName, range, pkgs);
      if (!resolved) continue;
      const key = `${resolved.name}@${resolved.version}`;
      let set = dependents.get(key);
      if (!set) {
        set = new Set();
        dependents.set(key, set);
      }
      set.add(e.name);
    }
  }
  return dependents;
}

function parsePackageLock(json) {
  const set = new Set();
  const list = [];
  const entries = [];
  const add = (name, version, key, deps) => {
    if (!name || !version) return;
    const k = `${name}@${version}`;
    if (!set.has(k)) {
      set.add(k);
      list.push({ name, version, key });
      entries.push({ key, name, version, deps: deps || {} });
    }
  };

  const ver = json.lockfileVersion;
  const versionLabel = ver !== undefined ? ver : 1;
  let directNames = new Set();

  if (json.packages && (ver === undefined || ver >= 2)) {
    const rootDeps = json.packages['']?.dependencies || {};
    directNames = new Set(Object.keys(rootDeps));
    for (const [key, entry] of Object.entries(json.packages)) {
      if (!key || key === '') continue;
      if (!entry || typeof entry !== 'object') continue;
      if (entry.link) continue;
      if (!entry.version) continue;
      let name = entry.name;
      if (!name) {
        const at = key.lastIndexOf('node_modules/');
        name = at === -1 ? key : key.slice(at + 'node_modules/'.length);
      }
      add(name, entry.version, key, entry.dependencies);
    }
  }
  if (json.dependencies && (ver === undefined || ver < 2)) {
    const root = Object.keys(json.dependencies);
    directNames = new Set([...directNames, ...root]);
    const walk = (deps) => {
      for (const [name, entry] of Object.entries(deps)) {
        if (!entry || typeof entry !== 'object') continue;
        if (entry.version) {
          const normalized = {};
          for (const [depName, dep] of Object.entries(entry.dependencies || {})) {
            normalized[depName] = typeof dep === 'string' ? dep : dep?.version;
          }
          add(name, entry.version, `node_modules/${name}`, normalized);
        }
        if (entry.dependencies) walk(entry.dependencies);
      }
    };
    walk(json.dependencies);
  }

  const dependents = buildGraph(entries);
  return {
    format: 'package-lock',
    version: versionLabel,
    list,
    graph: { directNames, dependents },
    warnings: [],
  };
}

function packageNameFromSelector(selector) {
  let s = selector.trim().replace(/^"/, '').replace(/"$/, '').replace(/,$/, '');
  s = s.replace(/^npm:/, '').replace(/^file:/, '').replace(/^github:/, '').replace(/^https?:\/\//, '');
  const at = s.lastIndexOf('@');
  if (at <= 0) return null;
  return s.slice(0, at);
}

function parseYarnLock(text) {
  const warnings = [];
  const set = new Set();
  const list = [];

  if (text.includes('__metadata:') || /yarn lockfile v[23]/i.test(text)) {
    warnings.push(
      'yarn.lock v2/v3 (YAML) is not supported; run `yarn import` to regenerate a v1 lockfile and re-scan.'
    );
    return { format: 'yarn', version: null, list, graph: null, warnings };
  }

  const lines = text.split('\n');
  const entries = [];
  let current = null;
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (/^\S/.test(line)) {
      if (/^\S.*:$/.test(line)) {
        current = { keys: [], version: null };
        const keyLine = line.replace(/:\s*$/, '');
        for (const part of keyLine.split(',')) current.keys.push(part.trim());
        entries.push(current);
      }
    } else if (current) {
      const m = line.match(/^ {2}([A-Za-z]+)\s+"(.*)"\s*$/);
      if (m && m[1] === 'version') current.version = m[2];
    }
  }

  for (const e of entries) {
    if (!e.version || e.keys.length === 0) continue;
    const name = packageNameFromSelector(e.keys[0]);
    if (!name) continue;
    const key = `${name}@${e.version}`;
    if (!set.has(key)) {
      set.add(key);
      list.push({ name, version: e.version });
    }
  }
  return { format: 'yarn', version: 1, list, graph: null, warnings };
}

function splitPackageKey(key) {
  let k = key;
  const paren = k.indexOf('(');
  if (paren > 0) k = k.slice(0, paren);
  const at = k.lastIndexOf('@');
  if (at <= 0) return null;
  const name = k.slice(0, at);
  let version = k.slice(at + 1);
  if (version.startsWith('npm:')) version = version.slice('npm:'.length);
  return /^\d/.test(version) || /^v\d/.test(version) ? { name, version } : null;
}

function stripJsonc(text) {
  let out = '';
  let inStr = false;
  let esc = false;
  let inLine = false;
  let inBlock = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];
    if (inLine) {
      if (c === '\n') {
        inLine = false;
        out += c;
      }
      continue;
    }
    if (inBlock) {
      if (c === '*' && n === '/') {
        inBlock = false;
        i++;
      }
      continue;
    }
    if (inStr) {
      out += c;
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
      continue;
    }
    if (c === '/' && n === '/') {
      inLine = true;
      i++;
      continue;
    }
    if (c === '/' && n === '*') {
      inBlock = true;
      i++;
      continue;
    }
    out += c;
  }
  return out.replace(/,\s*([}\]])/g, '$1');
}

function parseBunLock(text) {
  const warnings = [];
  const seen = new Set();
  const set = new Set();
  const list = [];
  const entries = [];
  let json;
  try {
    json = JSON.parse(stripJsonc(text));
  } catch {
    throw new Error('bun.lock is not valid JSON (JSONC)');
  }
  const packages = json && typeof json.packages === 'object' ? json.packages : {};
  for (const [key, raw] of Object.entries(packages)) {
    if (!raw) continue;
    const id = Array.isArray(raw) ? String(raw[0] ?? '') : typeof raw === 'object' && raw.id ? String(raw.id) : key;
    const at = id.lastIndexOf('@');
    if (at <= 0) continue;
    const name = id.slice(0, at);
    let version = id.slice(at + 1);
    if (version.startsWith('npm:')) version = version.slice('npm:'.length);
    if (!parseSemver(version)) {
      const msg = `bun.lock: skipping non-semver package ${id} (git/path/alias dependency)`;
      if (!seen.has(msg)) {
        seen.add(msg);
        warnings.push(msg);
      }
      continue;
    }
    const entryKey = `${name}@${version}`;
    if (!set.has(entryKey)) {
      set.add(entryKey);
      list.push({ name, version });
      entries.push({ key: entryKey, name, version, deps: {} });
    }
  }

  const directNames = new Set();
  const workspaces = json && typeof json.workspaces === 'object' ? json.workspaces : {};
  for (const ws of Object.values(workspaces)) {
    if (!ws || typeof ws !== 'object') continue;
    for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      const deps = ws[kind];
      if (!deps || typeof deps !== 'object') continue;
      for (const depName of Object.keys(deps)) directNames.add(depName);
    }
  }

  const dependents = buildGraph(entries);
  return { format: 'bun', version: json.lockfileVersion, list, graph: { directNames, dependents }, warnings };
}

function parsePnpmLock(text) {
  const warnings = [];
  const set = new Set();
  const list = [];

  let inPackages = false;
  const isPkgKey = /^ {2}[^ ].*:$/;

  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim()) continue;
    if (!inPackages) {
      if (/^packages:$/.test(line)) inPackages = true;
      continue;
    }
    if (/^\S/.test(line)) {
      if (/^snapshots:/.test(line)) break;
      continue;
    }
    if (isPkgKey.test(line)) {
      const key = line.trim().replace(/:$/, '').replace(/^['"]/, '').replace(/['"]$/, '');
      const parsed = splitPackageKey(key);
      if (!parsed) continue;
      const entryKey = `${parsed.name}@${parsed.version}`;
      if (!set.has(entryKey)) {
        set.add(entryKey);
        list.push({ name: parsed.name, version: parsed.version });
      }
    }
  }
  return { format: 'pnpm', version: null, list, graph: null, warnings };
}

export function parseLockFile(text, format) {
  switch (format) {
    case 'package-lock':
      return parsePackageLock(JSON.parse(text));
    case 'yarn':
      return parseYarnLock(text);
    case 'pnpm':
      return parsePnpmLock(text);
    case 'bun':
      return parseBunLock(text);
    case 'bun-binary':
      throw new Error(
        'binary bun.lockb is not supported; run `bun install --save-text-lockfile` to generate a text bun.lock and re-scan.'
      );
    default:
      throw new Error(`Unsupported lock file format: ${format}`);
  }
}

export async function loadLockfile(filePath) {
  const text = await readFile(filePath, 'utf8');
  const format = detectFormat(filePath);
  if (format) return parseLockFile(text, format);
  try {
    return parseLockFile(text, 'package-lock');
  } catch {
    const head = text.slice(0, 1024);
    if (/__metadata:|^# THIS IS AN AUTOGENERATED FILE/m.test(head)) return parseLockFile(text, 'yarn');
    if (/^lockfile-?version:/m.test(head)) return parseLockFile(text, 'pnpm');
    throw new Error(`Unrecognized lock file format for ${filePath}`);
  }
}
