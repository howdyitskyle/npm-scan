import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { ScanError } from './errors.js';

const NAME_RE = /^@?[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9._-]+)?$/;

export async function loadExcludeRules(path, cwd) {
  const abs = isAbsolute(path) ? path : join(cwd, path);
  let text;
  try {
    text = await readFile(abs, 'utf8');
  } catch (e) {
    throw new ScanError(`Error: cannot read exclude list ${path}: ${e.message}`);
  }
  const names = new Set();
  const versionsByPkg = new Map();
  let lineNo = 0;
  for (const raw of text.split(/\r?\n/)) {
    lineNo++;
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const at = line.lastIndexOf('@');
    if (at > 0) {
      const name = line.slice(0, at).trim();
      const version = line.slice(at + 1).trim().replace(/^v/, '');
      if (!NAME_RE.test(name) || !/^\d[\w.+-]*$/.test(version)) {
        throw new ScanError(
          `Error: malformed exclude line ${lineNo} in ${path}: "${line}" (expected pkg or pkg@version)`
        );
      }
      if (!versionsByPkg.has(name)) versionsByPkg.set(name, new Set());
      versionsByPkg.get(name).add(version);
    } else {
      if (!NAME_RE.test(line)) {
        throw new ScanError(`Error: malformed exclude line ${lineNo} in ${path}: "${line}" (expected pkg or pkg@version)`);
      }
      names.add(line);
    }
  }
  return {
    path,
    excludes(name, version) {
      if (names.has(name)) return true;
      const versions = versionsByPkg.get(name);
      if (!versions) return false;
      return versions.has(version) || versions.has(version.replace(/^v/, ''));
    },
  };
}
