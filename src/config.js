import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';

export const FORMATS = ['pretty', 'compact', 'markdown', 'json', 'sarif', 'gh-annotations'];
export const SOURCE_IDS = ['keyv', 'shai-hulud', 'axios', 'teampcp', 'osv'];

export function defaultOptions() {
  return {
    lockfile: null,
    sources: null,
    csv: [],
    noOsv: false,
    verbose: false,
    ttl: 24,
    cacheDir: join(homedir(), '.cache', 'npm-scan'),
    format: 'pretty',
    config: '.npmscanrc.json',
    retries: 3,
    timeoutMs: 30000,
    backoffMs: 1000,
    noTui: false,
    excludePkg: null,
    iocs: false,
    iocsRoots: null,
    osvOffline: false,
    downloadOsvDb: false,
    help: false,
    version: false,
  };
}

const CONFIG_KEY_MAP = {
  lockfile: 'lockfile',
  sources: 'sources',
  csv: 'csv',
  'no-osv': 'noOsv',
  noOsv: 'noOsv',
  osv: 'osv',
  verbose: 'verbose',
  ttl: 'ttl',
  'cache-dir': 'cacheDir',
  cacheDir: 'cacheDir',
  format: 'format',
  retries: 'retries',
  'timeout-ms': 'timeoutMs',
  timeoutMs: 'timeoutMs',
  'backoff-ms': 'backoffMs',
  backoffMs: 'backoffMs',
  'no-tui': 'noTui',
  noTui: 'noTui',
  'exclude-pkg': 'excludePkg',
  excludePkg: 'excludePkg',
  iocs: 'iocs',
  'iocs-roots': 'iocsRoots',
  iocsRoots: 'iocsRoots',
  'osv-offline': 'osvOffline',
  osvOffline: 'osvOffline',
  'download-osv-db': 'downloadOsvDb',
  downloadOsvDb: 'downloadOsvDb',
};

export function loadConfigFile(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    return { __error: err };
  }
}

function applyConfig(opts, cfg) {
  for (const [k, v] of Object.entries(cfg)) {
    if (v === undefined || v === null) continue;
    const key = CONFIG_KEY_MAP[k];
    if (!key) continue;
    if (key === 'csv' && typeof v === 'string') opts.csv = [v];
    else if (key === 'sources' && Array.isArray(v)) opts.sources = v.join(',');
    else if (key === 'osv') opts.noOsv = !v;
    else opts[key] = v;
  }
}

function applyFlags(opts, flags) {
  for (const [k, v] of Object.entries(flags)) {
    if (v === undefined) continue;
    switch (k) {
      case 'osv':
        opts.noOsv = false;
        break;
      case 'json':
        opts.format = 'json';
        break;
      case 'csv':
        opts.csv = [...(opts.csv || []), ...v];
        break;
      default:
        opts[k] = v;
    }
  }
}

export function parseArgs(argv) {
  const flags = {};
  const errors = [];
  let help = false;
  let i = 0;
  const next = (name) => {
    const value = argv[i + 1];
    if (value === undefined) errors.push(`Option ${name} requires a value`);
    i++;
    return value;
  };

  for (; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--lockfile':
        flags.lockfile = next(a);
        break;
      case '--sources':
        flags.sources = next(a);
        break;
      case '--csv':
        flags.csv = flags.csv || [];
        flags.csv.push(next(a));
        break;
      case '--no-osv':
        flags.noOsv = true;
        break;
      case '--osv':
        flags.osv = true;
        break;
      case '--verbose':
        flags.verbose = true;
        break;
      case '--ttl':
        flags.ttl = Number(next(a));
        break;
      case '--cache-dir':
        flags.cacheDir = next(a);
        break;
      case '--format':
        flags.format = next(a);
        break;
      case '--json':
        flags.json = true;
        break;
      case '--config':
        flags.config = next(a);
        break;
      case '--retries':
        flags.retries = Number(next(a));
        break;
      case '--timeout-ms':
        flags.timeoutMs = Number(next(a));
        break;
      case '--backoff-ms':
        flags.backoffMs = Number(next(a));
        break;
      case '--no-tui':
        flags.noTui = true;
        break;
      case '--exclude-pkg':
        flags.excludePkg = next(a);
        break;
      case '--iocs':
        flags.iocs = true;
        break;
      case '--iocs-roots':
        flags.iocsRoots = next(a);
        break;
      case '--osv-offline':
        flags.osvOffline = true;
        break;
      case '--download-osv-db':
        flags.downloadOsvDb = true;
        break;
      case '--version':
        flags.version = true;
        break;
      case '-h':
      case '--help':
        help = true;
        break;
      default:
        if (a.startsWith('-')) {
          errors.push(`Unknown option: ${a}`);
          help = true;
        }
    }
  }
  return { flags, help, errors };
}

export function resolveOptions(argv, { cwd = process.cwd() } = {}) {
  const { flags, help, errors } = parseArgs(argv);
  const opts = defaultOptions();

  const configPath = isAbsolute(flags.config || opts.config)
    ? flags.config || opts.config
    : join(cwd, flags.config || opts.config);
  const cfg = loadConfigFile(configPath);
  if (cfg.__error) {
    if (flags.config) errors.push(`Config file ${configPath}: ${cfg.__error.message}`);
  } else {
    applyConfig(opts, cfg);
  }
  applyFlags(opts, flags);

  if (opts.format && !FORMATS.includes(opts.format)) {
    errors.push(`Unknown format: ${opts.format} (expected one of ${FORMATS.join(', ')})`);
  }
  if (opts.sources && opts.sources !== 'all') {
    const invalid = opts.sources
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .filter((s) => s !== 'all' && !SOURCE_IDS.includes(s));
    if (invalid.length) errors.push(`Unknown source(s): ${invalid.join(', ')}`);
  }
  if (typeof opts.ttl === 'number' && (Number.isNaN(opts.ttl) || opts.ttl < 0)) {
    errors.push(`Invalid --ttl: ${opts.ttl}`);
  }
  for (const [name, value] of [
    ['retries', opts.retries],
    ['timeout-ms', opts.timeoutMs],
    ['backoff-ms', opts.backoffMs],
  ]) {
    if (typeof value === 'number' && (Number.isNaN(value) || value < 0)) {
      errors.push(`Invalid --${name}: ${value}`);
    }
  }
  if (opts.osvOffline && opts.noOsv) {
    errors.push('--osv-offline cannot be combined with --no-osv');
  }

  return { opts, help, errors };
}

export function ttlFor(opts, srcId, fallbackHours = 24) {
  const ttl = opts.ttl;
  if (ttl && typeof ttl === 'object') {
    const hours = ttl[srcId] ?? ttl.default ?? fallbackHours;
    return hours * 60 * 60 * 1000;
  }
  const hours = typeof ttl === 'number' ? ttl : fallbackHours;
  return hours * 60 * 60 * 1000;
}

export function helpText() {
  return `npm-scan: detect known malicious npm packages in your lock files

Usage:
  npm-scan [options]

Options:
  --lockfile <path>     Lock file to scan. Auto-detects package-lock.json,
                        yarn.lock, pnpm-lock.yaml and bun.lock in the current directory.
  --sources <list>      Comma-separated sources: all,keyv,shai-hulud,axios,teampcp,osv (default: all)
  --csv <path|url>      Extra indicator CSV source (repeatable; schema auto-detected)
  --no-osv              Skip the OSV API check (fully offline, CSV sources only)
  --osv                 Force-enable the OSV check (overrides a config that set osv:false)
  --format <fmt>        Output format: pretty, compact, markdown, json, sarif,
                        gh-annotations (default: pretty)
  --json                Shortcut for --format json
  --ttl <hours>         Cache TTL for downloaded indicators (default: 24; 0 = always refresh;
                        a failed fetch falls back to the stale cached copy with a warning)
  --cache-dir <dir>     Cache directory (default: ~/.cache/npm-scan)
  --exclude-pkg <file>  File of package(s) to ignore even when flagged (one per line:
                        bare name matches every version; pkg@version matches exactly;
                        lines starting with # are comments)
  --iocs                Also scan installed packages on disk (package.json files)
                        against the indicator feeds
  --iocs-roots <dirs>   Comma-separated roots for --iocs (default: current directory)
  --osv-offline         Query a local OSV database instead of the OSV API (fully offline;
                        no OSV network calls are made)
  --download-osv-db     Download the npm OSV database (~100-300 MB, one-time) and exit,
                        or refresh it when combined with --osv-offline
  --no-tui              Disable the interactive progress UI (spinner/loading dots)
  --config <path>       Config file (default: .npmscanrc.json)
  --retries <n>         HTTP retries per fetch (default: 3)
  --timeout-ms <ms>     HTTP timeout per attempt (default: 30000)
  --backoff-ms <ms>     Initial retry backoff (default: 1000)
  --verbose             Print progress details to stderr
  --version             Print version and exit
  -h, --help            Show this help

Exit codes:
  0  no malicious packages found
  1  malicious packages found
  2  error (missing lock file, bad input, unrecognized source/format)`;
}
