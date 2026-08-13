import { mkdir, stat, writeFile } from 'node:fs/promises';
import { isAbsolute, join, basename } from 'node:path';
import { defaultConfig, helpText, resolveOptions } from './config.js';
import { renderReport } from './report.js';
import { isTuiEligible, runTui } from './tui.js';
import { ScanError } from './errors.js';
import { VERSION } from './version.js';
import { runScan } from './scan.js';
import { loadExcludeRules } from './exclude.js';
import { downloadOsvDb } from './osvdb.js';

export { runScan, loadExcludeRules };

async function detectLockfile(cwd, errPrint) {
  const candidates = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'];
  for (const name of candidates) {
    try {
      const st = await stat(join(cwd, name));
      if (st.isFile()) return join(cwd, name);
    } catch {}
  }
  errPrint(`Error: no lock file found (tried ${candidates.join(', ')}). Pass --lockfile.`);
  return null;
}

export async function main(
  argv = process.argv.slice(2),
  { stdout = process.stdout, stderr = process.stderr, cwd = process.cwd() } = {}
) {
  const hasFindings = (r) => r.matches.length + (r.iocMatches?.length || 0) > 0;
  const { opts, help, errors } = resolveOptions(argv, { cwd });
  const print = (s = '') => stdout.write(`${s}\n`);
  const errPrint = (s = '') => stderr.write(`${s}\n`);
  const startedAt = Date.now();

  if (errors.length > 0) {
    for (const e of errors) errPrint(`Error: ${e}`);
    errPrint('');
    errPrint(helpText());
    return 2;
  }
  if (opts.version) {
    print(`npm-scan ${VERSION}`);
    return 0;
  }
  if (help) {
    print(helpText());
    return 0;
  }

  if (opts.initConfig) {
    const target = isAbsolute(opts.config) ? opts.config : join(cwd, opts.config);
    try {
      await writeFile(target, `${JSON.stringify(defaultConfig(), null, 2)}\n`, { flag: 'wx' });
    } catch (e) {
      if (e.code === 'EEXIST') {
        errPrint(`Error: ${target} already exists; edit it in place or remove it first.`);
        return 2;
      }
      errPrint(`Error: cannot write ${target}: ${e.message}`);
      return 2;
    }
    print(`Wrote ${target}`);
    return 0;
  }

  await mkdir(opts.cacheDir, { recursive: true });

  const netOpts = {
    retries: opts.retries,
    timeoutMs: opts.timeoutMs,
    backoffMs: opts.backoffMs,
    verbose: opts.verbose,
  };

  if (opts.downloadOsvDb) {
    try {
      const res = await downloadOsvDb({ dir: opts.cacheDir, log: errPrint, ...netOpts });
      print(`Downloaded ${res.count} malicious advisory records to ${res.path}`);
    } catch (e) {
      errPrint(`Error: ${e.message}`);
      return 2;
    }
    if (!opts.osvOffline) return 0;
  }

  let lockPath = opts.lockfile
    ? isAbsolute(opts.lockfile)
      ? opts.lockfile
      : join(cwd, opts.lockfile)
    : null;
  if (!lockPath) {
    lockPath = await detectLockfile(cwd, errPrint);
    if (!lockPath) return 2;
  }
  const displayPath = opts.lockfile ? opts.lockfile : basename(lockPath);

  if (isTuiEligible({ stdout, opts })) {
    const stderrBuf = [];
    let report;
    try {
      report = await runTui({ stdout, stderr, lockfile: displayPath, version: VERSION }, async (emit) =>
        runScan(opts, { ...netOpts, log: (m) => stderrBuf.push(m) }, {
          emit,
          log: (m) => stderrBuf.push(m),
          warn: (m) => stderrBuf.push(m),
          cwd,
          displayPath,
          lockPath,
          startedAt,
        })
      );
    } catch (e) {
      if (!(e instanceof ScanError)) {
        let fallback;
        try {
          fallback = await runScan(opts, { ...netOpts, log: errPrint }, {
            emit: null,
            log: errPrint,
            warn: errPrint,
            cwd,
            displayPath,
            lockPath,
            startedAt,
          });
        } catch (e2) {
          if (e2 instanceof ScanError) {
            errPrint(e2.message);
            return e2.exitCode;
          }
          throw e2;
        }
        print(renderReport(fallback, { format: 'pretty', verbose: opts.verbose }));
        return hasFindings(fallback) ? 1 : 0;
      }
      for (const m of stderrBuf) errPrint(m);
      errPrint(e.message);
      return e.exitCode;
    }
    for (const m of stderrBuf) errPrint(m);
    print(renderReport(report, { format: 'pretty', verbose: opts.verbose }));
    return hasFindings(report) ? 1 : 0;
  }

  let report;
  try {
    report = await runScan(opts, { ...netOpts, log: errPrint }, {
      emit: null,
      log: errPrint,
      warn: errPrint,
      cwd,
      displayPath,
      lockPath,
      startedAt,
    });
  } catch (e) {
    if (e instanceof ScanError) {
      errPrint(e.message);
      return e.exitCode;
    }
    throw e;
  }

  const output = renderReport(report, { format: opts.format, verbose: opts.verbose });
  print(output);
  return hasFindings(report) ? 1 : 0;
}
