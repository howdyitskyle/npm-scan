# AGENTS.md

Guidance for AI agents working in this repository.

## Project

`npm-scan` scans lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
`bun.lock`) for known malicious npm packages against threat-intelligence feeds
(DataDog keyv campaign, Shai-Hulud, axios, TeamPCP CSVs, and OSV `MAL-*` /
malicious `GHSA-*` advisories). Exit code `1` means matches found; `2` is an
error. MIT licensed.

## Commands

```sh
npm install                # install runtime deps (ink-based progress UI) + dev deps (ESLint)
npm run check              # node --check + ESLint + coverage gate + full test suite
npm test                   # test suite only (node --test "test/**/*.test.mjs")
npm run lint               # ESLint (eslint.config.js, flat config)
npm run coverage           # coverage gate: fails unless every src/ file is at 100% line coverage
npm run scan -- --format json   # run the scanner against local lock files
```

`npm run check` is the gate: `node --check bin/npm-scan.js`, then ESLint over
`bin/`, `src/`, `test/`, `scripts/`, then `scripts/check-coverage.mjs` (which
runs the full `node:test` suite with `--experimental-test-coverage` and fails
if any `src/` file is below 100% line coverage).

All `src/` files currently hold 100% line coverage; keep it that way when
adding code — export seams (e.g. `setFetch`, `setUseColor`, `ScanUi`,
`truncateAnsi`, `clipAnsi`) are used by tests to reach otherwise private paths.

A brand-new `src/*.js` module needs at least one test that imports it: the
coverage gate fails with "`<file>` was not reported by the coverage run" (not
merely "<100%"), so adding an untested module breaks `npm run check`.

## Structure

- `bin/npm-scan.js` — shebang entry; calls `main()` from `src/cli.js` and maps
  errors to exit `2`.
- `src/cli.js` — `main()` only: argument handling, TTY detection, report
  printing, exit codes. Re-exports `runScan` and `loadExcludeRules` for tests.
- `src/scan.js` — the `runScan` orchestration: loads indicator feeds, parses
  the lock file, runs `--iocs` and OSV checks, builds the report object.
- `src/config.js` — CLI flag + `.npmscanrc.json` config merging.
- `src/sources.js` — the built-in CSV indicator feeds and URL/name resolution.
- `src/csv.js` — CSV parsing (schema auto-detection) and record matching.
- `src/iocs.js` — `--iocs` installed-`package.json` walk (node_modules, pnpm
  `.pnpm` stores, nested).
- `src/lockfile.js` — lock file parsing for all supported formats.
- `src/osv.js` — OSV API queries (querybatch, advisory details, GHSA
  classification).
- `src/osvdb.js` — offline OSV database build/query (`--download-osv-db`,
  `--osv-offline`).
- `src/exclude.js` — `--exclude-pkg` rule parsing.
- `src/errors.js` — `ScanError` (exit code `2`).
- `src/version.js` — package version, single source of truth.
- `src/report.js` — `renderReport` dispatcher plus compact and gh-annotations
  renderers. Re-exports `clipAnsi` for tests.
- `src/report-pretty.js` — pretty renderer and the `clipAnsi` ANSI/OSC-aware
  truncator.
- `src/report-markdown.js` — markdown renderer.
- `src/report-sarif.js` — SARIF 2.1.0 renderer.
- `src/report-shared.js` — `matchKindLabel`, `severityLabel` shared by
  renderers.
- `src/tui.js` — ink-based progress UI; exposes `ScanUi`.
- `src/util.js` — helpers (`fetchWithRetry`, `fetchCached`, `wrapAnsi`,
  `truncateAnsi`, `plural`, `mapLimit`, etc.).
- `src/colors.js` — ANSI/OSC color helpers; `useColor`/`setUseColor`.
- `scripts/check-coverage.mjs` — coverage gate backing `npm run coverage`.
- `test/fixtures/` — synthetic lock files and fixture data for tests.
- `docs/comparison.md` — landscape review vs. other scanners.

## Conventions

- ESM throughout (`"type": "module"`), Node >= 20.19. No transpilation.
- No code comments unless explicitly requested; prefer self-documenting names.
- Runtime deps live in `package.json` (`ink`, `@inkjs/ui`, `gradient-string`,
  `react`, `fflate`); tests should not add new dependencies — the built-in
  `node:test` runner plus `node:assert` cover everything so far.
- Tests reach internals through exported seams; keep those exports minimal and
  documented by the tests that use them.
- Keep `npm run lint` and `npm run coverage` green after every change.
- User-facing output changes belong in `CHANGELOG.md` under `[Unreleased]`.
- README documents every CLI flag; keep the "Options" block and sections in
  sync when flags change.
- The scheduled CI smoke test (`.github/workflows/scan.yml`) greps
  `test/fixtures/malicious-v3.json` output for `keyv@6.0.0` and `axios@1.14.1`;
  don't change those fixture packages without updating the workflow. It only
  runs on `schedule`, so `npm run check` won't catch a break.
- The npm package is published as the scoped `@howdyitskyle/npm-scan`. The
  unscoped name `npm-scan` is rejected by the npm registry as too similar to
  the existing `npmscan` package. The CLI binary is still `npm-scan`; publish
  with `npm publish --access=public`. README's `npx`/pre-commit examples and
  `package.json` `name` must use the scoped name.
- Repo is on GitHub at `howdyitskyle/npm-scan` (CI green via
  `.github/workflows/scan.yml`); do not commit or push unless asked.
- `main` is branch-protected: it requires a pull request and the `scan` status
  check to pass. Never push directly to `main`. The workflow for any change is
  a feature branch, push it, open a PR (`gh pr create`), and merge once the
  `scan` check is green (`gh pr merge`).
