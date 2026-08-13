# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `gh-annotations` output format (`--format gh-annotations`): emits GitHub
  Actions workflow commands (`::error` per flagged package, `::notice` when
  clean) so findings render as PR annotations on the lock file. `--iocs`
  installed-package findings annotate `<path>/package.json`.
- `--exclude-pkg <file>`: ignores flagged packages listed in a file (`pkg`
  matches every version, `pkg@version` matches exactly, `#` comments).
  Excluded matches are surfaced in the report footer, `summary.excluded`, and
  an all-excluded run exits `0`. Missing/malformed files exit `2`. Rules apply
  to both lock file findings and installed packages found with `--iocs`.
- `--iocs`: scans installed `package.json` files on disk (node_modules incl.
  scoped, pnpm `.pnpm` virtual stores, and nested `node_modules`) against the
  same indicator feeds, catching packages missing from the lock file. Reported
  in a dedicated `Installed packages (--iocs)` section in every format
  (`iocMatches` in JSON), counted in `found`/exit code `1`, and deduplicated
  against lock file findings. `--iocs-roots <dirs>` overrides the roots
  (default: current directory). Installed packages get full OSV coverage via
  a query over the lockfile ∪ installed union.
- `--osv-offline` + `--download-osv-db`: fully offline OSV check against a
  local database built from the npm OSV dump (`~100-300 MB`, one-time),
  filtered to `MAL-*` + malicious `GHSA-*` records. No `api.osv.dev` calls are
  made in offline mode; advisory details come from the local records.
  `--download-osv-db` alone downloads and exits `0`; with `--osv-offline` it
  refreshes and scans. A missing DB exits `2` with instructions;
  `--osv-offline` conflicts with `--no-osv`.
- `docs/comparison.md`: landscape review of existing malicious-package scanners
  and the rationale for the borrowed features.
- Runtime dependency `fflate` for zip parsing of the OSV database download.

### Changed

- Package renamed to the scoped `@howdyitskyle/npm-scan` (the unscoped
  `npm-scan` name is rejected by npm as too similar to the existing `npmscan`
  package). The CLI binary is still `npm-scan`; publish with
  `npm publish --access=public`.
- License switched from Apache-2.0 to MIT.
- Internal source layout: `src/cli.js` now only wires the CLI — the scan
  orchestration moved to `src/scan.js`, `--exclude-pkg` rule parsing to
  `src/exclude.js`, `ScanError` to `src/errors.js`, and the package version to
  `src/version.js`. Report renderers split into `report-pretty.js`,
  `report-markdown.js`, `report-sarif.js`, and `report-shared.js`; `report.js`
  is now the dispatcher. Behavior is unchanged (181 tests, 100% line coverage).
- Added ESLint (flat config) and an enforced coverage gate: `npm run check`
  now runs `node --check`, `eslint`, and `scripts/check-coverage.mjs`, which
  fails unless every `src/` file is at 100% line coverage.
- The GitHub Actions workflow scans the checked-out code
  (`node bin/npm-scan.js`) instead of the published npm package, and the
  "Run test suite" step became a lint + coverage + test gate.
- Requires Node 20.19+ (was 18+) to keep dev tooling (ESLint 10) current;
  Node 18 is end-of-life.
- The progress UI is held for at least two seconds even on fast (cached) scans,
  so it is visible instead of flashing past before the report prints. It drops
  the `████░` percentage bars: the OSV check is now an animated `osv check …`
  loading line (dots tick on a 300ms cycle) that flips to
  `✓ osv check complete` when done. On fast scans the dots and `scanning…`
  footer keep animating through the minimum-display hold, and the completion
  state is revealed only when the report is about to print. GHSA classification
  and advisory enrichment keep their spinner rows without bars.
- Report spacing and readability pass on the pretty format:
  - key/value rows (lockfile, scanned, indicators, and every `Details & links`
    field) use a right-aligned label column so colons and values line up;
  - advisory links are nested under their advisory as an indented list, with
    blank lines separating multiple advisories and multiple findings;
  - the Recommended actions list uses a hanging indent so wrapped lines align
    under the text instead of the number.
- Advisory IDs, advisory links, and campaign references in the pretty report are
  clickable OSC 8 terminal hyperlinks (interactive terminals only; piped and
  redirected output stays plain text).
- Report language and information architecture overhaul (pretty, markdown, and
  compact formats):
  - one word per concept: indicator sources report `indicators`, dependency
    counts report `package`/`packages` — no more `(s)`, `entries`, or `pkg`;
  - counts use thousands separators (`3,474 indicators`);
  - section names unified across formats as `Findings`, `Details & links`, and
    `Recommended actions`; the count lives only in the header chip instead of
    being repeated in the section name;
  - clean results say `no known malicious packages found` (reflecting that
    feeds cover known indicators, not an absolute guarantee);
  - `Detected by` falls back to `osv` instead of `—` when only OSV advisories
    flagged a package;
  - markdown gains a `## Recommended actions` section;
  - the pretty footer collapses to a one-line digest
    (`4 sources · 3,474 indicators · all fresh`) with per-source rows shown
    only under `--verbose`.
- Pretty output wraps long lines (ANSI-aware word wrap) instead of clipping
  them, in both the framed (≥80 cols) and borderless (<80 cols) layouts.
- `summary.sources` in the JSON schema counts detection sources including the
  OSV check, while human copy now reports the number of indicator feeds — the
  info line, footer digest, and markdown all agree.

### Fixed

- pnpm v9 lock entries with peer-dependency suffixes (`foo@1.0.0(bar@2.0.0)`)
  were split on the peer's `@`, mangling the package name/version; the
  parenthesized suffix is now stripped before splitting, so such packages are
  matched correctly.
- `--exclude-pkg` no longer counts installed packages as "excluded" unless a
  feed actually flagged them (the excluded tally was inflated by excluded-but-
  clean installed packages found via `--iocs`).
- The HTTP `User-Agent` now reports the real package version instead of a
  hardcoded `1.0.0`.
- `--retries`, `--timeout-ms`, and `--backoff-ms` are validated like `--ttl`
  (negative or non-numeric values now exit `2` with a clear error instead of
  misbehaving at fetch time).
- `--osv` (force-enable OSV) is now listed in `--help` and the README options.
- `scripts/check-coverage.mjs` now parses both the Node 20 (`#`) and Node 22+
  (`ℹ`) test-coverage report formats, so the coverage gate no longer fails on
  newer Node versions.
- SARIF output now uses the schema-valid `invocations` array (was a bare
  `invocation` object, which the SARIF 2.1.0 schema rejects), so uploads to
  GitHub code scanning succeed.

## [1.2.0] - 2026-08-06

### Added

- Interactive progress UI while the scan runs, built with
  [ink](https://term.ink), [@inkjs/ui](https://term.ink/ui), and
  `gradient-string`. The "Neon/Hacker" style includes:
  - a cyan→magenta gradient wordmark and rounded outer frame;
  - `[ OK ]` / `[ FAIL ]` / `[ CACHED ]` / `[ STALE ]` chips per indicator
    source with entry counts;
  - custom `████░` block progress bars (sized to terminal width) for the OSV
    query, GHSA classification, and advisory enrichment phases;
  - a KPI footer with live counts, an elapsed-time ticker, and the final
    `✗ Found N malicious package(s)` result line.
  The full pretty report prints normally when the scan finishes.
- Responsive TUI layout: two columns at ≥110 cols, single framed column at
  ≥80, borderless compact rows below that.
- The UI activates only when stdout is a TTY and the format is `pretty`; it is
  skipped for piped/CI output and machine-readable formats. `--no-tui` forces
  it off.
- The pretty report matches the UI: gradient wordmark header in a rounded
  frame, `[ SEVERITY ]` chips, a findings table with severity column, and
  magenta-banded `Details & links` and `recommended actions` sections.
- The pretty report uses the same layout language as the TUI: the whole report
  sits inside one rounded gray frame with full-width rules, a `[ clean ]` /
  `[ N malicious package ]` header chip, and a KPI-style footer. Below 80
  columns it drops the frame, mirroring the TUI's responsive layout.
- `react@^18`, `ink@^5`, `@inkjs/ui@^2`, and `gradient-string@^3` as runtime
  dependencies (still Node 18+ compatible).

### Fixed

- README's `.npmscanrc.json` example used `"ttl": 86400`, which the hours-based
  TTL config would have interpreted as ~9.8 years of caching; the example now
  shows the per-source TTL object form.

## [1.1.0] - 2026-08-05

### Added

- `bun.lock` (text/JSONC format) support, including auto-detection and a
  friendly message for the binary `bun.lockb` suggesting
  `bun install --save-text-lockfile`.
- Stale-cache fallback: if a downloaded indicator's cached copy is older than
  the TTL and the network fetch fails, the stale copy is used (previously the
  scan errored) with a visible warning and a `stale` flag per source in every
  report format.
- GHSA classification freshness: `osv-types.json` now stores
  `{ type, fetchedAt }` and re-checks advisory classifications older than the
  TTL (default 24h) instead of caching them forever. Transient fetch failures
  self-heal on the next scan. Legacy caches are migrated automatically.
- Accurate per-source `fetchedAt`: served-from-cache sources now report the
  cache file's mtime instead of the scan time.
- `satisfies` support for `x`/`X`/`*` ranges (`1.x`, `1.2.x`, `~1.x`) and
  partial versions (`1`, `1.2`), plus prerelease/build-suffix tolerance —
  restoring transitive (`via`) attribution for non-exact ranges.
- CI: `.github/workflows/scan.yml` now runs the test suite on every push/PR
  and a daily feed-integrity smoke test that re-downloads all CSV feeds with
  `--ttl 0` and asserts known-bad packages are still detected.
- `prepublishOnly` runs the full check before publishing.

### Fixed

- README/CHANGELOG previously claimed "stale-cache warnings" that were never
  implemented; behavior now matches the docs (see above).
- OSV advisory details are no longer destroyed by a failed network fetch: if
  the cached copy for an advisory is stale and the API is unreachable, the
  last good summary/details/affected ranges are preserved (mirroring the CSV
  stale-cache fallback) instead of being overwritten with an empty entry.

## [1.0.0] - 2026-08-05

### Added

- Modular codebase (`bin/npm-scan.js` + `src/`) replacing the monolithic
  `scan-malicious.mjs` prototype.
- Packaging: `npm-scan` bin entry, `engines >= 18`, Apache-2.0 license.
- Yarn lockfile (v1 and v2+) and pnpm lockfile (v9) parsing in addition to
  `package-lock.json` (v1/v2/v3).
- Rich findings: transitive attribution via dependency graph walk, direct vs
  transitive classification, severity, affected range vs installed version,
  and patched version from OSV fixed events.
- Output formats: `pretty` (default), `compact`, `markdown`, `json`
  (versioned schema), and `sarif`.
- Ops hardening: `.npmscanrc.json` config file merging (resolved relative to
  the scan directory), per-source cache TTL overrides, and HTTP retries with
  backoff.
- GHSA `MALICIOUS` classification via OSV `GET /v1/vulns/{id}` for advisory
  IDs that do not carry a `MAL-*` prefix.
- Test suite (48 `node:test` cases) covering CSV schema detection, lockfile
  parsing (npm/yarn/pnpm), config merging, and end-to-end scans with mocked
  HTTP.
- CI template (`.github/workflows/scan.yml` with SARIF upload) and pre-commit
  hook config.

### Fixed

- JSON/SARIF reports no longer emit empty objects for advisory/source sets
  (arrays are serialized instead of `Set`s).
- GHSA `MALICIOUS` advisories were never classified because `Array#flat()`
  does not flatten `Set`s; candidate IDs are now spread from each set.
- `.npmscanrc.json` was read relative to the process working directory instead
  of the scanned project directory.
- Lock files with unrecognized names are now content-sniffed (yarn v1/v2,
  pnpm) so `--lockfile` works with renamed files.
- Markdown reports emitted `Generated: undefined` when run without `--json`
  (timestamp now comes from the report header).

## [0.1.0] - 2026-08-05

### Added (prototype, `scan-malicious.mjs`)

- Scan lockfiles against known malicious npm package indicators:
  DataDog keyv campaign, Shai-Hulud 2.0, axios supply-chain compromise,
  TeamPCP, and OSV MAL-* / malicious GHSA-* advisories.
- Automatic source detection for `package-lock.json` (v1/v2/v3), custom
  `--csv` files (auto schema detection), and custom `--lockfile` paths.
- Deduplication on `package@version` with merged source attribution.
- Rich report with advisory details, links, and recommended remediation
  actions.
- Local HTTP cache (`~/.cache/npm-scan/`) with configurable TTL.
- Exit codes: `0` clean, `1` matches found, `2` error.
