# npm-scan

[![CI](https://github.com/howdyitskyle/npm-scan/actions/workflows/scan.yml/badge.svg)](https://github.com/howdyitskyle/npm-scan/actions/workflows/scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.19.0-brightgreen.svg)](https://nodejs.org/)

Detect known malicious npm packages in your lock files.

`npm-scan` scans `package-lock.json` (v1/v2/v3), `yarn.lock` (v1), `pnpm-lock.yaml`
(v9), and `bun.lock` (text format) against multiple threat-intelligence feeds of
known malicious npm packages, and reports anything it finds with rich detail
— including whether the package is a direct or transitive dependency and
which of your direct dependencies pulled it in.

## Quick start

```sh
npx --yes npm-scan
```

Auto-detects a lock file in the current directory, scans it, and prints a
report. Exit code is `1` when anything is found, so it drops straight into
CI and pre-commit hooks.

```sh
# Scan a specific lock file, JSON output
npm-scan --lockfile path/to/package-lock.json --json

# Fully offline (skip OSV, CSV feeds only)
npm-scan --no-osv

# Fully offline with a downloaded OSV database (no OSV API calls, ever)
npm-scan --download-osv-db   # one-time: ~100-300 MB
npm-scan --osv-offline

# Also scan installed packages on disk (node_modules) against the feeds
npm-scan --iocs

# Keep your own indicator feed
npm-scan --csv ./my-iocs.csv --sources all
```

## Sources

| Source | Feed | Coverage |
| --- | --- | --- |
| `keyv` | DataDog keyv campaign malicious packages | `keyv-campaign/malicious-packages.csv` |
| `shai-hulud` | Shai-Hulud 2.0 consolidated IOCs | `shai-hulud-2.0/consolidated_iocs.csv` |
| `axios` | axios supply-chain compromise | `axios-npm-supply-chain-compromise/iocs.csv` |
| `teampcp` | TeamPCP npm malicious packages | `teampcp/iocs.csv` |
| `osv` | OSV `MAL-*` and malicious `GHSA-*` advisories | `api.osv.dev/v1/querybatch` or local DB (`--osv-offline`) |

All sources are enabled by default (`--sources all`). Use
`--sources keyv,osv` to restrict, or `--no-osv` to run with CSV sources only.
`--osv-offline` runs the OSV check against a downloaded local database instead
of the API (see [Offline mode](#offline-mode)).
Custom CSV files added with `--csv` have their schema auto-detected
(`ecosystem,package,versions`, `package_name,package_versions`, `type/indicator`,
`artifact_type,name,affected_versions`, or generic `name,version`).

Results are deduplicated on `package@version` and attributed to every source
that flagged them.

## Output

- `pretty` (default) — Neon/Hacker styled report in a rounded frame, matching
  the progress UI: gradient wordmark header, `[ clean ]` / `[ N malicious
  package ]` chip, a Findings table, Details & links, and Recommended actions.
  Advisory IDs, advisory links, and campaign references render as clickable
  terminal hyperlinks in interactive terminals. Each indicator source is
  reported as its `indicators` count; the footer collapses to a one-line digest
  (`N sources · M indicators · all fresh`) and expands to per-source rows with
  `--verbose`
- `compact` — one line per match, for logs
- `markdown` — GitHub-flavored markdown
- `json` — versioned machine-readable schema
- `sarif` — SARIF 2.1.0 for GitHub code scanning / generic SARIF consumers
- `gh-annotations` — GitHub Actions workflow commands (`::error`/`::notice`) so
  flagged packages appear as PR annotations

## Installed packages (`--iocs`)

`--iocs` additionally walks `package.json` files on disk — `node_modules`
(including scoped, pnpm `.pnpm` virtual stores, and nested dependency
`node_modules`), plus your own project manifest — and matches installed
`package@version` pairs against the same indicator feeds. This catches
packages that are present in `node_modules` but missing from the lock file
(e.g. scripts or manual installs). Results appear in a separate
`Installed packages (--iocs)` report section, are deduplicated against lock
file findings, and count toward exit code `1`. Point the walk elsewhere with
`--iocs-roots <dir>[,<dir>]`. Non-package indicators in the feeds (domains,
IPs, other ecosystems) are not matched.

## Offline mode

Two independent offline switches:

- `--no-osv` — skips OSV entirely; CSV feeds only. Fully offline once feeds are
  warm (or with `--csv` pointing at local files).
- `--osv-offline` — runs the full OSV check against a **local database** of
  malicious advisories, so no `api.osv.dev` calls are made. Build it once:

  ```sh
  npm-scan --download-osv-db   # downloads the npm OSV dump (~100-300 MB), keeps
                               # only MAL-* + malicious GHSA records, then exits 0
  ```

  Combined with a scan: `npm-scan --download-osv-db --osv-offline` refreshes the
  database and scans in one go. If the local DB is missing,
  `--osv-offline` exits `2` with instructions. `--osv-offline` conflicts with
  `--no-osv`.

## Excluding known-false positives (`--exclude-pkg`)

`--exclude-pkg <file>` drops matching packages from the report even when a feed
flags them — useful when a fork or pinned build is intentionally ignored. One
rule per line; `#` comments are ignored:

```text
# ignore every version of lodash
lodash
# ignore only this exact version
keyv@6.0.0
```

Bare names match every version; `name@version` matches exactly (a leading `v`
on the version is tolerated). Rules apply to both lock file findings and
installed packages found with `--iocs`. Excluded matches are still counted in
the report footer (`N match(es) excluded via --exclude-pkg`). If every match is
excluded, the run exits `0`. A missing or malformed file exits `2`.

## GitHub Actions

`--format gh-annotations` emits workflow commands that GitHub renders as
annotations on the lock file in the PR diff. A minimal job:

```yaml
- uses: actions/checkout@v4
- run: npx --yes npm-scan --format gh-annotations
```

For the check to fail when malware is found, let the exit code propagate (it is
`1` when matches exist and `0` otherwise).

## Interactive progress UI

When stdout is a terminal and the output format is `pretty` (the default),
`npm-scan` renders a live **Neon/Hacker** progress UI while the scan runs — a
gradient wordmark, rounded frame, `[ OK ]`/`[ FAIL ]`/`[ CACHED ]`/`[ STALE ]`
chips per indicator source, an animated `osv check …` loading line (which flips
to `✓ osv check complete`), spinner rows for GHSA classification / advisory
enrichment, and a KPI footer with live counts, an elapsed-time ticker, and the
final result line (e.g. `scanned 4 packages · 3,474 indicators · 0.8s · 1
malicious package`). The full pretty report then prints normally once the scan
finishes.

The UI adapts to terminal width: two-column layout on wide terminals (≥110
cols), single framed column at ≥80, and borderless compact rows below that.
On fast (cached) scans it is held on screen for at least two seconds so it
doesn't flash past. It is disabled automatically when stdout is not a TTY
(piped/CI), `CI` is set, `TERM=dumb`, or the format is not `pretty`. Force it
off with `--no-tui`. Machine-readable formats (`json`, `sarif`, `markdown`,
`compact`) always produce plain text.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | no malicious packages found |
| `1` | malicious packages found |
| `2` | error (missing lock file, bad input, unrecognized source/format) |

## Configuration

`.npmscanrc.json` in the project directory is merged with CLI flags (flags
win). All keys mirror the CLI options:

```json
{
  "format": "pretty",
  "sources": ["keyv", "shai-hulud", "axios", "teampcp", "osv"],
  "osv": true,
  "osvOffline": false,
  "excludePkg": "exclude.txt",
  "iocs": false,
  "ttl": { "default": 24, "keyv": 1 },
  "cacheDir": ".cache/npm-scan",
  "retries": 3,
  "timeoutMs": 30000,
  "backoffMs": 500
}
```

See `.npmscanrc.json.example`. Downloads are cached in `~/.cache/npm-scan/`
(override with `--cache-dir`) with a default TTL of 24h (`--ttl 0` forces a
refresh). If a cached source is older than the TTL and the network fetch
fails, npm-scan falls back to the stale cached copy, prints a warning, and
flags the source as stale in the report.

### How fresh are the indicator lists?

- **OSV `MAL-*` advisories** are queried live against `api.osv.dev` on every
  run — never cached — so they are always up to date. With `--osv-offline`
  they come from the local database instead (refresh it with
  `--download-osv-db`).
- **CSV feeds** (DataDog, Shai-Hulud, axios, TeamPCP) are re-downloaded
  whenever the cached copy is older than the TTL (default 24h), picking up
  upstream additions on the next run. `--ttl 0` always refreshes.
- **OSV advisory details** (`osv-advisories.json`) and **GHSA classification**
  (`osv-types.json`) both honor the same TTL, so re-classifications are picked
  up on the same cadence instead of being cached forever.
- **CI**: the included workflow runs on every push/PR and on a daily schedule
  (`0 6 * * *`), plus a daily feed-integrity smoke test that re-downloads all
  CSV feeds with `--ttl 0` and asserts known-bad packages are still detected —
  so upstream format drift is caught the morning it happens.

## CI / pre-commit

GitHub Actions workflow at `.github/workflows/scan.yml` runs the test suite,
scans with `pretty`, `sarif`, and `gh-annotations` output, uploads SARIF to
code scanning, and runs a daily feed-integrity smoke test. A local pre-commit
hook at `.pre-commit-config.yaml` runs `npm-scan --no-osv --format compact` on
lock file changes.

## Options

```
npm-scan [options]

  --lockfile <path>     Lock file to scan. Auto-detects package-lock.json,
                        yarn.lock, pnpm-lock.yaml and bun.lock in the current directory.
  --sources <list>      Comma-separated sources: all,keyv,shai-hulud,axios,teampcp,osv (default: all)
  --csv <path|url>      Extra indicator CSV source (repeatable; schema auto-detected)
  --no-osv              Skip the OSV API check (fully offline, CSV sources only)
  --osv                 Force-enable the OSV check (overrides a config that set osv:false)
  --format <fmt>        Output format: pretty, compact, markdown, json, sarif,
                        gh-annotations (default: pretty)
  --json                Shortcut for --format json
  --ttl <hours>         Cache TTL for downloaded indicators (default: 24; 0 = always refresh)
  --cache-dir <dir>     Cache directory (default: ~/.cache/npm-scan)
  --exclude-pkg <file>  Ignore packages listed in <file> (pkg or pkg@version per line, # comments)
  --iocs                Also scan installed packages on disk (package.json files)
  --iocs-roots <dirs>   Comma-separated roots for --iocs (default: current directory)
  --osv-offline         Query a local OSV database instead of the OSV API (fully offline)
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
```

## How npm-scan compares

npm-scan is a **malware-only** scanner: a non-zero exit code means
*compromised*, not "has an old dependency", so the check is safe to gate merges
and pre-commit hooks on. For general CVE coverage, SBOM generation, or
call-graph analysis, pair it with a broader scanner such as OSV-Scanner.

| Tool | Malicious-only? | Source of truth | Standout capability |
| --- | --- | --- | --- |
| **npm-scan** | Yes | DataDog campaign CSVs + OSV `MAL-*` / malicious `GHSA-*` | exit 1 = compromised; direct/transitive attribution; custom `--csv` feeds; interactive TUI report |
| **OSV-Scanner** (Google) | No | OSV.dev (all advisories) | offline DB, `gh-annotations`, call analysis, guided remediation |
| **depx** (ProjectDiscovery) | Mostly | OpenSSF MAL + X/Grok live feed | system-wide audit, `--exclude-pkg`, exit 0/1/2/3 |
| **shai-scan** (@digi4care) | Yes | static hand-maintained DB | zero runtime deps, npm+PyPI, system IOC sweep |
| **Socket / Snyk / Trivy / Grype** | No | mixed | broad CVE coverage, SBOM, provenance |
| **DataDog Guarddog** | No | behavior heuristics | produces the campaign CSVs npm-scan consumes |
| **Apify NPM Lockfile Threat Scanner** | Yes | OSV MAL + GHSA malware | paid actor; closest design match |

### Where npm-scan wins

- **Malicious-only signal.** `exit 1` means *compromised*, so CI can fail on a
  real threat without drowning in low-severity CVEs.
- **Campaign feeds are independent of OSV/GHSA ingestion.** The DataDog keyv,
  Shai-Hulud, axios, and TeamPCP CSVs are pulled directly and can flag packages
  OSV hasn't catalogued yet — the day-one fast path.
- **Direct/transitive attribution** — which of your direct dependencies pull a
  flagged package in — plus `--csv` custom feeds, `npx` install, and an
  interactive TUI report.

### What we borrowed

- [`gh-annotations` output](#github-actions) from OSV-Scanner
- [`--exclude-pkg`](#excluding-known-false-positives---exclude-pkg) from depx
- [`--iocs` installed-footprint scan](#installed-packages---iocs) from shai-scan
- [`--osv-offline` / `--download-osv-db`](#offline-mode) from OSV-Scanner

See [docs/comparison.md](docs/comparison.md) for the full landscape review and
the rationale for each borrowed feature.

## Development

```sh
npm install      # installs runtime deps (ink-based progress UI) + dev deps (ESLint)
npm run check    # node --check + ESLint + coverage gate + full test suite
npm test         # test suite only
npm run lint     # ESLint (flat config)
npm run coverage # coverage gate: fails unless every src/ file is at 100% line coverage
npm run scan -- --format json   # run against local lock files
```

Requires Node 20.19+. MIT.
