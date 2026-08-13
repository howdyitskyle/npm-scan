# npm-scan vs. existing scanners

Notes from a March 2026 landscape review of tools that scan npm dependencies for
**known malicious** packages (as opposed to general CVEs). Bottom line up front:
no open-source tool does exactly what npm-scan does — the closest OSS tool is
Google's OSV-Scanner, and the closest design match is a paid Apify actor.

## The ecosystem

| Tool | Type | Malicious-only? | Source of truth | Notable capabilities |
| --- | --- | --- | --- | --- |
| **npm-scan** (this repo) | OSS, npx-installable | **Yes** | DataDog campaign CSVs + OSV `MAL-*`/malicious `GHSA-*` | exit-1 = compromised, direct/transitive attribution, `--csv` custom feeds, interactive TUI report, offline DB |
| **OSV-Scanner** (Google) | OSS Go, Apache-2.0 | No (all advisories) | OSV.dev | offline DB, 10 output formats (incl. `gh-annotations`), call analysis, guided remediation (`fix`), SLSA 3 |
| **depx** (ProjectDiscovery) | OSS Go, MIT | Mostly | OpenSSF MAL + X/Grok live feed | system-wide audit of `$HOME`/lockfiles/SBOMs, `--exclude-pkg`, exit 0/1/2/3 |
| **shai-scan** (@digi4care) | OSS TS, MIT | Yes | static hand-maintained DB | zero runtime deps, npm+PyPI, includes a system-level IOC sweep |
| **Apify NPM Lockfile Threat Scanner** | paid actor | Yes | OSV MAL + GHSA malware | dual live feeds; closest **design** match to npm-scan |
| Socket / Snyk / Trivy / Grype | OSS/commercial | No | mixed | broad CVE coverage, SBOM, provenance |
| DataDog Guarddog | OSS | No | behavior heuristics | produces the campaign CSVs npm-scan consumes |

## Where npm-scan wins

1. **Malicious-only signal.** A non-zero exit code means *compromised*, not
   "has an old dependency." This makes it safe to gate merges on.
2. **Campaign feeds are independent of OSV/GHSA ingestion.** The DataDog
   `keyv-campaign`, Shai-Hulud 2.0, axios, and TeamPCP CSVs are pulled
   directly and can flag packages OSV hasn't catalogued yet — the actual
   day-one fast-path. (Note: npm-scan does **not** call any GitHub API; GHSA
   records arrive via OSV's aggregation of the GitHub Advisory Database.)
3. **Direct/transitive attribution** with which direct dependencies pull a
   flagged package in.
4. **`--csv` custom feeds**, **npx install**, and a pretty interactive TUI
   report.

## Where OSV-Scanner wins

- Breadth (everything OSV knows, not just malware) and provenance/SBOM.
- **Full offline DB mode** (`--offline` + `--download-offline-databases`) over
  ecosystem dumps — no network at all.
- `gh-annotations` output, call analysis, and guided remediation.

## What we borrowed (and why)

From the review, four things were adopted:

1. **`gh-annotations` output** (from OSV-Scanner) — GitHub renders workflow
   commands as PR annotations on the lock file.
2. **`--exclude-pkg`** (from depx) — a allowlist file for known-false-positives
   (`pkg` or `pkg@version`, `#` comments).
3. **`--iocs` installed-footprint scan** (from shai-scan) — walks installed
   `package.json` files (incl. pnpm `.pnpm` stores) against the same feeds,
   catching packages missing from the lock file.
4. **`--osv-offline` / `--download-osv-db`** (from OSV-Scanner) — a local
   database of the npm OSV dump filtered to `MAL-*` + malicious `GHSA-*`, so
   scans can run with zero OSV network calls.

Everything else was left alone: full CVE coverage, call-graph analysis, SBOM
generation, and remediation planning are out of scope for a malware-only
lockfile scanner.
