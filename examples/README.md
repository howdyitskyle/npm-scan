# Examples

This folder shows what `npm-scan` reports for different outcomes. Each
scenario has a crafted lockfile under `lockfiles/` and the generated reports
under `output/`.

> The outputs are snapshots from a live run against the DataDog / OSV feeds.
> Feed content, advisory IDs, timestamps, and indicator counts change over
> time, so re-run the commands below to regenerate them. The crafted lockfiles
> deliberately reference `keyv@6.0.0`, a real package version that was
> compromised in the keyv ecosystem supply-chain incident and is flagged by
> the DataDog `keyv-campaign` feed and OSV `MAL-2026-11524`.

## Scenarios

### 1. Clean — `lockfiles/clean/`

A tiny healthy lockfile (one dependency, nothing flagged).

- Expected result: `[ clean ]` header chip
- Exit code: `0`
- Outputs: `output/clean.pretty.txt`, `output/clean.compact.txt`,
  `output/clean.markdown.md`, `output/clean.json`

```sh
npm-scan --lockfile examples/lockfiles/clean/package-lock.json
```

### 2. Malicious direct dependency — `lockfiles/malicious-direct/`

`keyv@6.0.0` installed directly.

- Expected result: one finding, `Dependency: Direct dependency`
- Exit code: `1`
- Outputs: `output/malicious-direct.pretty.txt`,
  `output/malicious-direct.compact.txt`, `output/malicious-direct.markdown.md`,
  `output/malicious-direct.json`, `output/malicious-direct.sarif.json`

```sh
npm-scan --lockfile examples/lockfiles/malicious-direct/package-lock.json
```

### 3. Malicious transitive dependency — `lockfiles/malicious-transitive/`

`keyv@6.0.0` pulled in only as a transitive dependency of `cacheable-request`
(nested under its `node_modules`), so the app itself never depends on it
directly.

- Expected result: one finding, `Dependency: Transitive via cacheable-request`
- Exit code: `1`
- Outputs: `output/malicious-transitive.pretty.txt`,
  `output/malicious-transitive.compact.txt`,
  `output/malicious-transitive.markdown.md`,
  `output/malicious-transitive.json`

```sh
npm-scan --lockfile examples/lockfiles/malicious-transitive/package-lock.json
```

## Other outcomes to try

- **Piped / non-TTY output:** pipe the command through `cat` (or set `CI`) to
  skip the progress UI and print only the report.
- **Interactive progress UI:** run in a terminal without `--no-tui`; on fast
  (cached) scans the UI is held for about two seconds so it stays visible.
- **Offline / stale cache:** run with `--ttl 0 --no-osv` or without network to
  see the stale-cache and `OSV check skipped` notes.
- **Narrow terminals:** resize the terminal below 80 columns to see the
  borderless layout.
- **More formats:** `--format sarif` (GitHub code scanning), `--format json`.

## Regenerating the outputs

```sh
# from the project root
for d in clean malicious-direct malicious-transitive; do
  npm-scan --no-tui --format pretty  --lockfile examples/lockfiles/$d/package-lock.json > examples/output/$d.pretty.txt
  npm-scan --no-tui --format compact --lockfile examples/lockfiles/$d/package-lock.json > examples/output/$d.compact.txt
  npm-scan --no-tui --format markdown --lockfile examples/lockfiles/$d/package-lock.json > examples/output/$d.markdown.md
  npm-scan --no-tui --format json    --lockfile examples/lockfiles/$d/package-lock.json > examples/output/$d.json
done
npm-scan --no-tui --format sarif --lockfile examples/lockfiles/malicious-direct/package-lock.json > examples/output/malicious-direct.sarif.json
```

For each format, stdout is non-TTY when redirected, so the outputs are plain
text (no ANSI colors). In a real terminal the pretty report renders in the
Neon/Hacker color scheme.
