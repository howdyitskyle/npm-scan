# npm-scan report

- **Lockfile:** `examples/lockfiles/malicious-direct/package-lock.json`
- **Format:** package-lock
- **Scanned:** 1 package
- **Indicators:** 3,474 from 4 sources
- **Generated:** 2026-08-06T20:35:00.792Z (387ms)

## Findings (1)

| Package | Version | Direct | Detected by | Advisory | Severity | Patched |
| --- | --- | --- | --- | --- | --- | --- |
| `keyv` | `6.0.0` | Direct dependency | DataDog keyv-campaign | MAL-2026-11524 | — | — |

## Details & links

### keyv@6.0.0
- **MAL-2026-11524**: Malicious code in keyv (npm)
  - https://api.osv.dev/v1/vulns/MAL-2026-11524
  - https://www.npmjs.com/package/keyv/v/6.0.0
  - https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain
  - https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack
- Campaign: https://github.com/DataDog/indicators-of-compromise/tree/keyv-campaign/keyv-campaign

## Recommended actions

1. Update/pin each flagged package to a patched version listed in its advisory link above.
2. Run `npm audit fix` then `npm install` to re-resolve the dependency tree.
3. If a flagged package ran install scripts or executed code, treat the machine as compromised — rotate npm / GitHub / cloud credentials and review published packages and git history.
4. Keep `package-lock.json` committed and review dependency changes in every pull request.

## Sources

- **DataDog keyv-campaign:** 2,236 indicators (sha256 75a8e8f32426…)
- **DataDog Shai-Hulud 2.0:** 1,091 indicators (sha256 6e23c118af47…)
- **DataDog axios compromise:** 3 indicators (sha256 9c9ddad95350…)
- **DataDog TeamPCP:** 144 indicators (sha256 b7ab68715b11…)

