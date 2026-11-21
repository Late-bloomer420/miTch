# Full build, test, lint and three-app dev start — 2026-11-21

Revision `b00eb14` (master after #319). Linux cloud container, 4 cores, 15 GB RAM,
Node `v22.22.0`, pnpm `10.34.9`. Run on 2026-11-21. Existing `node_modules` were reused; this
was not a fresh clone. Turbo caches were bypassed with `--force` for build and test.

Earlier records keep their scope and date. This record does not replace the 2026-11-19
[performance baseline](BUILD_TEST_PERFORMANCE_BASELINE_2026-11-19.md), which measured timings on Windows.

## Results

| Step        | Command                                               | Result                                                                                  |
| ----------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Install     | `pnpm install --frozen-lockfile`                      | exit 0, 3.5 s                                                                           |
| Build       | `pnpm build --force` (excludes `@askmi/poc-hardened`) | exit 0; **31/31 tasks**, 0 cached; 28.7 s wall                                          |
| Test        | `pnpm test --force` (excludes `@askmi/poc-hardened`)  | exit 0; **49/49 tasks**, 0 cached; 1 m 15 s wall                                        |
| Test totals | 31 Vitest suites                                      | **2659 passed, 1 skipped, 0 failed**                                                    |
| Lint        | `pnpm lint`                                           | exit 0; 13/13 tasks; 0 errors, 7 warnings (the known `no-explicit-any` in `wallet-pwa`) |

Log lines that read "failed" (for example `KB-JWT verification failed`, `nonce mismatch`) come from
negative tests that expect a denial. No test failed.

### Tests per package

| Package                        | Result     |
| ------------------------------ | ---------- |
| `@askmi/anchor-service`        | 12 passed  |
| `@askmi/audit-log`             | 37 passed  |
| `@askmi/connect`               | 66 passed  |
| `@askmi/consent-ui`            | 23 passed  |
| `@askmi/data-flow`             | 71 passed  |
| `@askmi/discrete-core`         | 45 passed  |
| `@askmi/eid-issuer-connector`  | 21 passed  |
| `@askmi/evidence`              | 38 passed  |
| `@askmi/integration-tests`     | 54 passed  |
| `@askmi/issuer-mock`           | 26 passed  |
| `@askmi/layer-resolver`        | 24 passed  |
| `@askmi/mcp-server`            | 11 passed  |
| `@askmi/mdoc`                  | 195 passed |
| `@askmi/mock-issuer`           | 14 passed  |
| `@askmi/oid4vci`               | 35 passed  |
| `@askmi/oid4vp-verifier`       | 65 passed  |
| `@askmi/oid4vp`                | 101 passed |
| `@askmi/phase0-security`       | 149 passed |
| `@askmi/policy-engine`         | 349 passed |
| `@askmi/predicates`            | 90 passed  |
| `@askmi/revocation-statuslist` | 34 passed  |
| `@askmi/secure-memory`         | 4 passed   |
| `@askmi/secure-storage`        | 11 passed  |
| `@askmi/shared-crypto`         | 351 passed |
| `@askmi/shared-types`          | 96 passed  |
| `@askmi/verifier-sdk`          | 62 passed  |
| `@askmi/wallet-core`           | 52 passed  |
| `@askmi/wallet-pwa`            | 289 passed |
| `@askmi/webauthn-verifier`     | 25 passed  |
| `verifier-backend`             | 296 passed |
| `verifier-frontend`            | 13 passed  |

## Dev start of the three apps

Started one at a time as filtered dev servers, as recommended, not via a full `pnpm dev`:

| App              | Command                                | Port | Startup log                                  | Probe                                                                                                                                |
| ---------------- | -------------------------------------- | ---- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| issuer-mock      | `pnpm --filter @askmi/issuer-mock dev` | 3005 | "Issuer Keys Ready (ECDSA P-256)", listening | `GET /health` → `{"status":"ok","keysReady":true}`; metadata has `credential_issuer`, `credential_endpoint`, `credentials_supported` |
| verifier-backend | `pnpm --filter verifier-backend dev`   | 3004 | "Pilot Verifier listening"                   | `GET /health` → `status: ok`; `POST /oid4vp-present` without a session → **400** (denied)                                            |
| wallet-pwa       | `pnpm --filter @askmi/wallet-pwa dev`  | 5174 | Vite 8.3.5 ready in 285 ms                   | `GET https://…:5174/` → 200, title "AskMI"; plain HTTP is not served                                                                 |

Privacy check on the public key endpoint: `GET /.well-known/jwks.json` returns one EC P-256 key
(`kid: key-1`) **without** the private parameter `d`.

All servers were stopped after the probes. The working tree stayed clean; the verifier's
`verifier-key.json` and `nonce-cache.json` are ignored by git.

## Observations (not fixed here)

- `wallet-pwa` Vite config warns about `__dirname` (use `import.meta.dirname`) and an extensionless
  import of `shared-types/src/askmi`. It builds and serves; this is a cleanup item.
- `wallet-pwa` build warns about chunk size.

## Scope and limits

- **Shown:** the code at `b00eb14` installs from the lockfile and builds. All test suites outside
  `poc-hardened` pass, lint has no errors, and the three apps start and answer basic requests,
  including one fail-closed denial.
- **Not shown:**
  - **Credential flow:** the real flow of issuing a credential, presenting it from the wallet and
    verifying it was not re-run; see [ADOPT-0a/0b, 2026-07-17](ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md).
  - **Browser smoke check:** `pnpm demo:smoke` was not run. It needs `pnpm demo` and a Chrome
    channel that this container does not have.
  - **Excluded package and images:** `@askmi/poc-hardened` is excluded from the root scripts.
    Docker images were not built.
- **Not a release claim:** this is not a clean-checkout RC report (Wave 1 exit evidence),
  conformance result or release-readiness claim. Product goals and open acceptance criteria in
  [BACKLOG](../BACKLOG.md) and the [release roadmap](../RELEASE_READINESS_ROADMAP.md) are unchanged.
