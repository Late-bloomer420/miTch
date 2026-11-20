# Review of the 2026-11-03 API/protocol audit — 2026-11-18

**Tracks:** #299 (standalone review that the closed split #280/#281 was meant to produce).
**Reviewed:** [`API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](API_PROTOCOL_REALITY_AUDIT_2026-11-03.md)
(`API-01`..`API-07`, executable base `002ce5e`) and the 16 `EUDI_CIR_MATRIX.md` rows changed
by `4397b2b`.
**Revision checked:** `master` @ `d7f0e77`.
**Method:** static source reading with file/line references. No tests, builds or runtime
checks were run for this record. This is not a security PASS, and it changes no finding,
gate or matrix status. The audit record itself stays unchanged (dated evidence is immutable);
corrections are recorded here.

## 1. Findings `API-01`..`API-07` at `d7f0e77`

"Active path" = code reached by the verifier-demo `POST /oid4vp-present` / Connect flow or the
wallet-pwa presentation flow. A package with no importer outside tests is marked as such.

| ID | Still present at `d7f0e77`? | Evidence | Active path? | Open PRs touching it | Tracked in |
|---|---|---|---|---|---|
| API-01.1 HTTPS wallet vs HTTP defaults/CORS | yes | `verifier-demo/backend/src/app.ts:492` default `http://localhost:5174`; `dev-demo.sh:85`, `dev-demo.ps1:39` CORS lists only `http://localhost:5174`; wallet serves HTTPS unless `ASKMI_DEV_HTTPS=0` (`wallet-pwa/vite.config.ts:6`) | demo | #265 | BACKLOG API-01, #170 |
| API-01.2 handoff without `demo=wallet` | yes | `wallet-pwa/src/App.tsx:2452-2466` renders the landing page unless `?demo=wallet` | demo | #277 (routes handoff params directly) | BACKLOG API-01, #170 |
| API-01.3 `DENY` on `$.age` for `liquor-store` | yes (configuration) | `wallet-pwa/src/data/DemoPolicy.ts:73-75` `allowedClaims: []`, `provenClaims: ['age >= 18']` | wallet | — | BACKLOG API-01 |
| API-01.4 `iss` mismatch issuer-mock vs verifier | yes | `issuer-mock/src/index.ts:48` `did:web:localhost%3A3005` vs `verifier-demo/backend/src/app.ts:52` default `ASKMI_DEMO.issuerUri` | demo | — | BACKLOG API-01 |
| API-02 disclosure clipping bypass (P0) | yes | `wallet-pwa/src/App.tsx:959-961` derives claim names from `presentation_definition`, not `authorized_requirements` | **yes** (wallet) | — | BACKLOG API-02 only, **no issue** |
| API-03a `typ`/`alg` not enforced | yes | `shared-crypto/src/sd-jwt-vc.ts:145-157`: `jwtVerify` without `typ`/`algorithms` options; the `typ` comment at `:156` has no check | yes | — | BACKLOG API-03 |
| API-03b unmatched/malformed disclosures skipped | yes on master | `sd-jwt-vc.ts:405,407` `continue` | yes (`oid4vp/src/demo-flow.ts:429`) | #288 (strict parser on that path) | #264 |
| API-03c `~~` for zero disclosures | yes | `sd-jwt-vc.ts:465` | holder side | — | BACKLOG API-03 |
| API-03d KB-JWT optional | yes, but see note | `oid4vp-verifier/src/response-verifier.ts:197` | **no**: `@askmi/oid4vp-verifier` is imported only by `integration-tests`; the active route requires `cnf.jwk` and a valid KB-JWT (`demo-flow.ts:388-402`) | — | BACKLOG API-03, **no issue** |
| API-04 mdoc DeviceAuth structure | yes | `mdoc/src/device-auth.ts:44-49` passes `encode(sessionTranscript)` as `externalAad`; `:58` fails closed on detached payload | no active mdoc route | — | #97, BACKLOG API-04 |
| API-05a trust list without anchor key | yes on master | `shared-crypto/src/trust-list-resolver.ts:38,159` | **yes** (`checkTrust: true`) | #276 | #240 |
| API-05b stale-cache grace for `high` | yes | `trust-list-resolver.ts:121` condition `low \|\| within grace` | yes | #276 | #240 |
| API-05c status list unsigned | yes | `revocation-statuslist/src/index.ts`: no signature verification in the resolver | yes, but skipped when the credential has no `status` (`demo-flow.ts:372`) | — | #293 |
| API-05d server WebAuthn assertion signature | yes, **wider than recorded** (see §3) | `webauthn-verifier/src/index.ts:129-168` | **no**: imported only by `integration-tests` | — | BACKLOG API-05, **no issue** |
| API-06 `@sd-jwt/*` citation | resolved on master | `docs/_core/03_ARCHITECTURE.md:12` states the in-house implementation | docs | — | BACKLOG API-06 ✅ |
| API-07 pre-final protocol baseline | yes | no `dcql_query` / `response_uri` / `verifier_info` in `src/`; `oid4vci/src/index.ts:112` `issueBatchCredential` (draft-13) | yes (protocol generation) | — | #97, BACKLOG API-07 |

No PR merged between `002ce5e` and `d7f0e77` closes any of these findings. #291 (merged)
adds a separate, non-official verifier profile and does not change them. Open PRs listed above
are proposals until merged.

## 2. `EUDI_CIR_MATRIX.md` rows changed by `4397b2b`

All 16 rows are 🟡 at `d7f0e77`: 2977-6, 2977-7, 2977-8, 2977-9, 2977-13, 2979-15, 2982-1,
2982-2, 2982-6, 2982-7, 2982-11, 2982-14, 2982-15, 2982-16, 2982-17, 2982-18.

For each row, the cited location was checked against `d7f0e77`. The described gap is still
present in every row; no row describes a gap that has since been closed. Line numbers in
2977-6 (`response-verifier.ts:197`), 2977-7 (`sd-jwt-vc.ts:404-418`), 2977-8
(`L145-157`), 2982-11 (`App.tsx:959-961`) and 2982-18 (`device-auth.ts:39-101`) still match.
2977-13 (`issueBatchCredential`), 2979-15 (`haip.ts:116,148`), 2982-16/17
(`WalletService.ts:2069,2158`) still match by symbol.

Rows 2977-6 and the KB-JWT part of the matrix describe `@askmi/oid4vp-verifier`, which is not on
the active route (§1, API-03d). The 🟡 stays correct; the row does not say which path is active.

## 3. Corrections to the audit record (not applied to it)

- **API-05d understates the gap.** The audit says server-side `verifyAssertion()` "checks
  challenge, origin, `rpIdHash`, flags, and sign counter". At `d7f0e77` (file unchanged since
  `efc6950`, 2026-06-11, so also at `002ce5e`) it checks challenge, origin and counter only;
  `rpIdHash` and flags appear only in a comment (`webauthn-verifier/src/index.ts:150`). The
  signature is not verified, as recorded.
- **API-03d and API-05d scope.** Both packages have no importer outside `integration-tests`
  (see also `docs/ARCHIVE_INVENTORY_2026-11-11.md` in #266). The defects are real in those
  packages but not reachable from the active verifier/wallet flow at `d7f0e77`.

## 4. Tracking gaps

Every finding has a `docs/BACKLOG.md` row (`API-01`..`API-07`) and a row in
`docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md`. Three open defects have **no GitHub issue**:

- **API-02** (P0, active wallet path) — highest priority of the three.
- **API-03d** (KB-JWT optional in `oid4vp-verifier`, not active).
- **API-05d** (no server-side WebAuthn signature check in `webauthn-verifier`, not active).

Whether to open issues for them, and whether inactive packages are fixed or archived (#266),
is an owner decision. This record opens none.
