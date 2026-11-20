# Follow-up review of the 2026-11-03 API/protocol audit — 2026-11-20

**Tracks:** #299 (standalone review of the audit that landed via #247).
**Follows:** [`API_AUDIT_REVIEW_2026-11-18.md`](API_AUDIT_REVIEW_2026-11-18.md) (checked at `d7f0e77`). That record stays
unchanged; this one re-checks every finding at a newer revision and records what changed in between.
**Reviewed:** [`API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](API_PROTOCOL_REALITY_AUDIT_2026-11-03.md) (`API-01`..`API-07`).
**Revision checked:** `master` @ `8dd7f3e`.
**Method:** static source reading with file/line references, plus `git diff --stat d7f0e77 HEAD` over the audited files
and `git log -S` to attribute each change to a merged PR. No tests, builds or runtime checks were run. This is not a
security PASS, and it changes no finding, gate or matrix status. The audit record stays unchanged (dated evidence is immutable).

## 1. Which audited files changed since `d7f0e77`

Changed: `wallet-pwa/src/App.tsx`, `wallet-pwa/src/services/WalletService.ts`, `issuer-mock/src/index.ts`,
`shared-crypto/src/sd-jwt-vc.ts`, `shared-crypto/src/trust-list-resolver.ts`.
Also touched by merged PRs outside that `diff --stat` list: `shared-types/src/askmi.ts`, `wallet-pwa/src/utils/connect-handoff.ts`.

**Not changed** (so the 2026-11-18 result carries over for them): `oid4vp-verifier/src/response-verifier.ts`,
`mdoc/src/device-auth.ts`, `webauthn-verifier/src/index.ts`, `revocation-statuslist/src/index.ts`,
`oid4vci/src/index.ts`, `oid4vp/src/haip.ts`, `wallet-pwa/src/data/DemoPolicy.ts`, `connect/src/core/profile.ts`.

## 2. Findings at `8dd7f3e`

| ID | Status at `8dd7f3e` | Evidence | Closed/changed by |
|---|---|---|---|
| API-01.1 HTTPS wallet vs HTTP default | **closed** (default) | `shared-types/src/askmi.ts:28-30` `askmiDevWalletUrl()` derives scheme from `ASKMI_DEV_HTTPS`; `verifier-demo/backend/src/app.ts:501` uses it. `dev-demo.sh`/`dev-demo.ps1` no longer contain the literal `5174`. Their CORS configuration was **not** re-read in this pass | #265 |
| API-01.2 handoff without `demo=wallet` | **closed** on the Connect path | `wallet-pwa/src/App.tsx:2525` shows `<WalletApp />` when `isWalletDeepLink()`; `connect-handoff.ts:9-13` accepts `request_uri`; `connect/src/core/verifier.ts:229` sets `requestUri`; `connect/src/browser/handoff.ts:44` forwards it. The helper still omits `demo=wallet`, which is no longer needed | #265 (per `git log -S request_uri`) |
| API-01.3 `DENY` on `$.age` (`liquor-store`) | **still present** | `connect/src/core/profile.ts:27` requests `$.age`; `DemoPolicy.ts:73-75` `allowedClaims: []`, `provenClaims: ['age >= 18']`. Neither file changed | — |
| API-01.4 `iss` mismatch | **still present** | `issuer-mock/src/index.ts:49` `did:web:localhost%3A3005`; `verifier-demo/backend/src/app.ts:54` `process.env.ISSUER_DID \|\| ASKMI_DEMO.issuerUri`. `issuer-mock` changed (7 lines) but the constant did not | — |
| API-02 disclosure clipping (P0) | **still present** | `wallet-pwa/src/App.tsx:997-999` `requestedClaimNames` from `presentation_definition`, passed to `presentStoredSdJwtVc` at `:1006`. `authorized_requirements` is read at `:1849`, not on this path. Lines moved from `959-961` | — |
| API-03a `typ`/`alg` not enforced | **still present** | `shared-crypto/src/sd-jwt-vc.ts:150-152` `jwtVerify(jwtPart, key, { clockTolerance })`, no `typ`/`algorithms` | — |
| API-03b unmatched/malformed disclosures skipped | **closed on the verifier path** | `extractDisclosedClaimsStrict` (`sd-jwt-vc.ts:405`) rejects malformed, unmatched and duplicate disclosures; used at `oid4vp/src/demo-flow.ts:430`. The audited function `extractDisclosedClaims` no longer exists in `sd-jwt-vc.ts`. **Residual:** the holder-side presentation builder still `continue`s on an undecodable *stored* disclosure (`sd-jwt-vc.ts:477`) | #288 |
| API-03c `~~` for zero disclosures | **closed** | `sd-jwt-vc.ts:485` `selected.length > 0 ? …~ : \`${issuerJwt}~\``, then the KB-JWT is appended | #288 (per `git log -S`) |
| API-03d KB-JWT optional | **still present, not on the active path** | `oid4vp-verifier/src/response-verifier.ts:197` checks the KB-JWT only if the last segment is a compact JWT; `verifyCredentialSignatures` stays opt-in. File unchanged. No importer in `verifier-demo`, `wallet-pwa` or `connect` found; `packages/evidence/src/manifest.ts` references the package | — |
| API-04 mdoc DeviceAuth | **still present** | `mdoc/src/device-auth.ts:44-49` `externalAad = encode(sessionTranscript)`; detached payload rejected at `:58`. File unchanged | — |
| API-05a trust list without anchor key | **closed outside explicit dev mode** | `trust-list-resolver.ts:54-55` `ASKMI_TRUST_MODE` defaults to `live`; `:183-184` missing anchor key throws `TSL_ANCHOR_KEY_MISSING` unless `dev`; `:191` unsigned list throws `TSL_SIGNATURE_MISSING`. **Residual:** `ASKMI_TRUST_MODE=dev` still accepts an unverified list (`:186`, with a console warning) | #276 |
| API-05b stale-cache grace for `high` | **closed** | `trust-list-resolver.ts:134` stale fallback only for `riskTier === 'low'` inside the grace window | #276 |
| API-05c status list unsigned | **still present** | `revocation-statuslist/src/index.ts` has no signature handling (grep for signature/verify/jwt finds nothing). File unchanged. Active path checks status only when the credential carries `status` (`demo-flow.ts:372`) | — (tracked #293) |
| API-05d server WebAuthn signature | **still present** | `webauthn-verifier/src/index.ts:129-168` checks challenge, origin and counter; the comment says "simplified"; no signature check, `rpIdHash` and flags are not read. File unchanged. Imported by `integration-tests` | — |
| API-06 `@sd-jwt/*` citation | **resolved** (unchanged) | see the 2026-11-18 record | #247 |
| API-07 pre-final protocol baseline | **still present** | no `dcql_query`, `response_uri`, `verifier_info` or `nonce_endpoint` in `src/**/*.ts`; `oid4vci/src/index.ts` still has `issueBatchCredential` (draft-13). Files unchanged | — |

Net change since the 2026-11-18 record: API-01.1, API-01.2, API-03b, API-03c, API-05a and API-05b moved from
"present" to closed (with the residuals above). The other findings are unchanged.

## 3. `EUDI_CIR_MATRIX.md` rows changed by `4397b2b`

All 16 rows are still 🟡. Rows whose cited location or description no longer matches `8dd7f3e`
(the matrix is **not** edited here):

- **2977-7** cites `extractDisclosedClaims` (`sd-jwt-vc.ts:404-418`) with `continue`; the strict replacement exists
  (#288). The 🟡 for this row needs an owner decision.
- **2982-11** cites `App.tsx:959-961` (now `:997-999`) and `sd-jwt-vc.ts:465` `~~` (closed by #288). The clipping part
  (API-02) is still open.

Rows whose cited files did not change since `d7f0e77` (2977-6, 2977-13, 2979-15, 2982-18) keep their 2026-11-18 result.
2982-16/17 cite `WalletService.ts`, which changed (26 lines); the symbols were not re-read in this pass.

## 4. Tracking

Open defects without a GitHub issue are unchanged from the 2026-11-18 record: API-02 (P0), API-03d, API-05d.
Issue creation stays an owner decision; this record opens none.
