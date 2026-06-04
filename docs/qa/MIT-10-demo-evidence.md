# MIT-10 — Local Demo Flow Re-run: QA Evidence

**Issue:** MIT-10 — Re-run local demo flow on wallet 5174, verifier 3004, issuer 3005
**Tester:** QA Engineer (Paperclip agent, `claude_local`)
**Date:** 2026-05-25 (run ~08:16 UTC)
**Result:** ✅ **PASS** — all three services boot and the full OID4VP demo flow works end-to-end across all 5 scenarios.

## Environment

| Item | Value |
|---|---|
| OS | Windows 10 Pro 19045 |
| Node | v24.13.1 |
| pnpm | 9.15.9 |
| Vite (wallet) | 6.4.2 |
| Build state | All 26 `@askmi/*` workspace packages resolve to prebuilt `dist/` |

Services started via:
```bash
pnpm --filter '@askmi/issuer-mock' dev      # → http://localhost:3005
pnpm --filter 'verifier-backend' dev         # → http://localhost:3004
pnpm --filter '@askmi/wallet-pwa' dev        # → http://localhost:5174
```

## Steps & Results

### 1. Service health (all 200)

| Service | Port | Endpoint | Result |
|---|---|---|---|
| Issuer-Mock | 3005 | `GET /health` | ✅ `{"status":"ok","service":"issuer-mock","keysReady":true}` |
| Verifier-Backend | 3004 | `GET /health` | ✅ `{"status":"ok",...}` |
| Wallet-PWA | 5174 | `GET /` | ✅ 200, `<title>miTch Wallet</title>` |

### 2. Issuer — OID4VCI metadata & credential issuance

- `GET /.well-known/openid-credential-issuer` → ✅ advertises `AgeCredential` (jwt_vc_json, ES256) + `mDL` (mso_mdoc).
- `GET /.well-known/jwks.json` → ✅ returns EC P-256 signing key (`kid: key-1`, `use: sig`, `alg: ES256`).
- `POST /credential` → ✅ returns a signed JWT VC (`format: jwt_vc_json`). Server log: `✅ Credential Issued: urn:uuid:987ad768-...`.

### 3. Verifier — OID4VP authorization request

- `GET /authorize?scenario=liquor-store` → ✅ returns `authRequest` (response_type `vp_token`, client_id `did:mitch:verifier-liquor-store`, presentation_definition `pd-age-verification`) + fresh `nonce`.

### 4. Verifier — Full OID4VP presentation flow (`POST /wallet-present`)

Runs the full protocol server-side: issue SD-JWT VC → build KB-JWT → validate → session cleanup, with selective disclosure.

| Scenario | HTTP | Outcome | Disclosed claims | Pass/Fail |
|---|---|---|---|---|
| `liquor-store` | 200 | SUCCESS | `age` only | ✅ minimal disclosure (no name/address/nationalId) |
| `doctor-login` | 200 | SUCCESS | `age, role, licenseId` | ✅ withheld `salary`, `homeAddress` |
| `ehds-er` | 200 | SUCCESS | `bloodGroup, allergies, emergencyContacts` | ✅ withheld `diagnosis`, `geneticData`, `insuranceId` |
| `pharmacy` | 200 | SUCCESS | `medication, dosageInstruction, refillsRemaining` | ✅ withheld `diagnosis`, `geneticData`, `insuranceId` |
| `revoked` | **403** | **DENIED** | — | ✅ fail-closed: `Credential revoked (status_list idx: 42)` |

Each success returned a `consentReceipt` + `auditEntry` with `claimsShared` matching exactly the disclosed claims — confirming the data-minimization / selective-disclosure design.

### 5. Verifier — state tracking, reset, metrics

- `GET /status` after the flow → reflected last presentation (`FAILED` after the revoked case).
- `POST /reset` → ✅ `{"ok":true}`; subsequent `GET /status` → `WAITING`, claims cleared.
- `GET /health` metrics → ✅ `oid4vp_success: 4, oid4vp_rejected: 1` — exactly 4 passes + 1 revocation denial.

### 6. Wallet PWA — boot & UI render

- Boots cleanly; console shows: `🔐 Initializing Wallet with Secure Storage`, `✨ Creating SESSION-SCOPED Identity Keypair (RAM only)`, seeds Employment / EHDS Patient Summary / EHDS Prescription / mdoc mDL credentials.
- Full UI rendered (screenshot `_qa_logs_mit10/wallet.png`): "miTch Smart Wallet" header, active credentials, "Prove Age & Forget", ZKP Age-Check panel, Download Signed Audit Report, Governance Settings (Block Unknown Verifiers, Deny Secondary Use EHDS, Third Country Block, Biometric Session Timeout), Trusted Issuers, and Demo Scenario buttons (Doctor Login / ER Access / Pharmacy).

## Pass/Fail Notes

- **PASS** — All 3 services start and respond on the expected ports (5174 / 3004 / 3005).
- **PASS** — Credential issuance, OID4VP authorization, presentation, status, reset all functional.
- **PASS** — Selective disclosure verified: only requested claims leave the wallet; sensitive fields withheld.
- **PASS** — Fail-closed verified: revoked credential is rejected with 403 + status-list reason.
- **PASS** — Verifier metrics counters match observed outcomes (4 success / 1 rejected).
- **Minor (non-blocking):** Wallet console logs one `404` for a static resource (favicon/manifest) and a benign CSP `frame-ancestors` meta warning. Neither affects the flow.

## Artifacts

- `_qa_logs_mit10/issuer.log` — issuer boot + issuance log
- `_qa_logs_mit10/verifier.log` — verifier boot + per-scenario OID4VP audit entries
- `_qa_logs_mit10/wallet.log` — Vite boot log
- `docs/qa/MIT-10-wallet.png` — full-page wallet UI screenshot (committed alongside this report)
