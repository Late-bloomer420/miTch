# 51 — RP #1 Onboarding Pack

Stand: 2026-02-11

## 1) Goal
Enable a relying party (RP) to reach first successful verification quickly and safely.

## 2) Prerequisites
- Verifier running (`npm start`)
- Auth enabled:
  - `AUTH_TOKEN_REQUIRED=1`
  - `AUTH_TOKEN=<token>`
- Audience aligned:
  - `RUNTIME_AUDIENCE=rp.example`

## 3) Endpoints
- `POST /verify` (auth required)
- `GET /health`
- `GET /metrics`, `GET /kpi` (if metrics enabled)

## 4) Minimal request contract (v0)
Fields required:
- `version`, `requestId`, `rp.id`, `rp.audience`, `purpose`, `claims[]`, `proofBundle`, `binding`, `policyRef`

## 5) First-success checklist
1. Send authenticated request with matching audience.
2. Ensure hash/binding values are valid.
3. Ensure key resolver can resolve active key.
4. Confirm response decision + receiptRef.
5. Confirm event in metrics/kpi.

## 6) Common failure mapping
- `DENY_BINDING_AUDIENCE_MISMATCH` -> wrong audience
- `DENY_BINDING_HASH_MISMATCH` -> canonicalization/hash mismatch
- `DENY_CRYPTO_KEY_STATUS_INVALID` -> revoked/missing key
- `DENY_RATE_LIMIT_EXCEEDED` -> request burst exceeded limits
- `DENY_SCHEMA_*` -> contract mismatch
