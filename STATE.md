# STATE.md — Current Operating State

**Date:** 2026-03-04  
**Branch:** `consolidation`  
**Repo:** `https://github.com/Late-bloomer420/miTch.git` (also mirrored at `mitch-temp.git`)

---

## Current Phase

Post-consolidation. The 7→1 repo merge is complete. Now closing **P0 gaps** needed for a pilot.

## What's Done

- ✅ Monorepo structure: 22 packages + 3 apps, clean DAG, no circular deps
- ✅ Policy engine with layer-aware evaluation (Layer 0/1/2)
- ✅ SD-JWT VC credential stack
- ✅ Predicate proofs (hash-based, not ZKP)
- ✅ Crypto-shredding primitives
- ✅ Audit log with hash-chain
- ✅ Wallet PWA shell
- ✅ E2E demo flow (liquor store)
- ✅ Layered documentation structure (docs/00–05)
- ✅ Basic revocation deny list (REVOKED_CREDENTIAL_IDS)

## P0 — TODO for Pilot

- [ ] **G-01:** DID resolution + signature verification (stubs only today)
- [ ] **G-02:** Credential revocation — StatusList2021 runtime enforcement
- [ ] **G-03:** Policy engine — deterministic conflict resolution + deny reason codes
- [ ] **G-04:** Presentation binding & anti-replay (nonce TTL, canonicalization)
- [ ] **G-05:** eID issuer connector (at least 1 real or high-fidelity sim)
- [ ] **G-06:** Wallet credential persistence

**Critical path:** G-01 → G-04 → G-03 → G-02 → G-05 → G-06

## P1 — Should Fix for Pilot Quality

Key items: key lifecycle separation (G-07), JWE decryption (G-08), blockchain anchor stubs (G-09), WebAuthn in full flow (G-10), supply chain security (G-11), log redaction (G-15).

## Known Issues

- `policy-engine` depends on `mock-issuer` — layering violation, should be injected
- 6 orphan packages with no internal connections (may be dead code)
- No CI pipeline running
- `npm`/`kpi:check` references in old docs should be `pnpm`

## Batch-Close Checklist

- [ ] `pnpm test` green
- [ ] `pnpm build` clean
- [ ] Relevant docs updated
- [ ] Commit with clear message

---

Full gap tracker: see `consolidated-gaps.md` (31 gaps, P0–P3).
