# DECISION-001: Credential Format & Proof System

**Date:** 2026-02-20  
**Status:** Accepted  
**Scope:** Phase 0 foundation

---

## Summary

SD-JWT for Phase 0, BBS+ for Phase 1. Format-agnostic credential data model so the swap is painless.

---

## Options Evaluated

| Option | Privacy | Complexity | Ecosystem | Verdict |
|---|---|---|---|---|
| **SD-JWT VC** | Good (per-claim disclosure, no native ZK) | Low (~500 lines core) | Strong (eIDAS 2.0, IETF) | **Phase 0** ✅ |
| **BBS+ Signatures** | Excellent (unlinkable ZK proofs) | Medium (WASM lib in-browser) | Growing (Mattr, Spruce, EU exploring) | **Phase 1** |
| **ZK Circuits (Circom/snarkjs)** | Maximum | High (circuit design, trusted setup) | Niche (blockchain only) | Phase ∞ (if needed) |
| **AnonCreds** | Good | Medium | Dying (Hyperledger) | Rejected |

---

## Decision: SD-JWT Now, BBS+ Next

### Why SD-JWT First
- Time to working MVP: days, not weeks
- Browser/PWA friendly: native JS, no WASM
- EU regulatory alignment: eIDAS 2.0 Architecture Reference Framework
- Jonas can follow and learn the code
- Slots directly into existing `ProofBundleV0.format` field

### Known Gap (Accepted)
- SD-JWT has a **correlation vector**: same issuer signature across presentations. Colluding verifiers can compare signatures.
- **Mitigation for Phase 0:** Per-session derived keyIds (HMAC), short-lived credentials
- **Closed in Phase 1:** BBS+ produces cryptographically unlinkable proofs

### Architecture Requirement
- Credential data model MUST be format-agnostic (claims array, not JWT-specific)
- `ProofBundleV0.format`: `"sd-jwt"` now, `"bbs"` later
- Verifier dispatches on format (already does this with `alg`)
- Wallet stores credentials in normalized form, not raw JWTs

---

## Trade-offs: Verifier Complexity vs Privacy vs Ecosystem

```
        Privacy (max)
           /\
          /  \
    BBS+ /    \ ZK Circuits
        /      \
       /________\
  Simple          Adopted
  (SD-JWT)        (SD-JWT)
```

SD-JWT wins simplicity + adoption. BBS+ wins privacy. For miTch's core promise ("structurally cannot know anything"), BBS+ is the long-term target. SD-JWT gets us running fastest without architectural lock-in.

### Per Use-Case Recommendation

| Use Case | Right Tool | Why |
|---|---|---|
| Age gate at a webshop | SD-JWT | Issuer pre-signs `over_18: true`, done |
| Health data (Layer 2) | BBS+ | Patient must selectively disclose without issuer predicting every query |
| Multi-party proofs | ZK circuits | Complex cross-credential logic |
| Auditor/regulator demo | SD-JWT | They understand JWTs |

---

## Phase 0 Deliverables

1. SD-JWT credential type definition
2. Issuer module (sign credentials with pre-computed predicates)
3. Updated `ProofEngine` for real selective disclosure
4. Compatible with existing verification flow
