# 29 — Implementation Scaffold (Code Start Blueprint)

Stand: 2026-02-11

## Ziel
Von Dokumentation zu implementierbarem MVP-Code mit klaren Modulen, Verantwortlichkeiten und Testeintritt.

---

## Proposed folder structure

```text
src/
  api/
    verifierRoutes.ts
    schemas/
      request.v0.schema.json
      response.v0.schema.json
  policy/
    evaluator.ts
    manifestLoader.ts
    denyCodeMapper.ts
  binding/
    canonicalize.ts
    requestHash.ts
    nonceStore.ts
    expiryValidator.ts
  proof/
    verifier.ts
    formats/
      sdjwtVerifier.ts
      fallbackAttestationVerifier.ts
  receipt/
    wormWriter.ts
    receiptModel.ts
  privacy/
    logRedaction.ts
    retentionGuard.ts
  config/
    policy.ts
    security.ts
  types/
    api.ts
    policy.ts
    decision.ts

tests/
  unit/
  integration/
  adversarial/
  vectors/
    canonicalization/
    binding/
```

---

## Module contracts (v0)

### policy/evaluator.ts
- Input: parsed request + policy manifest + binding status + proof status
- Output: `{ decision, decisionCode, claimsSatisfied }`
- Rule: fail closed on any uncertainty

### binding/canonicalize.ts
- Implements `20_Canonicalization_and_Binding_Spec_v0.md`
- Deterministic output required across runtimes

### binding/nonceStore.ts
- Atomic consume semantics
- TTL enforcement
- Replay detection reason code mapping

### api/verifierRoutes.ts
- Enforce gate precedence
- Convert internal errors to `DENY_INTERNAL_SAFE_FAILURE`

### receipt/wormWriter.ts
- Append-only decision receipt
- No raw PII in persisted records

---

## Implementation rules
- No implicit defaults for security-critical fields
- No untyped payload access in verification path
- Every deny path must map to catalog code (21)
- All config values must have safe defaults (deny-biased)

---

## Initial dependencies (minimal)
- JSON schema validator
- crypto utilities (SHA-256, signature verify)
- test runner + assertion library
- no heavy framework needed for v0
