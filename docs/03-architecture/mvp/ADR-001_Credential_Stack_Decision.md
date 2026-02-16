# ADR-001 — Credential/Proof Stack Decision

**Status:** ACCEPTED
**Date:** 2026-02-16
**Owner:** Architecture Lead
**Decision:** SD-JWT VC als Primary Stack für MVP

## Context

miTch benötigt einen Credential-Stack der:
- W3C VC kompatibel ist (eIDAS 2.0)
- Selective Disclosure nativ unterstützt
- ZK-Predicates ermöglicht (isOver18 ohne birthdate)
- Gute Library-Support hat

## Decision

**Primary Stack:** SD-JWT VC (Selective Disclosure JWT Verifiable Credentials)

**Libraries:**
- Issuer: `@sd-jwt/core` + `jose`
- Holder: `@sd-jwt/decode` + `@sd-jwt/present`
- Verifier: `@sd-jwt/verify` + `jose`

**Predicates für MVP:**
1. `isOver18` (boolean) - für Liquor Store Demo
2. `residencyCountry` (equality) - für regionale Services
3. `hasDriversLicense` (boolean) - für Car Rental

**Fallback:** Plain JWT mit manueller Selective Disclosure (wenn SD-JWT Library-Issues)

## Alternatives Considered

1. **BBS+ Signatures:** Zu komplex für MVP, schlechter Library-Support
2. **ZKCP (Zero-Knowledge Circuit Proofs):** Overkill, performance issues
3. **Plain JWT:** Kein Selective Disclosure out-of-the-box

## Consequences

✅ W3C Standard Compliance
✅ eIDAS 2.0 ready
✅ Interop mit existierenden eID-Issuern
⚠️ Library-Abhängigkeit (SD-JWT noch früh im Lifecycle)

## Acceptance Evidence

- [ ] 2 Test-Vektoren (issuance + verification)
- [ ] Interop-Test mit mindestens 1 real eID-Issuer-Simulator
- [ ] Performance: <100ms für Verify-Flow

## Implementation Notes

### SD-JWT Structure

```
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>
```

**Example Flow:**
1. Issuer creates JWT with hashed claims
2. User stores full JWT + disclosures
3. User selectively reveals only required disclosures to verifier
4. Verifier validates JWT + presented disclosures

### Security Properties

- **Unlinkability:** Different presentations cannot be correlated (different disclosure combinations)
- **Minimization:** Only required attributes revealed
- **Holder Binding:** Optional Key Binding JWT prevents presentation attacks

## References

- [SD-JWT Specification (IETF)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- [eIDAS 2.0 ARF](https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-architecture-and-reference-framework)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)

## Change Log

- 2026-02-16: Initial decision (ACCEPTED)
