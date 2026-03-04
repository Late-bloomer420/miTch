# DECISION-002: Issuer Integration Boundary

**Date:** 2026-02-20  
**Status:** Accepted  
**Scope:** Phase 0 foundation

---

## Summary

Model B: Adapter layer. miTch defines the credential format and adapter interface. External issuers (eID, banks, government) plug in via adapters. On-device derivation (Pattern C) for Phase 0 — works with existing state provider APIs without requiring their cooperation.

---

## Models Evaluated

| Model | Description | Verdict |
|---|---|---|
| A: miTch IS the issuer | Self-contained, but who trusts it? | Mock/demo only |
| **B: miTch wraps external issuers** | Adapter layer, miTch defines format | **Selected** ✅ |
| C: miTch is purely wallet/verifier | Accepts external VCs, least control | Can't enforce privacy guarantees |

---

## How State Providers Expose Proofs Without Exporting Raw PII

### Three Patterns

| Pattern | State Provider Changes? | Privacy | Phase |
|---|---|---|---|
| A: Issuer-side predicates (provider computes predicates internally) | Yes (new API) | High | Future |
| B: Blind issuance (BBS+ blind signatures) | Yes (crypto upgrade) | Maximum | Far future |
| **C: On-device derivation** | **No** | **High** | **Phase 0** ⭐ |

### Pattern C Flow (Selected)

```
User authenticates with State Provider (standard eID flow)
  → State Provider returns raw PII (as they do today)
  → PII lands in miTch Wallet (sandboxed, encrypted)
  → Wallet LOCALLY computes predicates (birthdate → over_18: true)
  → Wallet requests miTch Issuer to sign the predicates
     (issuer sees predicates ONLY, not raw data)
  → Raw PII crypto-shredded from wallet
  → Only signed predicate credential remains
```

### Trust Chain

```
State Provider (trusted root)
  → authenticates user, provides evidence token
miTch Issuer (trusted intermediary)
  → verifies evidence token is real + recent
  → receives ONLY predicates from wallet
  → signs predicate credential
Verifier
  → checks miTch Issuer signature
  → checks evidence reference points to real state provider
```

The issuer doesn't see raw PII. But it verifies the user actually authenticated with the state provider.

---

## Adapter Interface

```typescript
interface IssuerAdapter {
  credentialTypes: string[];  // ["age_verification", "email_verified"]
  
  resolveClaims(
    userId: string, 
    requestedClaims: string[]
  ): Promise<ResolvedClaims>;
  
  issuerMetadata(): IssuerMeta;
}

interface ResolvedClaims {
  claims: Record<string, unknown>;     // empty for Pattern C (no raw PII crosses boundary)
  predicates: Record<string, boolean>; // { over_18: true }
  evidence: string;                    // "eid-at:session:abc123"
}

interface IssuerMeta {
  id: string;             // "eid-austria"
  name: string;           // "Austrian eID Bridge"
  trustFramework: string; // "eIDAS_LOA_HIGH"
  publicKeyJwk: JsonWebKey;
}
```

---

## Phase 0 Deliverables

1. `IssuerAdapter` interface definition
2. Mock issuer adapter (wraps existing `issuer-mock/`)
3. On-device predicate derivation in wallet
4. Evidence token verification stub
