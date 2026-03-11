# miTch Architecture Refactoring Roadmap

> **Status:** Pre-Phase 6 Gate | **Last Updated:** 2026-01-27

## Executive Summary

This document describes the **architectural seams** for transitioning miTch from PoC to production-grade architecture. The current implementation reflects **conscious PoC consolidation** â€” deliberate trade-offs that prioritized speed-to-validation over separation of concerns.

These are **not violations**, but **intentional technical debt** with a clear repayment plan.

---

## 1. PoC Context: Conscious Consolidation

### Philosophy
The PoC phase prioritized:
- **Rapid iteration** on cryptographic primitives
- **End-to-end validation** of the Privacy Firewall concept
- **Stakeholder demos** with working, tangible flows

This led to **vertical slices** where components were tightly coupled for fast feedback. This was the right call for validation, but must be addressed before scaling.

### Framing (for Reviews)
| Current State | Interpretation |
|---------------|----------------|
| "God Object" in WalletService | *Conscious PoC consolidation; orchestration logic mixed with domain logic for demo velocity* |
| Crypto + Storage mixed | *Deliberate boundary collapse to accelerate PoC; Phase 6 separates via adapters* |
| Linear rule matching | *Sufficient for <100 rules; indexing deferred to production scale* |

**Key Message:** These are not "violations" to apologize for â€” they are documented decisions with explicit remediation paths.

---

## 2. WalletService Decomposition: Seam Interfaces

### Current State
`WalletService` (~700 LOC) is a **monolithic orchestrator** that:
- Manages credentials
- Evaluates policies
- Generates presentations
- Handles audit logging
- Manages crypto keys

### Target Architecture (Facade Pattern)

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                        WalletService                            â”‚
â”‚                    (Orchestrator / Facade)                      â”‚
â”‚                         ~150 LOC                                â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚              â”‚              â”‚              â”‚
         â–¼              â–¼              â–¼              â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ ICredential â”‚  â”‚   IPolicy   â”‚  â”‚IPresentationâ”‚  â”‚  IAudit     â”‚
â”‚ Repository  â”‚  â”‚  Evaluator  â”‚  â”‚  Manager    â”‚  â”‚  Trail      â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Seam Interfaces (Incremental Extraction)

#### 2.1 `ICredentialRepository`
```typescript
interface ICredentialRepository {
  getAllMetadata(): Promise<StoredCredentialMetadata[]>;
  load<T>(id: string): Promise<T | null>;
  loadSelectiveClaims<T>(id: string, claims: string[]): Promise<Partial<T> | null>;
  save(id: string, data: unknown, metadata: Omit<StoredCredentialMetadata, 'id'>): Promise<void>;
  delete(id: string): Promise<void>;
}
```

#### 2.2 `IPolicyEvaluator`
```typescript
interface IPolicyEvaluator {
  evaluate(
    request: VerifierRequest,
    context: EvaluationContext,
    credentials: StoredCredentialMetadata[],
    policy: PolicyManifest
  ): Promise<PolicyEvaluationResult>;
  
  getRiskScore(verifierId: string): number;
}
```

#### 2.3 `IPresentationManager`
```typescript
interface IPresentationManager {
  generatePresentation(
    capsule: DecisionCapsule,
    credentials: ICredentialRepository,
    targetKey?: CryptoKey
  ): Promise<{ encryptedVp: string; auditLog: string[] }>;
}
```

#### 2.4 `IAuditTrail`
```typescript
interface IAuditTrail {
  append(event: AuditEventType, subject: string, metadata?: Record<string, unknown>): Promise<void>;
  getRecentLogs(): Promise<AuditLogEntry[]>;
  verifyChain(): Promise<ChainVerificationResult>;
  syncToL2(): Promise<L2Receipt>;
}
```

### Migration Path (No Big-Bang)
1. **Phase 6a:** Extract `ICredentialRepository` interface; `SecureStorage` implements it.
2. **Phase 6b:** Extract `IPolicyEvaluator`; `PolicyEngine` implements it (already close).
3. **Phase 6c:** Extract `IPresentationManager` from `generatePresentation()`.
4. **Phase 6d:** `WalletService` becomes pure facade; all domain logic delegated.

---

## 3. SecureStorage: Adapter + Crypto Boundary

### Current State
`SecureStorage` mixes:
- **Persistence** (IndexedDB operations)
- **Encryption** (AES-GCM via shared-crypto)
- **Serialization** (JSON stringify/parse)

### Target Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                      SecureStorage                              â”‚
â”‚                   (Composition Root)                            â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚                              â”‚
         â–¼                              â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚   IStorageAdapter   â”‚      â”‚    IEnvelopeCrypto      â”‚
â”‚   (Persistence)     â”‚      â”‚    (Crypto Boundary)    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜      â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚                              â”‚
         â–¼                              â–¼
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ IndexedDB  â”‚                â”‚ encrypt/decryptâ”‚
  â”‚ Adapter    â”‚                â”‚ key management â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤                â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
  â”‚ InMemory   â”‚ (testing)
  â”‚ Adapter    â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
  â”‚ ReactNativeâ”‚ (mobile)
  â”‚ Adapter    â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Interface Definitions

#### 3.1 `IStorageAdapter`
```typescript
interface IStorageAdapter {
  // Store raw bytes (ciphertext blobs only)
  put(key: string, value: Uint8Array, indexTags: Record<string, string>): Promise<void>;
  get(key: string): Promise<Uint8Array | null>;
  delete(key: string): Promise<void>;
  list(): Promise<Array<{ key: string; indexTags: Record<string, string> }>>;
}
```

#### 3.2 `IEnvelopeCrypto`
```typescript
interface IEnvelopeCrypto {
  // Envelope encryption (data at rest)
  seal(plaintext: string, aad?: BufferSource): Promise<Uint8Array>;
  unseal(ciphertext: Uint8Array, aad?: BufferSource): Promise<string>;
  
  // Key wrapping (data in transit)
  wrapKey(key: CryptoKey, recipientPubKey: CryptoKey): Promise<string>;
  
  // Key lifecycle
  shred(): void;
  isActive(): boolean;
}
```

### Portability Benefit
| Environment | IStorageAdapter | IEnvelopeCrypto |
|-------------|-----------------|-----------------|
| Browser PWA | IndexedDBAdapter | WebCrypto |
| React Native | AsyncStorageAdapter | react-native-keychain |
| Node.js (Tests) | InMemoryAdapter | node:crypto |
| TEE (Future) | SecureEnclaveAdapter | Hardware HSM |

---

## 4. PolicyEngine: Strategy Extension Point

### Current State
Credential selection is hardcoded to "first matching credential".

### Target Architecture

```typescript
interface ICredentialSelectionStrategy {
  select(
    candidates: StoredCredentialMetadata[],
    requirement: Requirement,
    context: EvaluationContext
  ): StoredCredentialMetadata | null;
}

// Initial implementation (current behavior)
class DefaultSelectionStrategy implements ICredentialSelectionStrategy {
  select(candidates, requirement, context) {
    return candidates[0] || null;
  }
}

// Future: Privacy-first (prefer newest, least used)
class PrivacyFirstStrategy implements ICredentialSelectionStrategy { ... }

// Future: Reputation-first (prefer highest trust score)
class ReputationFirstStrategy implements ICredentialSelectionStrategy { ... }
```

### When To Introduce
> **Strategy Pattern as Extension Point, not Overengineering.**
> 
> Currently, `DefaultSelectionStrategy` is sufficient. The interface is defined as a **future extension point** for:
> - Multi-issuer environments (prefer trusted issuers)
> - Privacy optimization (rotate credentials to limit linkability)
> - Enterprise policies (reputation scoring)

**Decision:** Define interface now; implement additional strategies only when product requirements demand.

---

## 5. Refactoring Sprint: Phase 6 Gate

### Definition of Done (DoD)

| # | Criterion | Measurement | Status |
|---|-----------|-------------|--------|
| 1 | **WalletService LOC** | < 200 LOC (orchestration only) | â¬œ Pending |
| 2 | **Unit Tests without IndexedDB** | All `@mitch/secure-storage` tests run with InMemoryAdapter | â¬œ Pending |
| 3 | **Second Storage Adapter Exists** | `InMemoryStorageAdapter` implemented and tested | â¬œ Pending |
| 4 | **Policy Selection Swappable** | `ICredentialSelectionStrategy` interface defined; injectable | â¬œ Pending |
| 5 | **Public API Stability** | No breaking changes to `WalletService` public methods | âœ… Verified |

### Sprint Scope (Estimated: 3-5 days)

#### Day 1-2: Storage Decomposition
- [ ] Extract `IStorageAdapter` interface
- [ ] Implement `IndexedDBAdapter` (refactor existing)
- [ ] Implement `InMemoryAdapter` (for testing)
- [ ] Extract `IEnvelopeCrypto` interface

#### Day 3: Repository Pattern
- [ ] Define `ICredentialRepository`
- [ ] Refactor `SecureStorage` to implement it
- [ ] Update WalletService to use interface

#### Day 4: Policy Strategy
- [ ] Define `ICredentialSelectionStrategy`
- [ ] Implement `DefaultSelectionStrategy`
- [ ] Inject strategy into PolicyEngine

#### Day 5: Verification & Cleanup
- [ ] Run full test suite with InMemoryAdapter
- [ ] Verify WalletService < 200 LOC
- [ ] Update ARCHITECTURE.md

---

## 6. Risk Assessment

| Risk | Mitigation |
|------|------------|
| Breaking pilot integrations | Interface extraction preserves existing signatures; internal refactor only |
| Crypto boundary bugs | Extensive test coverage; no changes to algorithms, only structure |
| Over-abstraction | Start with 2 adapters (IndexedDB + InMemory); add more only as needed |

---

## Appendix: Code Quality Grades (PoC Context)

| Component | Current Grade | Reason | Phase 6 Target |
|-----------|---------------|--------|----------------|
| WalletService | B- | Conscious consolidation; orchestration + domain mixed | A (Facade only) |
| SecureStorage | B | Crypto + Persistence mixed for PoC velocity | A (Separated) |
| PolicyEngine | B+ | Close to SOLID; strategy extraction pending | A |
| AuditLog | A- | Already well-separated | A |

> **Note:** Grades reflect *current suitability for production*, not code quality per se. PoC consolidation was a deliberate trade-off that enabled rapid validation.

---

*Document maintained by: miTch Architecture Team*
*Next Review: Phase 6 Kickoff*
