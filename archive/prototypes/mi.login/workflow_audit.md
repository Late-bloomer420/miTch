# miTch Workflow Integration Audit

## ✅ Completed Items

### Stage 1-8 Mapping
- [x] Stage 1: Request Intake → **WalletService.evaluateRequest()**
- [x] Stage 2: Verifier Identification → **fetchVerifierPublicKey() + resolveDID()**
- [x] Stage 3: Policy Evaluation → **PolicyEngine.evaluate()**
- [x] Stage 4: Verdict Handling → **PolicyEngine (returns Decision)**
- [x] Stage 5: Presence Binding → **WebAuthnService.provePresence()**
- [x] Stage 6: Proof Assembly → **WalletService.generatePresentation()**
- [x] Stage 7: Delivery → **EphemeralKey.encrypt() + sealToRecipient()**
- [x] Stage 8: Audit Entry → **AuditLog.append()**

### Invariants Encoded
- [x] Invariant 1: Request Integrity → **DecisionCapsule validation (lines 420-433)**
- [x] Invariant 2: Unknown Verifier → **PolicyEngine pattern matching**
- [x] Invariant 3: Claim Denial → **PolicyEngine deniedClaims check**
- [x] Invariant 4: Presence Requirement → **WebAuthn conditional (lines 453-459)**
- [x] Invariant 5: Issuer Trust → **PolicyEngine trustedIssuers validation**
- [x] Invariant 6: Replay Protection → **HardenedNonceStore.checkAndRegister()**
- [x] Invariant 7: Temporal Validity → **Nonce TTL (5 min default)**

### Never Events
- [x] No raw PII in ZKP → **evaluatePredicates() returns boolean results only**
- [x] No credential IDs → **T-36b: credentialId intentionally omitted (line 538)**
- [x] No cross-tracking → **Ephemeral keys + crypto-shredding (lines 645-656)**

## ⚠️ Gaps Identified

### 1. Missing: Explicit Consent Receipt Signing
**Workflow Requirement:**
```typescript
ConsentReceipt {
  action: 'GRANTED' | 'DENIED',
  scope: string[],
  timestamp: string,
  signature: string  // ← NOT IMPLEMENTED
}
```

**Current State:** PolicyEngine returns Decision, but no cryptographic binding of user consent

**Fix Required:** Add `signConsentReceipt()` method to bind user action

---

### 2. Missing: Purpose Validation
**Workflow Requirement:**
```
purpose MUST be non-empty (cannot be generic)
```

**Current State:** No validation in PolicyEngine that `purpose` is meaningful

**Fix Required:** Add purpose validation rule (e.g., reject "general use" or empty strings)

---

### 3. Missing: Credential Freshness Constraint
**Workflow Requirement:**
```
Evaluate credential freshness constraints
→ DENY with CREDENTIAL_EXPIRED
```

**Current State:** No check that credential `issuedAt` is within acceptable window

**Fix Required:** Add `maxCredentialAge` to PolicyRule

---

### 4. Missing: Network Status Context
**Workflow Requirement:**
```typescript
PolicyContext {
  networkStatus: 'online' | 'offline'
}
```

**Current State:** Not passed to PolicyEngine

**Fix Required:** Add `networkStatus` to `EvaluationContext`

---

### 5. Partial: Error Code Standardization
**Workflow Defines:**
- `INVALID_REQUEST`
- `VERIFIER_UNRESOLVABLE`
- `VERIFIER_NOT_ALLOWED`
- `CLAIM_DENIED`
- `ISSUER_NOT_TRUSTED`
- `CREDENTIAL_EXPIRED`
- `PRESENCE_REQUIRED`
- `USER_DENIED`
- `CONSENT_TIMEOUT`
- `REPLAY_DETECTED`
- `REQUEST_EXPIRED`

**Current State:** PolicyEngine returns reason codes, but NOT standardized across system

**Fix Required:** Create `ReasonCode` enum in `@mitch/shared-types`

---

### 6. Missing: Test Harness
**Workflow Requirement:**
```
Test harness for each fail-closed rule
```

**Current State:** Unit tests exist for PredicateEvaluator, but NOT for full workflow invariants

**Fix Required:** Create `workflow-invariants.test.ts` with scenarios:
- Missing verifier_id → DENY
- Expired credential → DENY
- Replay nonce → DENY
- etc.

---

## 📋 Recommended Actions

### Priority 1 (Security Critical)
1. **Implement Consent Receipt Signing**
   - Location: `WalletService.handleAction()` for `OVERRIDE_WITH_CONSENT`
   - Use: `signData()` to bind user action cryptographically

2. **Standardize Error Codes**
   - Create: `packages/shared-types/src/error-codes.ts`
   - Export: `ReasonCode` enum matching workflow spec

3. **Add Credential Freshness Check**
   - Update: `PolicyEngine.evaluate()` to validate `issuedAt`
   - Use: `maxCredentialAge` from PolicyRule

### Priority 2 (Compliance)
4. **Purpose Validation**
   - Add: `validatePurpose()` utility in PolicyEngine
   - Reject: Generic/empty purpose strings

5. **Network Context**
   - Update: `EvaluationContext` type to include `networkStatus`
   - Pass: From request metadata

### Priority 3 (Testing)
6. **Workflow Invariant Tests**
   - Create: End-to-end test suite for all 7 invariants
   - Use: Real PolicyEngine + mocked storage

---

## 🎯 Completeness Score

| Category | Score | Notes |
|----------|-------|-------|
| Stage Mapping | 8/8 ✅ | All stages implemented |
| Invariants | 5/7 ⚠️ | Missing purpose + freshness |
| Never Events | 3/3 ✅ | All enforced |
| Artifacts | 5/6 ⚠️ | Missing ConsentReceipt signature |
| Error Codes | 0/1 ❌ | Not standardized |
| Tests | 2/8 ❌ | Only unit tests, no E2E |

**Overall: 23/33 (70%)**

---

## 🔧 Implementation Roadmap

### Week 1: Critical Fixes
- [ ] T-85: Standardize error codes (`ReasonCode` enum)
- [ ] T-86: Credential freshness validation
- [ ] T-87: Consent receipt signing

### Week 2: Compliance
- [ ] T-88: Purpose validation
- [ ] T-89: Network context integration

### Week 3: Testing
- [ ] T-90: Workflow invariant test suite
- [ ] T-91: Integration test harness
- [ ] T-92: Compliance report generator

