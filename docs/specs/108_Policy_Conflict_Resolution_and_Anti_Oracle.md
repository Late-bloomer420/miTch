# 108 — Policy Conflict Resolution & Anti-Oracle Deny Codes (Normative v1)

Stand: 2026-03-04
Status: DRAFT → REVIEW
Blocking: Phase 5 Pilot (P0)

---

## 1) Problem Statement

The policy engine lacks:
- **Deterministic conflict resolution** when multiple rules match a request
- **Versioned fail-closed behavior** for unknown policy schemas
- **Anti-oracle deny reason codes** that prevent verifiers from probing policy internals
- **Audience-split messaging** (user / verifier / audit) for all deny outcomes

Without these, a verifier can enumerate policy rules by observing different error responses (oracle attack), and conflicting rules can produce non-deterministic outcomes.

---

## 2) Conflict Resolution: Deny-Wins Precedence

### 2.1 Core Rule

When multiple policy rules match a request, the **most restrictive interpretation wins**:

1. If ANY matching rule produces DENY → final verdict is DENY
2. If no rule produces DENY but any produces PROMPT → final verdict is PROMPT
3. ALLOW only if ALL matching rules agree on ALLOW

This is the **deny-wins** strategy. It is the only strategy compatible with fail-closed design.

### 2.2 Determinism Requirements

- **Same inputs → same output.** No randomness, no time-of-day variance, no probabilistic evaluation.
- **Rule ordering is irrelevant.** The engine evaluates ALL matching rules and merges verdicts via deny-wins. Priority is used only for selecting the *primary* rule's metadata (matched rule ID, capsule fields), not for overriding deny decisions.
- **Unknown policy version → DENY.** If `policy.version` is not in the engine's known-versions set, the entire evaluation fails closed.
- **Missing policy → DENY.** A null/undefined policy manifest produces DENY with code `DENY_POLICY_MISSING`.

### 2.3 Layer Inheritance & Conflict

- A higher-layer rule (e.g., Layer 2) **cannot override** a lower-layer deny (Layer 0/1).
- Layer protections are cumulative (inherited). A Layer 1 DENY on a claim cannot be un-denied by a Layer 2 rule that allows it.
- Implementation: after merging all rule verdicts, re-check layer constraints. Any layer violation in ANY matched rule forces DENY.

### 2.4 Algorithm

```
function resolveConflict(verdicts: Verdict[]): Verdict {
  if (verdicts.length === 0) return DENY  // fail-closed
  if (verdicts.some(v => v === DENY)) return DENY
  if (verdicts.some(v => v === PROMPT)) return PROMPT
  return ALLOW
}
```

---

## 3) Anti-Oracle Deny Reason Codes

### 3.1 Design Principle

Deny responses must not leak policy internals. A verifier must not be able to distinguish between:
- "User doesn't exist"
- "Policy denied this request"
- "Credential expired"
- "Layer violation"

All of these produce the **same verifier-facing message**. Only the user and audit log see the real reason.

### 3.2 Audience Split

Each `DenyReasonCode` has three message tiers:

| Audience | Purpose | Oracle Risk |
|----------|---------|-------------|
| **User** | Helpful, actionable, privacy-safe | None (user owns the data) |
| **Verifier** | Generic, non-distinguishing | Minimized — same message for multiple codes |
| **Audit** | Full detail, compliance review | N/A (access-controlled) |

### 3.3 Verifier Message Buckets

To prevent oracle attacks, multiple deny codes map to the same verifier-facing message:

| Verifier Message | Codes Mapped |
|-----------------|-------------|
| `"Verification could not be completed."` | EXPIRED, REVOKED, POLICY_MISMATCH, LAYER_VIOLATION, UNKNOWN_VERIFIER, BINDING_FAILED, NO_MATCHING_RULE, CREDENTIAL_TOO_OLD, UNTRUSTED_ISSUER, NO_SUITABLE_CREDENTIAL |
| `"Request rate exceeded."` | RATE_LIMIT_EXCEEDED |
| `"User action required."` | CONSENT_REQUIRED, PRESENCE_REQUIRED |

The first bucket is intentionally large — it is the "black hole" that absorbs all policy-distinguishing denials.

### 3.4 Timing Oracle Mitigation

**Requirement:** All DENY paths must execute in approximately constant time relative to ALLOW paths.

Implementation options (in order of preference):
1. **Constant-time padding:** Add artificial delay so all paths take `max(observed_time, FLOOR_MS)`
2. **Async batching:** Queue responses and flush on fixed intervals
3. **Documentation-only (MVP):** Document the requirement, measure in tests, enforce in Phase 6

For Phase 5 pilot: Option 3 (document + measure). Add `processingTimeMs` to test assertions to detect obvious timing leaks.

---

## 4) Versioned Policy Schema

### 4.1 Known Versions

The engine maintains a set of known policy schema versions. Evaluation against an unknown version is rejected:

```typescript
const KNOWN_POLICY_VERSIONS = new Set(['1.0.0', '1.1.0']);

if (!KNOWN_POLICY_VERSIONS.has(policy.version)) {
  return DENY with DENY_POLICY_UNSUPPORTED_VERSION
}
```

### 4.2 Version Compatibility

- Patch versions (1.0.x) are forward-compatible within the same minor
- Minor versions (1.x.0) may add fields but not remove them
- Major versions (x.0.0) are breaking — old engine rejects new major

---

## 5) Integration with Existing Catalog (Spec 21)

This spec extends spec 21 by adding:
- Audience-split messages to each code
- The `DenyReasonCode` enum in TypeScript (previously only documented)
- Anti-oracle bucketing logic
- Conflict resolution algorithm

Spec 21 codes remain canonical. New codes added here:
- `DENY_POLICY_MISSING` — no policy manifest provided
- `DENY_CONFLICT_RESOLUTION` — multiple rules conflict, deny-wins applied

---

## 6) Test Requirements

See `policy-engine/src/__tests__/determinism.test.ts` and `anti-oracle.test.ts`.

---

## 7) Change Control

Per spec 21 §5: new codes require ADR reference and version update. This spec serves as the ADR for codes added in §5.
