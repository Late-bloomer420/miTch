# DECISION-004: User Consent UX

**Date:** 2026-02-20  
**Status:** Accepted  
**Scope:** Phase 0–1

---

## Summary

Three-tier consent model (legal/service/optional). No dark patterns. Decline consequences always visible. Equal-weight approve/decline buttons. Consent receipts logged locally. Verifiers must register claim requirements with justification.

---

## GDPR Consent Requirements

1. **Informed** — user understands what's being shared
2. **Specific** — per-claim, not blanket
3. **Freely given** — real ability to say no
4. **Revocable** — can withdraw later
5. **Minimal** — only show what's relevant

---

## Three-Tier Requirement Model

### Tier 1: Legally Required
- Must cite the actual law/regulation (e.g., JuSchG §2)
- miTch validates the legal basis
- Decline button is equal-sized, states real consequence ("Purchase cannot proceed")
- No guilt-tripping, no friction on decline

### Tier 2: Service-Required
- Clear visual separation from optional claims
- Each claim explains what it enables, not why verifier wants it
- Specific decline consequence ("Cannot book appointment")

### Tier 3: Nice-to-Have (Optional)
- ALL unchecked by default
- Primary button is "Continue without sharing"
- No "share all" shortcut

---

## Anti-Dark-Pattern Rules

| Anti-Pattern | miTch Alternative |
|---|---|
| Wall of legal text | Plain language, 1 sentence |
| Pre-checked optional claims | Optional = unchecked by default |
| "Accept all" as primary button | Equal-weight Approve/Decline |
| No undo | Consent log with revoke button |
| Consent fatigue (ask every time) | Remember preference per verifier (Phase 1) |

---

## Verifier Policy Registration

Verifiers declare requirements upfront with justification. Wallet rejects requests that don't match registered policy.

```typescript
interface VerifierClaimRequest {
  claim: string;
  tier: "legal" | "service" | "optional";
  legalBasis?: { regulation: string; jurisdiction: string; article?: string; };
  serviceBasis?: { reason: string; consequenceIfDeclined: string; };
  userFacingDescription: string;
  declineConsequence: string;
}
```

**Enforcement:** Wallet rejects claims not in the verifier's registered policy. A verifier can't suddenly ask for `full_name` if their policy only covers `over_18`.

---

## Dark Pattern Detection (Phase 1+)

Wallet flags suspicious verifier behavior:
- Excessive claims (>5 for a simple service)
- Inflated requirements (>80% marked "required")
- Jurisdiction mismatch
- Scope creep (changed requirements since registration)

Warning shown to user with option to decline or review.

---

## Consent Memory (Phase 1)

- Only for exact same verifier + exact same claims
- Time-limited (session / 30 / 90 days, user picks)
- Visible in consent log, revocable
- New claims from same verifier = full consent screen again

---

## Consent Receipts (Local Logging)

### Data Model

```typescript
interface ConsentReceipt {
  id: string;
  version: "v0";
  action: "presented" | "declined" | "partial";
  verifier: { id: string; name: string; policyRef: string; };
  claims: { name: string; tier: string; disclosed: boolean; }[];
  timestamp: number;
  evidence: { requestHash: string; responseHash: string; nonce: string; };
  consent: { remembered: boolean; expiresAt?: number; revokedAt?: number; };
}
```

**Critical rule:** Receipts never contain actual PII. They log what *type* of thing was shared, not the value.

### Storage
- On-device only, encrypted in wallet secure storage
- Organized by month: `receipts/2026-02/receipt-*.json`
- Lightweight index for fast queries

### UI
- **Activity feed:** Color-coded (🟢 approved, 🟡 partial, 🔴 declined)
- **Detail view:** What was shared, what wasn't, receipt ID, hashes
- **Monthly summary:** X verifications, Y approved, Z denied, N unique services

### Retention
- Detailed receipts: 1 year
- Summary only: 5 years
- User can manually delete anytime

---

## Updated ConsentDecision Type

```typescript
// Upgrade from binary to granular
interface ConsentDecision {
  requestId: string;
  allowed: boolean;
  approvedClaims: string[];
  declinedClaims: string[];
  remembered: boolean;
  constraints?: { validUntil?: number; audience?: string; };
}
```

---

## Phase 0 Deliverables

1. Three-tier consent screen (legal/service/optional)
2. Multi-claim consent with checkboxes
3. Equal-weight approve/decline buttons
4. Decline consequences shown
5. Consent receipt creation + storage
6. Activity feed UI (read-only)
7. Verifier policy registration (basic)
8. Policy validation (reject unregistered claims)
