# DECISION-003: Revocation & Status Checking

**Date:** 2026-02-20  
**Status:** Accepted  
**Scope:** Phase 0

---

## Summary

Pre-issued credentials (SD-JWT, signed once) + `expiresAt` for natural expiry + StatusList2021 bitstring for early revocation. No online queries, ever. Existing `credentialStatus.ts` is 80% ready.

---

## Online Query vs Pre-Issued vs Hybrid

| Model | Privacy | Availability | Verdict |
|---|---|---|---|
| Online query (real-time) | Terrible (issuer sees every check) | Depends on issuer uptime | **Rejected** — breaks core promise |
| Pre-issued credential | Excellent (issuer has no idea when/where used) | Always works (local) | **Selected** (base) |
| Hybrid (pre-issued + status check) | Good if status check is private | Mostly offline | **Selected** (with StatusList2021) |

---

## StatusList2021 (Privacy-Preserving Revocation)

```
Issuer publishes a bitstring: 0000010000001000...
                                    ^           ^
                              credential #5   credential #12
                              (revoked)       (revoked)

Verifier downloads ENTIRE list → checks their credential's index locally.
Issuer can't tell which credential the verifier is checking.
```

### Privacy Properties
- Issuer sees: "someone downloaded the status list" (not which credential)
- Verifier sees: "credential #X is/isn't revoked" (no PII)
- User sees: nothing (not involved in the check)

---

## What Exists (credentialStatus.ts)

Already built and working:
- ✅ StatusList2021Entry validation
- ✅ Env-based revocation list (dev/testing)
- ✅ HTTP-based revocation fetch (production)
- ✅ Revoked-only caching (security-conservative)
- ✅ Cache TTL, max entries, pruning
- ✅ URL validation, response size limits, timeouts

---

## What's Missing

### 1. Bitstring Format
Current: JSON array of revoked IDs. Need: actual StatusList2021 compressed bitstring.

```typescript
interface StatusList2021 {
  id: string;
  type: "StatusList2021";
  encodedList: string;       // base64(gzip(bitstring))
  validUntil?: string;
}

function isRevoked(encodedList: string, index: number): boolean {
  const bits = ungzip(base64decode(encodedList));
  return (bits[Math.floor(index / 8)] >> (7 - (index % 8))) & 1 === 1;
}
```

### 2. Cache TTL Tiers

| Use Case | Cache TTL | Why |
|---|---|---|
| Age verification | 24h | Revocation rare, low risk |
| Employee access | 5 min | Termination should propagate fast |
| Financial auth | 60s | Fraud response needs speed |

### 3. Offline Fallback Policy

| Policy | Behavior | When |
|---|---|---|
| Fail-open | Accept if status check fails | Low-risk |
| Fail-closed | Reject if status check fails | High-risk |
| **Stale-accept** | Use last cached list | **Default** ✅ |

Normal: re-fetch every 5 min. If fetch fails: use cached list up to 24h old. If cache >24h: fail-closed.

### 4. Issuer-Side Publishing
`StatusListPublisher` for the mock issuer — ~80 lines.

---

## Anti-Correlation Measures

### StatusList2021 Threats + Mitigations

| Threat | Mitigation |
|---|---|
| Verifier-Issuer collusion (verifier shares index) | Verifier downloads whole list, can't prove which index checked |
| Timing attack (fetch right after revocation) | Cache aggressively, serve from CDN, many verifiers add noise |
| Verifier-Verifier linkability (same credential ID across presentations) | Per-session derived keyId via HMAC (see Decision 005) |

### Future Enhancement
- OHTTP (Oblivious HTTP, RFC 9458) for Phase 1 — strips verifier IP from status list fetch

---

## Phase 0 Action Items

1. Keep `credentialStatus.ts` verification logic
2. Add bitstring decoding (StatusList2021 format) — ~50 lines
3. Add `StatusListPublisher` to issuer-mock — ~80 lines
4. Add stale-accept fallback policy
5. Document cache TTL tiers
