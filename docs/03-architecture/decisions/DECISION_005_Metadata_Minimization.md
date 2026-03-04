# DECISION-005: Metadata Minimization

**Date:** 2026-02-20  
**Status:** Accepted  
**Scope:** Phase 0–2

---

## Summary

Even with perfect ZK proofs, metadata leaks (IP, timing, payload size, credential structure) can reveal identity. Layered mitigations: response padding, disclosure padding, timing jitter, identical decline/missing responses, stripped bundle fields. ~80 lines for Phase 0.

---

## Attack Surfaces

### Network Level
| Leak | Reveals | Mitigation |
|---|---|---|
| IP address | Location, ISP | Relay proxy (Phase 1) |
| TLS fingerprint | Device type, OS | Relay normalization (Phase 1) |
| Request timing | When user interacts | Timing jitter (Phase 0) |
| Packet size | Credential complexity | Response padding (Phase 0) |

### Protocol Level
| Leak | Reveals | Mitigation |
|---|---|---|
| Credential structure (hash count) | Number of claims | Dummy disclosure padding (Phase 0) |
| Issuer identifier | Demographics (nationality) | Issuer aliasing (Phase 2) |
| Response time | Device class | Timing jitter (Phase 0) |
| Error patterns | What user doesn't have | Identical decline/missing responses (Phase 0) |

### Behavioral Level
| Leak | Reveals | Mitigation |
|---|---|---|
| Verification frequency | Usage patterns | Per-session derived IDs (Phase 0) |
| Decline patterns | What user refuses | Identical decline responses (Phase 0) |

---

## Phase 0 Mitigations (~80 lines total)

### 1. Response Padding (every response = fixed 4KB)
```typescript
// Without: 127 bytes → "1 claim", 893 bytes → "6 claims"
// With: every response = 4096 bytes
function padResponse(data: Buffer, targetBytes: number = 4096): Buffer
```

### 2. Strip Unnecessary Bundle Fields
```typescript
function minimizePresentation(bundle: ProofBundleV0): ProofBundleV0 {
  return {
    format: bundle.format,
    proof: bundle.proof,
    disclosures: bundle.disclosures,
    keyId: bundle.keyId,           // session-derived, unlinkable
    credentialId: undefined,       // NEVER send
    credentialStatus: undefined,   // verifier checks status list themselves
    alg: undefined,                // verifier detects from format
  };
}
```

### 3. Identical Decline/Missing Responses
```typescript
// Verifier can't tell if user declined or doesn't have the credential
{ decision: "DENY", decisionCode: "not_available" }
// Same code for both cases
```

### 4. Dummy Disclosure Padding
```typescript
// Pad SD-JWT to always have 8 disclosure hashes
// Hides actual number of claims
function padDisclosures(real: string[], target: number = 8): string[]
```

### 5. Timing Jitter
```typescript
// 0-3 seconds random delay on every presentation
// Prevents timing correlation
async function presentWithJitter(proof: ProofBundleV0): Promise<void>
```

---

## Per-Session Unlinkable Identifiers

Never send the same keyId or credentialId twice.

```typescript
function deriveUnlinkablePresentation(
  credential: SDJWTCredential,
  verifierNonce: string
): ProofBundleV0 {
  const sessionId = hmac(credential.id, verifierNonce);
  return {
    format: "sd-jwt",
    proof: credential.presentWithDisclosure(requestedClaims),
    keyId: sessionId,          // unlinkable across verifiers
    credentialId: undefined,   // never exposed
  };
}
```

---

## Server-Side Logging Policy

### What IS Logged
- Aggregate metrics only: "47 verifications this hour"
- Error rates by type (no request details)
- System health (uptime, memory, latency percentiles)

### What is NEVER Logged
- IP addresses (not even hashed)
- User agents
- Request/response bodies
- Credential IDs, key IDs, verifier IDs
- Per-request timestamps
- Claim types

### Retention
- Aggregate metrics: 90 days
- Security events (no identifiers): 30 days
- Debug: in-memory ring buffer only, never persisted

### Code-Level Enforcement
```typescript
// safeLog wrapper strips banned fields before any logger touches them
// Deep scan for PII patterns — throws if detected
function safeLog(event: Record<string, unknown>): void
```

### Deployment Constraint
- No persistent log volume in containers
- Filesystem is read-only
- Aggregate metrics to in-memory Prometheus-style store

---

## Abuse Monitoring Without User Profiling

| Technique | What It Catches | Privacy Cost | Phase |
|---|---|---|---|
| Aggregate anomaly detection | DDoS, stuffing, replay waves | Zero | 0 |
| Blind rate limiting (HMAC tokens) | Per-user abuse without knowing user | Zero | 0 |
| Streaming counters (no-log alerting) | Threshold violations | Zero | 0 |
| Adaptive PoW challenges | Bot farms | Slight UX under attack | 1 |
| Cryptographic abuse tokens (hot list) | Replay attacks | Zero | 1 |
| Sealed audit envelopes | Legal compliance | Minimal (encrypted) | 1 |

### Blind Rate Limiting
Wallet generates `token = HMAC(credential.cnfKey, timeWindow)`. Server counts per token. Can't reverse token to identity. Token rotates each window — no cross-window tracking.

### What Cannot Be Caught (Accepted)
- Single sophisticated attacker making normal-looking requests
- Social engineering
- Compromised wallet on user's device

These are endpoint security problems, not infrastructure monitoring problems.

---

## Future Phases

| Mitigation | Phase |
|---|---|
| Relay proxy (strip IP/UA) | 1 |
| OHTTP (Oblivious HTTP) for status list fetches | 1 |
| Dummy/cover traffic | 2 |
| Issuer aliasing (hide nationality) | 2 |

---

## Minimization Checklist (For Every Field)

1. Does the verifier NEED this to verify the proof? No → strip it
2. Can it be generalized without breaking verification? Yes → generalize
3. Can its size/timing be normalized? Yes → pad/jitter
4. Does its ABSENCE leak information? Yes → send dummy value
