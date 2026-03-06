# Spec 111 — Unlinkability Phase 1: Pairwise-Ephemeral DIDs

**Status:** DRAFT  
**Priority:** P0 (next phase)  
**Principle:** "Alle sind miTch"  
**Depends on:** G-01 (DID Resolution), G-04 (Anti-Replay), G-07 (Key Separation)

---

## Problem

Even with Selective Disclosure, a persistent DID or public key allows cross-session and cross-verifier tracking. Any cookie, SDK, or colluding verifier can correlate: "This is the same user again."

**Real-world example:** A user verifies age at a liquor store (Verifier A) and later at a pharmacy (Verifier B). If both see the same DID, they can collude to build a profile — even without knowing the user's name.

---

## Solution: Pairwise-Ephemeral DIDs

Every verification interaction uses a **fresh, unique DID** that is:
- Generated per-verifier, per-session
- Not resolvable by third parties
- Destroyed (shredded) after the interaction completes
- Cryptographically bound to the holder's master credential via ZKP or HKDF derivation

---

## Architecture

### 1. DID Generation (`did:peer` method)

```
Wallet                          Verifier
  │                                │
  │  ← Verification Request ───── │
  │                                │
  │  Generate ephemeral keypair    │
  │  Create did:peer from pubkey   │
  │  Derive session key via HKDF   │
  │                                │
  │  ── Proof + did:peer ────────→ │
  │                                │
  │  Shred ephemeral key material  │
  │                                │
```

### 2. Ephemeral Keypair per Interaction

Location: `@mitch/shared-crypto/src/pairwise-did.ts`

```typescript
interface PairwiseDIDOptions {
  /** Verifier identifier (used as HKDF context — NOT leaked) */
  verifierOrigin: string;
  /** Session nonce from verifier request */
  sessionNonce: string;
}

interface PairwiseDIDResult {
  /** Fresh did:peer for this interaction */
  did: string;
  /** Ephemeral signing key (for proof) */
  signingKey: EphemeralKey;
  /** Ephemeral encryption key (for response channel) */
  encryptionKey: EphemeralKey;
  /** Shred all key material */
  destroy(): void;
}

function generatePairwiseDID(options: PairwiseDIDOptions): Promise<PairwiseDIDResult>;
```

### 3. HKDF Derivation (Deterministic but Unlinkable)

```
Master Holder Key (never leaves wallet)
        │
        ▼
    HKDF-SHA256
    ├── salt: sessionNonce (from verifier)
    ├── info: verifierOrigin + timestamp
    └── output: ephemeral keypair seed (32 bytes)
                │
                ├── ECDSA signing key (for proof signature)
                └── ECDH encryption key (for response encryption)
```

**Why HKDF?**
- Same master key, but different output every time (nonce changes)
- Verifier cannot reverse-engineer master key from ephemeral key
- No two interactions produce the same DID

### 4. did:peer Format

```
did:peer:0z<multibase-encoded-ephemeral-pubkey>
```

- Method: `peer` (no registry, no resolution by third parties)
- Self-certifying: DID embeds the public key
- Short-lived: valid only for this interaction
- Spec: https://identity.foundation/peer-did-method-spec/

### 5. Proof Binding

The ephemeral DID signs the selective disclosure proof:
- Proof is bound to THIS session's DID (not the master key)
- Verifier can verify the proof using the embedded pubkey in did:peer
- Verifier CANNOT link this proof to any other interaction

### 6. Key Shredding (Post-Interaction)

After proof delivery + verifier acknowledgment:
1. `EphemeralKey.shred()` on signing key
2. `EphemeralKey.shred()` on encryption key
3. DID is forgotten — no record in wallet (unless user opts in to receipt)

Uses existing `EphemeralKey` class from `shared-crypto/src/ephemeral-key.ts`.

---

## Files to Create/Modify

| File | Action | Description |
|---|---|---|
| `shared-crypto/src/pairwise-did.ts` | CREATE | `generatePairwiseDID()`, did:peer generation, HKDF derivation |
| `shared-crypto/src/did.ts` | MODIFY | Add `did:peer` resolution (inline, no network) |
| `shared-crypto/test/pairwise-did.test.ts` | CREATE | Unlinkability tests (see below) |
| `shared-types/src/did.ts` | MODIFY | Add `PairwiseDIDResult` type |
| `policy-engine/src/engine.ts` | MODIFY | Use pairwise DID in proof generation |

---

## Test Requirements

### Unlinkability Tests
```typescript
// Same verifier, different sessions → different DIDs
test('two interactions with same verifier produce different DIDs')

// Different verifiers → different DIDs (obviously)
test('two interactions with different verifiers produce different DIDs')

// DID cannot be linked back to master key
test('ephemeral DID reveals no information about holder master key')

// Key shredding works
test('key material is zeroed after destroy()')

// Proof is valid with ephemeral DID
test('selective disclosure proof verifies against did:peer pubkey')

// Proof is not valid with a different session's DID
test('proof from session A does not verify with session B DID')
```

### Anti-Correlation Tests
```typescript
// Statistical test: generate 1000 DIDs, verify no patterns
test('no statistical correlation between sequential DIDs')

// Timing test: generation time is constant (no timing side-channel)
test('DID generation time is constant regardless of verifier')
```

---

## Security Properties

| Property | Guarantee |
|---|---|
| Cross-verifier unlinkability | ✅ Different DID per verifier |
| Cross-session unlinkability | ✅ Different DID per session (nonce) |
| Master key protection | ✅ HKDF is one-way |
| Forward secrecy | ✅ Shredded keys can't decrypt past sessions |
| Proof binding | ✅ Proof is bound to ephemeral DID |
| Verifier collusion resistance | ✅ No shared identifier to correlate |

---

## What This Does NOT Solve (→ Phase 2+3)

- Proof content fingerprinting (same age claim = same user?) → Phase 2: BBS+ randomized proofs
- Wallet network fingerprinting (IP, timing) → Phase 3: Anti-fingerprinting
- Tracker/cookie identifier theft → Phase 3: Transparency Layer
- Issuer-Verifier collusion → Phase 2: Blinded issuance

---

## Implementation Notes

- Use Web Crypto API (`crypto.subtle`) for HKDF — browser-native, no WASM needed
- `did:peer` method 0 (inception key only) is sufficient for Phase 1
- EphemeralKey.shred() already exists and works
- HKDF is already available via Web Crypto: `crypto.subtle.deriveKey('HKDF', ...)`
- No new dependencies needed for Phase 1!
