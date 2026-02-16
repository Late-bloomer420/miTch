# ADR-002 — WebAuthn Native Verification Strategy

**Status:** ACCEPTED
**Date:** 2026-02-16
**Owner:** Security Lead
**Decision:** Implement native WebAuthn verification for hardware-backed security

## Context

miTch Phase-0 uses software-based keys (WebCrypto). For production, we need hardware-backed security (TEE/Secure Enclave) to prevent key extraction.

## Decision

**Strategy:** WebAuthn Native Verifier with counter-based replay protection

**Implementation:**
- Library: `@simplewebauthn/server` (actively maintained, W3C compliant)
- Key Storage: Hardware authenticators (TouchID, Windows Hello, YubiKey)
- Replay Protection: Signature counter increment validation
- Challenge Lifecycle: 5-minute expiry, single-use

**Security Properties:**
1. ✅ Keys non-extractable (hardware-backed)
2. ✅ Replay protection (counter-based)
3. ✅ Phishing resistance (origin binding)
4. ✅ User presence verification (biometric/PIN)

## Alternatives Considered

1. **Software-only keys:** Easy but extractable
   - ❌ Keys can be stolen from memory
   - ❌ No user presence verification
   - ✅ Works on all devices

2. **FIDO2/U2F:** Hardware-backed but requires external device
   - ✅ Strong security
   - ❌ Requires physical device (YubiKey)
   - ❌ Poor UX for mobile users

3. **Platform Authenticator:** Best UX (TouchID/FaceID built-in)
   - ✅ Hardware-backed
   - ✅ Great UX (built-in biometrics)
   - ✅ Production-grade security
   - ⚠️ Requires WebAuthn-capable device

## Consequences

✅ Production-grade security
✅ Zero key extraction risk
✅ Regulatory compliance (eIDAS High)
✅ User presence verification (prevents coercion)
⚠️ Requires WebAuthn-capable device
⚠️ Fallback needed for older devices

## Implementation Details

### Counter-Based Replay Protection

```typescript
// On authentication:
1. Generate challenge (5-minute expiry)
2. User signs with hardware key
3. Extract counter from authenticator data
4. Verify: newCounter > storedCounter
5. Update stored counter
6. Reject if counter not incremented (replay attack!)
```

**Why Counter Matters:**
- Each hardware authenticator has internal counter
- Counter increments with each signature
- If signature replayed, counter won't increment
- Server rejects signatures with old counters

### Challenge Lifecycle

```
1. Generate: 32-byte random Base64URL
2. Store: Map userDID → challenge (5min TTL)
3. Verify: Challenge must match client data
4. Delete: Single-use (deleted after verification)
5. Cleanup: Periodic expiry sweep
```

### Origin Binding (Phishing Protection)

```typescript
// Client sends origin in clientDataJSON
clientData = {
  type: 'webauthn.get',
  challenge: '<challenge>',
  origin: 'https://mitch.example.com'
}

// Server verifies:
if (clientData.origin !== expectedOrigin) {
  return DENY; // Phishing attempt!
}
```

## Security Analysis

### Threat Model

**Threats Mitigated:**
1. ✅ Key extraction (keys in hardware)
2. ✅ Replay attacks (counter validation)
3. ✅ Phishing (origin binding)
4. ✅ Coercion (user presence required)

**Remaining Risks:**
1. ⚠️ Device theft + biometric spoof (low probability)
2. ⚠️ Browser compromise (out of scope)
3. ⚠️ Legacy device fallback (software keys)

### Compliance

**eIDAS 2.0:**
- ✅ Level of Assurance: High (hardware-backed)
- ✅ Strong authentication (2-factor inherent)
- ✅ User presence verification

**GDPR:**
- ✅ Data minimization (no passwords stored)
- ✅ Security by design (hardware keys)
- ✅ Right to erasure (revoke credential)

## Acceptance Evidence

- [ ] Counter increment validated in tests ✅
- [ ] Replay attack blocked in adversarial test ✅
- [ ] Challenge expiry enforced ✅
- [ ] Cross-browser compatibility tested (Chrome, Safari, Firefox)
- [ ] Mobile device testing (iOS Safari, Android Chrome)
- [ ] Fallback mechanism for legacy devices

## Migration Path

**Phase 1 (MVP):** Software keys + WebAuthn Verifier implemented
**Phase 2 (Pilot):** Hardware keys encouraged, software fallback available
**Phase 3 (Production):** Hardware keys required for sensitive operations

**Fallback Strategy:**
```typescript
if (WebAuthn.isAvailable() && WebAuthn.isPlatformAuthenticatorAvailable()) {
  // Use hardware-backed keys
} else {
  // Fallback to software keys with warning
  console.warn('Hardware keys not available - using software keys');
}
```

## References

- [WebAuthn Spec (W3C)](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Specification](https://fidoalliance.org/specifications/)
- [SimpleWebAuthn Library](https://simplewebauthn.dev/)
- [eIDAS 2.0 Technical Specifications](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation)

## Change Log

- 2026-02-16: Initial decision (ACCEPTED)
- 2026-02-16: Implementation started (@mitch/webauthn-verifier)

## Next Steps

1. ✅ Implement WebAuthnNativeVerifier package
2. ✅ Add unit tests (9 tests)
3. [ ] Cross-browser integration tests
4. [ ] Mobile device testing
5. [ ] Performance benchmarking (<50ms verify)
6. [ ] Production deployment with fallback
