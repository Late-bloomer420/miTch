# 110 — eID Issuer Simulator: Fidelity Constraints

**Status:** Active (Phase 5 Pilot)
**Package:** `@mitch/eid-issuer-connector`
**Author:** miTch G-05

---

## Purpose

The eID Issuer Simulator enables end-to-end testing of miTch's credential issuance and verification flows without requiring real German eID hardware (Personalausweis + NFC reader) or AusweisApp2 integration.

## What the Simulator Does Faithfully (✅ Real)

| Aspect | Fidelity | Notes |
|--------|----------|-------|
| **ES256 Signatures** | Production-identical | `jose` library, ECDSA P-256. Same algorithm as production eID issuers. |
| **SD-JWT VC Format** | Spec-compliant | Follows draft-ietf-oauth-sd-jwt-vc. Disclosures use SHA-256 hashing. |
| **Credential Structure** | Production-aligned | `vct`, `_sd`, `_sd_alg`, `iss`, `sub`, `iat`, `exp`, `jti` fields per spec. |
| **DID Document** | Valid did:web format | Published `JsonWebKey2020` verification method with real EC key. |
| **Age Predicate (isOver18)** | Correct computation | `age_over_18` boolean computed from birthdate, non-selectively-disclosable. |
| **Selective Disclosure** | Working | Requested attributes are individual disclosures; verifier sees only what's disclosed. |
| **JWT Verification** | Standard | Any JOSE-compliant library can verify credentials against published DID/key. |
| **Protocol State Machine** | Modeled | Session tracks: idle → tc_token → pin → card_read → issue → complete. |

## What the Simulator Skips (❌ Simulated)

| Aspect | Production Reality | Simulator Behavior |
|--------|-------------------|-------------------|
| **PIN Verification** | User enters 6-digit PIN on device; verified against eID chip | State transition only, no actual PIN check |
| **Smartcard/NFC Interaction** | AusweisApp2 communicates with eID chip via NFC/contact reader | Citizen data loaded from in-memory profiles |
| **Certificate Chain** | eID chip has X.509 certificate chain rooted in BSI CA | Self-signed EC keypair per session |
| **AusweisApp2 SDK** | Local SDK via WebSocket on port 24727 | No external process communication |
| **eIDAS SAML** | Cross-border SAML AuthnRequest/Response flow | Not implemented |
| **Revocation** | OCSP/CRL for document validity | No status checks |
| **Rate Limiting / Abuse Prevention** | Government infrastructure has DDoS protection | None |
| **Data Processing Agreements** | Legal agreements required for PII handling | N/A for simulator |

## Upgrade Path to Real eID Integration

### Phase 1: AusweisApp2 Integration (Target: Phase 6)

1. Add `ausweisapp2` mode to `EIDIssuerConnector`
2. Implement TC Token generation (XML-based eID-Client protocol)
3. WebSocket client for AusweisApp2 SDK (`ws://localhost:24727/api/v2`)
4. Map AusweisApp2 response attributes to SD-JWT VC claims
5. Replace simulated keypair with HSM-backed signing key

### Phase 2: eIDAS Cross-Border (Target: Phase 7+)

1. SAML SP implementation for eIDAS node communication
2. Attribute mapping from eIDAS Minimum Dataset to SD-JWT VC
3. Country-specific attribute normalization

### Phase 3: Production Hardening

1. HSM integration for signing keys (PKCS#11)
2. Certificate chain validation against BSI root CA
3. OCSP stapling for revocation checks
4. Audit logging per GDPR Art. 30

## Testing Strategy

The simulator enables the following test scenarios without real hardware:

- **Happy path:** Wallet → Simulator → SD-JWT VC → Verifier (full E2E)
- **Age verification:** Adult vs minor profiles with correct predicate
- **Selective disclosure:** Verifier receives only requested attributes
- **Signature verification:** External verifier validates against DID Document
- **Error handling:** Invalid requests, unknown profiles, uninitialized connector

## Security Notes

- Simulator keys are ephemeral (generated per `initialize()` call)
- **Never use simulator-issued credentials in production**
- Simulator DID (`did:web:eid-simulator.mitch.local`) is clearly non-production
- The `vct` field uses the EU PID URN; production would add issuer-specific metadata
