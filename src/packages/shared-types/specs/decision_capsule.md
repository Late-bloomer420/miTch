# Decision Capsule Specification (Normative)

**Version**: 1.0.0
**Status**: DRAFT
**Related Schema**: `../schemas/decision_capsule.schema.json`

## 1. Introduction

The **Decision Capsule** is the authoritative, cryptographically-bound output of the miTch Policy Engine. It serves as the single source of truth for what the user (or their policy) has consented to.

## 2. Normative Rules for Wallet Implementers

### 2.1. Binding & Integrity

*   **MUST** be signed by the Wallet's key key or generated within a TEE.
*   **MUST** include `request_hash` (SHA-256 of the canonicalized incoming `VerifierRequest`).
*   **MUST** include `policy_hash` (SHA-256 of the active `PolicyManifest`).
*   Any modification of the capsule voids the decision.

### 2.2. Disclosure Constraints (The "Subset Rule")

*   The `allowed_claims` field **MUST** be strictly equal to or a subset of the `requestedClaims` in the original request.
*   **VP Generation Guard**: The Verifiable Presentation generation service **MUST** throw a security exception if it attempts to include any claim NOT listed in `allowed_claims`.
*   *Implementation Note*: `if (!subset(vp.claims, capsule.allowed_claims)) throw SecurityError`

### 2.3. UI & Agent Interaction

*   **Truth Panel**: If a UI (Native or Agent A2UI) renders a consent screen, it **MUST** display the contents of this capsule (Verdict, Allowed Claims, Verifier DID) in a host-controlled "Truth Panel" that cannot be obscured or modified by the Agent.
*   **Prompt Binding**: If `verdict` is `PROMPT`, the UI action to "Approve" **MUST** cryptographically reference `decision_id`.

### 2.4. Proof of Presence

*   If `requires_presence` is `true`:
    *   The Wallet **MUST** trigger a high-entropy user verification event (Biometric, PIN, FIDO2/WebAuthn).
    *   Simple UI clicks (simulated or real) are **INSUFFICIENT**.
    *   The `wallet_attestation` **MUST** only be generated *after* successful presence verification.

## 3. Field Semantics

| Field | Meaning & Enforcement |
| :--- | :--- |
| `decision_id` | Unique nonce to prevent replay attacks on this specific decision. |
| `verdict` | **ALLOW**: Safe to proceed auto. **DENY**: Stop. **PROMPT**: Must show UI + check presence. |
| `risk_level` | **HIGH**: Always requires presence. **MEDIUM**: Policy dependent. **LOW**: Auto-sign allowed. |
| `expires_at` | Wall-clock time after which this decision is void. Max default: 5 minutes. |

## 4. Crypto-Shredding Context

This capsule contains decision metadata.
*   **MAY** contain `allowed_claims` (names of attributes).
*   **MUST NOT** contain raw PII values (values of attributes).
*   This ensures the capsule itself does not become a toxic data leak if audit logs are compromised.
