# Ops Runbooks v1

Each playbook defines mechanical behavior and user-facing behavior. Fail-closed defaults apply unless explicitly documented otherwise.

## 1) DID resolver outage

- **Trigger:** DID resolution fetch times out, returns non-2xx, or quorum cannot be established.
- **Expected wallet verdict:** **DENY** — trust root cannot be established.
- **User messaging behavior:** "Sicherheitsprüfung konnte nicht abgeschlossen werden."
- **Audit evidence produced:** `reasonCode=DENY_RESOLVER_QUORUM_FAILED`; request hash, bucketed timestamp, verifier hash. No raw credential subject.
- **Safe default:** Fail-closed DENY confirmed.
- **Recovery path:** Retry when resolver endpoint healthy; if key changed, clear DID cache and re-resolve.

## 2) Revocation endpoint / status list outage

- **Trigger:** StatusList fetch fails or times out.
- **Expected wallet verdict:** **DENY** in strict pilot profile.
- **User messaging behavior:** "Ein externer Dienst ist nicht erreichbar. Bitte versuche es später."
- **Audit evidence produced:** `reasonCode=DENY_STATUS_SOURCE_UNAVAILABLE`, status URL, checkedAt bucket, cache/grace flags.
- **Safe default:** Fail-closed DENY confirmed.
- **Recovery path:** Retry after endpoint recovery; optionally refresh cached status list before next proof.

## 3) Clock skew or nonce expiry edge cases

- **Trigger:** Request `expiresAt` in past/invalid or nonce already consumed.
- **Expected wallet verdict:** **DENY** — replay/timing integrity violated.
- **User messaging behavior:** "Die Anfrage ist abgelaufen. Bitte starte den Vorgang neu." / generic security failure on replay.
- **Audit evidence produced:** `reasonCode=DENY_BINDING_EXPIRED` or `DENY_BINDING_NONCE_REPLAY`; nonce hash only.
- **Safe default:** Fail-closed DENY confirmed.
- **Recovery path:** Verifier reissues fresh request with fresh nonce and valid expiry.

## 4) Compromised issuer key (wallet reaction)

- **Trigger:** Signature verification fails, unsupported algorithm appears, or issuer key status is invalid.
- **Expected wallet verdict:** **DENY** — cryptographic authenticity cannot be trusted.
- **User messaging behavior:** "Sicherheitsprüfung fehlgeschlagen." / "Nicht unterstützter Sicherheitsstandard."
- **Audit evidence produced:** `reasonCode=DENY_CRYPTO_VERIFY_FAILED` or `DENY_CRYPTO_UNSUPPORTED_ALG` / `DENY_CRYPTO_KEY_STATUS_INVALID`.
- **Safe default:** Fail-closed DENY confirmed.
- **Recovery path:** Issuer rotates to valid trusted key; wallet refreshes trust metadata and retries.

## 5) Policy update rollback

**[PLANNED — not yet implemented]**

- **Trigger:** New policy deployment is rolled back to a previous version.
- **Expected wallet verdict:** **DENY** when policy version is missing/unknown until validated.
- **User messaging behavior:** "Keine Sicherheitsrichtlinie geladen. Bitte starte die App neu." or update-required message.
- **Audit evidence produced:** `reasonCode=DENY_POLICY_MISSING` or `DENY_POLICY_UNSUPPORTED_VERSION`.
- **Safe default:** Planned fail-closed behavior (enforced by policy version checks where implemented).
- **Recovery path:** Re-publish signed policy manifest with known version and integrity validation.
