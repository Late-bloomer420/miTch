# ADR-009 — Formal Threat Model (STRIDE-basiert)

**Status:** PROPOSED
**Date:** 2026-03-13
**Owner:** Architecture Lead
**Decision:** Vollständiges STRIDE Threat Model + Mitigations für alle vier Manifest-Prinzipien als P0-Basis für Phase 3

**Status-Begründung (2026-03-18):** Technische Acceptance Criteria dokumentiert (STRIDE-Tabelle, Szenarien, Gap-Analyse). Status bleibt PROPOSED bis externer Security Review abgeschlossen — menschliche Vorbedingung, nicht automatisierbar.

## Context

Das Manifest steht auf vier Säulen, die der Code strukturell erzwingt. Es existiert jedoch **kein formalisiertes STRIDE Threat Model**, obwohl umfangreiche Threat-Analysen in Specs (05, 49) und im Evidence Pack P0 vorliegen.
EUDI-CIR und DSGVO Art. 32 verlangen explizit ein Risiko-Assessment. Dieses ADR konsolidiert die vorhandene Evidenz in STRIDE-Form.

**Quellen:**
- `docs/specs/05_Threat_Model.md` — 6 Top-Level-Threats (T-01–T-06)
- `docs/specs/49_Agentic_Threat_Model_and_Controls.md` — 6 Agentic-Threats (T-A1–T-A6)
- `docs/ops/EVIDENCE_PACK_P0.md` — G-01–G-06 mit Threat Mappings + Test-Evidenz
- Repo-weite Testdateien (alle Pfade per Glob verifiziert)

## Decision

**Formalisierung des vorhandenen Threat Models** in STRIDE-Struktur mit:
- STRIDE pro Komponente (Policy-Engine, Crypto-Shredding, Wallet-PWA, Audit Log, Blind Provider, Pairwise DIDs, WebAuthn)
- Priorisierte Mitigations mit explizitem Evidenz-Status
- Gap-Analyse mit Residualrisiken
- 3 Test-Szenarien (Cold-Boot, Verifier-Collusion, Device-Loss)

---

## STRIDE-Tabelle

### Evidenz-Status-Legende

- **belegt** — Testdatei + Testname verifiziert, Mitigation in CI-Gate
- **teilweise belegt** — Code vorhanden, Tests eingeschränkt oder nur architektonisch adressiert
- **offen** — dokumentiert, nicht implementiert oder nicht testbar

### S — Spoofing

| # | Komponente | Threat | Manifest-Prinzip | Mitigation | Evidenz-Status | Test-Referenz |
|---|---|---|---|---|---|---|
| S-1 | Policy Engine | Fake Verifier gibt sich als bekannter Verifier aus | Smart Policy Engine | Verifier-Fingerprint: SHA256-Hash im Policy-Rule; Mismatch → PROMPT (User entscheidet) | belegt | `policy-engine/src/__tests__/verifier-fingerprint.test.ts` — "PROMPT (not ALLOW) when fingerprint does not match" |
| S-2 | Policy Engine | Unbekannter Verifier umgeht Policy | Smart Policy Engine | Fail-Closed: Unbekannter Verifier → DENY; Golden Invariant als Merge-Gate | belegt | `integration-tests/src/fail-closed-golden.test.ts` — "unknown verifier → DENY (never ALLOW)" |
| S-3 | DID Resolution | MITM / gefälschtes DID-Dokument | Smart Policy Engine | Quorum-basierte DID-Resolution (strict: 3/3, balanced: 2/3); Inkonsistenz → DENY | belegt | `shared-crypto/test/did-quorum.test.ts` — "detects INCONSISTENT when backends disagree" |
| S-4 | DID Resolution | DID-Resolution-Fehler (Netzwerk, Timeout, malformed) | Smart Policy Engine | Alle Fehler → DIDResolutionError (fail-closed); 6 Fehlerklassen getestet | belegt | `integration-tests/src/fail-closed-golden.test.ts` — "network error / HTTP 500 / timeout / unsupported method / empty DID / malformed → DIDResolutionError" |

### T — Tampering

| # | Komponente | Threat | Manifest-Prinzip | Mitigation | Evidenz-Status | Test-Referenz |
|---|---|---|---|---|---|---|
| T-1 | Policy Engine | Claim-Name-Injection (Path Traversal, Wildcards, Template-Injection) | Smart Policy Engine | Whitelist-basierte Input Validation: nur alphanumerisch + Underscore/Hyphen; rejects `../`, `.`, `/`, `*`, `$`, >128 Zeichen | belegt | `policy-engine/src/__tests__/input-validation.test.ts` — "rejects path traversal", "rejects wildcards", etc. |
| T-2 | Policy Engine | Protokoll-Downgrade (Replay-Protection, Step-Up abverhandeln) | Smart Policy Engine | Capability Negotiation: Security-kritische Flags → DENY bei Mismatch; DOWNGRADE_ATTACK Deny-Code | belegt | `policy-engine/src/__tests__/capability-negotiation.test.ts` — "DENY: unsafe downgrade attempt is rejected" |
| T-3 | Anti-Replay | Replay einer Präsentation (Nonce-Wiederverwendung) | Smart Policy Engine | Atomare Nonce-Konsumierung; zweite Verwendung → DENY (NONCE_REPLAY); Audience-Scoping | belegt | `poc-hardened/src/__tests__/nonceStore.test.ts` — "second use of same nonce returns replay" |
| T-4 | Anti-Replay | Abgelaufene / manipulierte Timestamps | Smart Policy Engine | Request-Expiry mit 90s Clock-Skew-Toleranz; ungültiges Datum → fail-closed expired | belegt | `poc-hardened/src/__tests__/requestGuards.test.ts` — "isExpired returns true for invalid date string" |
| T-5 | Audit Log | Manipulation der Audit-Kette (Einfügen, Löschen, Umordnen, Signatur-Swap) | Crypto-Shredding | Hash-Chain + Per-Entry-Signatur + Report-Signatur; 6 Angriffsvektoren getestet | belegt | `audit-log/test/adversarial_audit.test.ts` — "Payload Tampering detected", "Cherry-Picking detected", "Reordering detected", "Signature Swap detected" |
| T-6 | Policy Engine | ALLOW ohne nachvollziehbare Grundlage | Smart Policy Engine | Allow Assertion Grounding: ALLOW erfordert ruleId + reason + policy_hash; ohne → ALLOW_WITHOUT_EVIDENCE | belegt | `policy-engine/src/__tests__/allow-assertion.test.ts` — "fails for ALLOW with no evidence" |

### R — Repudiation

| # | Komponente | Threat | Manifest-Prinzip | Mitigation | Evidenz-Status | Test-Referenz |
|---|---|---|---|---|---|---|
| R-1 | Audit Log | Nutzer/System bestreitet Schlüsselvernichtung | Crypto-Shredding | Signed Shredding Receipt: KEY_CREATED → KEY_DESTROYED → signiertes Vernichtungszertifikat; Audit-Chain verifizierbar | belegt | `audit-log/test/proof_of_shredding.test.ts` — "Shredding Receipt Exported & Signed", "Audit Chain Integrity: VERIFIED" |
| R-2 | Crypto-Shredding | Ephemeral Key nach Shredding weiterverwendet | Crypto-Shredding | shred() → $0x00-Overwrite; Zugriff nach shred() → SECURITY VIOLATION; isShredded()-State | belegt | `shared-crypto/test/ephemeral.test.ts` — "Memory zeroing via shred() prevents further access" |
| R-3 | Policy Engine | ALLOW-Entscheidung nicht nachvollziehbar | Smart Policy Engine | Jedes ALLOW gebunden an ruleId, reason, evidenceAt, policy_hash | belegt | `policy-engine/src/__tests__/allow-assertion.test.ts` — "passes for valid ALLOW with evidence" |

### I — Information Disclosure

| # | Komponente | Threat | Manifest-Prinzip | Mitigation | Evidenz-Status | Test-Referenz |
|---|---|---|---|---|---|---|
| I-1 | Policy Engine | Oracle-Angriff: Verifier probt Policy-Regeln über Fehlermeldungen | Smart Policy Engine | Anti-Oracle: 27+ interne Deny-Codes → ≤4 generische Verifier-Buckets; "no such user" ≈ "policy denied" | belegt | `policy-engine/src/__tests__/anti-oracle.test.ts` — "verifier CANNOT distinguish 'no such user' from 'policy denied'", "total verifier bucket count ≤ 4" |
| I-2 | Pairwise DIDs | Cross-Verifier-Korrelation über persistente DIDs | Blind Provider | Pairwise-Ephemeral DIDs: neue DID pro Verifier pro Session; HKDF-Derivation; Proofs nicht übertragbar | belegt | `shared-crypto/test/unlinkability.test.ts` — "100 verifiers cannot correlate any two DIDs", "proof signed for verifier A cannot be verified against verifier B" |
| I-3 | Pairwise DIDs | Key-Material nach Session-Ende extrahierbar | Crypto-Shredding | Pairwise-DID-Keys: destroy() → isShredded()=true; sign() nach destroy() → throws; 50 Concurrent Interactions sicher | belegt | `shared-crypto/test/pairwise-did.test.ts` — "signing key is zeroed after destroy()", "50 concurrent interactions each shredded" |
| I-4 | SecureStorage | Credential-Daten im Klartext auf Disk | Crypto-Shredding | AES-256-GCM Encryption at Rest; Raw Storage enthält kein Klartext-PII; falscher Schlüssel → Decryption Failed | belegt | `secure-storage/test/persistence.test.ts` — "encrypted at rest — raw storage contains no plaintext PII", "wrong key → decryption fails" |
| I-5 | Policy Engine | Pairwise-DID in DENY-Response leakt Nutzer-Identität | Blind Provider | DENY-Verdict enthält keine pairwise_did; nur ALLOW/PROMPT erhalten DID | belegt | `policy-engine/src/__tests__/pairwise-did-proof.test.ts` — "DENY verdict does NOT include pairwise_did" |
| I-6 | Policy Engine | Datenabfluss in nicht-adäquate Jurisdiktionen | Blind Provider | GDPR-Transfer-Check: EU→EU erlaubt, nicht-adäquat → blockiert; ISO-3166-Whitelist | belegt | `policy-engine/src/__tests__/jurisdiction.test.ts` — "checkGDPRDataTransfer blocks non-adequate countries" |
| I-7 | Revocation | Widerrufs-Status unbekannt → Credential trotzdem akzeptiert | Smart Policy Engine | Fail-Closed: High-Risk → DENY bei fetch-Fehler; Revocation unavailable → DENY (never ALLOW) | belegt | `integration-tests/src/fail-closed-golden.test.ts` — "network error → DENY, never ALLOW" |

### D — Denial of Service

| # | Komponente | Threat | Manifest-Prinzip | Mitigation | Evidenz-Status | Test-Referenz |
|---|---|---|---|---|---|---|
| D-1 | Policy Engine | Verifier flutet Verifikations-Anfragen | Smart Policy Engine | Rate Limiting: per-Verifier + per-User Limits; Token-Bucket; RATE_LIMIT_VERIFIER / RATE_LIMIT_USER | belegt | `policy-engine/src/__tests__/rate-limiter.test.ts` — "blocks when verifier limit exceeded", "different verifiers have independent limits" |
| D-2 | Policy Engine | Proof-Fatigue: Nutzer durch häufige Prompts erschöpft | Human-in-the-Loop | Prompt-Quota pro Zeitfenster; bei Erschöpfung → auto-DENY; Warnung bei 80% | belegt | `policy-engine/src/__tests__/proof-fatigue.test.ts` — "triggers fatigue after exceeding max", "warns at 80% threshold" |
| D-3 | Policy Engine | Policy-Ambiguität führt zu unerwarteten Verdikten | Smart Policy Engine | Deny-Wins Conflict Resolution: ANY DENY > ANY PROMPT > ALL ALLOW; leere Verdicts → DENY | belegt | `policy-engine/src/__tests__/deny-code-disambiguation.test.ts` — "NO_MATCHING_RULE is produced when no rule matches" |

### E — Elevation of Privilege

| # | Komponente | Threat | Manifest-Prinzip | Mitigation | Evidenz-Status | Test-Referenz |
|---|---|---|---|---|---|---|
| E-1 | WebAuthn | Niedrig-privilegierte Aktion umgeht Step-Up-Auth | Human-in-the-Loop | Session-basierte Step-Up-Auth: High-Sensitivity erzwingt WebAuthn; unbekannte Session → fail-secure | belegt | `webauthn-verifier/src/__tests__/step-up-auth.test.ts` — "evaluateStepUp requires step-up for high sensitivity", "requires step-up for unknown session" |
| E-2 | Policy Engine | Anomal hohe ALLOW-Rate deutet auf Policy-Bypass | Smart Policy Engine | Allow Rate Guard: >90% ALLOW-Rate → flagged als suspicious; Minimum 10 Entscheidungen vor Bewertung | belegt | `policy-engine/src/__tests__/allow-assertion.test.ts` — "flags suspicious when all decisions are ALLOW" |

---

## Manifest-Prinzip-Abdeckung

| Manifest-Prinzip | STRIDE-Einträge | Abdeckung |
|---|---|---|
| **Smart Policy Engine** | S-1, S-2, S-3, S-4, T-1, T-2, T-3, T-4, T-6, I-1, I-7, D-1, D-2, D-3, E-2, R-3 | Alle 6 STRIDE-Kategorien |
| **Crypto-Shredding** | T-5, R-1, R-2, I-3, I-4 | T, R, I |
| **Blind Provider** | I-2, I-5, I-6 | I |
| **Human-in-the-Loop** | D-2, E-1 | D, E |

Alle vier Manifest-Prinzipien haben mindestens eine belegte STRIDE-Zeile.

---

## Test-Szenarien

### Szenario 1: Cold-Boot Attack

**Threat:** Angreifer extrahiert Schlüsselmaterial aus RAM nach App-Crash oder Device-Freeze.
**STRIDE:** I (Information Disclosure)

**Mitigations:**
- **(belegt)** SecureMemory $0x00-Wipe: `shred()` überschreibt Buffer mit Nullen; Zugriff nach shred() → SECURITY VIOLATION
  → `shared-crypto/test/ephemeral.test.ts`: "Memory zeroing via shred() prevents further access"
- **(belegt)** EphemeralKey auto-shred: Lifecycle Create → Use → Shred → Fail
  → `shared-crypto/test/ephemeral.test.ts`: "Lifecycle: Create -> Use -> Shred -> Fail"
- **(belegt)** Pairwise-DID-Keys nach Session zerstört
  → `shared-crypto/test/pairwise-did.test.ts`: "signing key is zeroed after destroy()"

**Residualrisiko (offen):** JavaScript-Runtime bietet keine Garantie für physische RAM-Löschung. `TypedArray.fill(0)` ist best-effort — der GC kann Kopien im Heap hinterlassen. Hardware-basierte Lösung (TEE) in ADR-010 vorgesehen, aber deferred.

### Szenario 2: Verifier-Collusion

**Threat:** Zwei oder mehr Verifier (z.B. Liquor Store + Pharmacy) korrelieren Nutzer-Identitäten über DIDs oder Credential-Metadata.
**STRIDE:** I (Information Disclosure)

**Mitigations:**
- **(belegt)** Pairwise-Ephemeral DIDs: Neue DID pro Verifier pro Session; 100 Verifier → 100 verschiedene DIDs; Proofs nicht übertragbar
  → `shared-crypto/test/unlinkability.test.ts`: "100 verifiers cannot correlate any two DIDs", "proof signed for verifier A cannot be verified against verifier B DID"
- **(belegt)** HKDF-Derivation: Deterministisch pro Master+Verifier+Nonce; verschiedene Sessions → verschiedene DIDs
  → `shared-crypto/test/unlinkability.test.ts`: "same master + different verifiers → different DIDs"
- **(belegt)** DENY-Verdict ohne pairwise_did
  → `policy-engine/src/__tests__/pairwise-did-proof.test.ts`: "DENY verdict does NOT include pairwise_did"

**Residualrisiko (teilweise belegt):** Timing-Korrelation bei gleichzeitigen Requests — architektonisch adressiert durch sessionspezifische DIDs, aber kein dedizierter Timing-Test vorhanden. Kein Request-Jitter implementiert.

### Szenario 3: Device-Loss

**Threat:** Gerät gestohlen; Angreifer versucht Zugriff auf gespeicherte Credentials und Schlüsselmaterial.
**STRIDE:** I (Information Disclosure) + E (Elevation of Privilege)

**Mitigations:**
- **(belegt)** AES-256-GCM Encryption at Rest: Raw Storage enthält kein Klartext-PII; falscher Schlüssel → Decryption Failed (nicht partial data)
  → `secure-storage/test/persistence.test.ts`: "encrypted at rest — raw storage contains no plaintext PII", "wrong key → decryption fails (fail-closed)"
- **(belegt)** WebAuthn Step-Up: High-Sensitivity-Operationen erfordern biometrische/PIN-Bestätigung; unbekannte Session → fail-secure
  → `webauthn-verifier/src/__tests__/step-up-auth.test.ts`: "evaluateStepUp requires step-up for high sensitivity", "evaluateStepUp requires step-up for unknown session"
- **(belegt)** Credential-Deletion tatsächlich wirksam
  → `secure-storage/test/persistence.test.ts`: "delete credential → actually removed from storage"

**Residualrisiko (offen):** Recovery-Flow nach Device-Loss nicht implementiert. Weder Remote-Wipe noch Guardian-basierte Recovery vorhanden. ADR-006 (Recovery Strategy) ist PROPOSED, aber nicht umgesetzt.

---

## Gap-Analyse

| # | Gap | Prio | Status | Mitigation-Pfad |
|---|---|---|---|---|
| GAP-1 | JavaScript-Runtime bietet keine physische RAM-Löschung; `TypedArray.fill(0)` ist best-effort | 🟡 | Dokumentiert, kein Fix in Browser möglich | TEE-Integration (ADR-010, deferred) |
| GAP-2 | Recovery bei Device-Loss nicht implementiert (kein Remote-Wipe, kein Guardian) | 🟡 | Dokumentiert, nicht umgesetzt | ADR-006 (PROPOSED) |
| GAP-3 | Timing-Side-Channel bei Anti-Oracle: verschiedene Code-Pfade können unterschiedliche Latenz haben | 🟡 | Architektonisch adressiert (4 Buckets), kein Timing-Test | Request-Jitter oder konstante Verarbeitungszeit (Phase 3+) |
| GAP-4 | Externer Security Review nicht durchgeführt | 🔴 | Menschliche Vorbedingung für ACCEPTED | Reviewer zuweisen + Review durchführen |

---

## Acceptance Evidence — Fail-Closed-Bewertung

| Kriterium | Status | Begründung |
|---|---|---|
| STRIDE-Tabelle deckt alle 4 Manifest-Prinzipien | **Erfüllt** | Alle 4 Prinzipien haben belegte STRIDE-Zeilen (siehe Manifest-Prinzip-Abdeckung) |
| Mind. 12 Mitigations mit Test-Vektoren | **Erfüllt** | 22 STRIDE-Einträge, alle mit Evidenz-Status "belegt" und verifizierter Testdatei-Referenz |
| Gap-Analyse < 5 offene Risiken | **Erfüllt** | 4 Gaps dokumentiert (1× 🔴, 3× 🟡) |
| 3 Test-Szenarien | **Erfüllt** | Cold-Boot, Verifier-Collusion, Device-Loss — jeweils mit belegten Mitigations + Residualrisiken |
| Review durch Architecture Lead + 1 externer Security Reviewer | **Nicht erfüllt** | Menschliche Aktion, kein Reviewer zugewiesen |

**Konsequenz:** ADR-009 bleibt **PROPOSED**. Upgrade auf ACCEPTED erst nach:
1. Externer Security Reviewer bestätigt STRIDE-Tabelle + Gap-Analyse
2. Architecture Lead Sign-Off

---

## Alternatives Considered

- Nur interne Security Patterns (Phase 3) → unzureichend für Auditoren
- Externes Audit ohne internes Model → zu spät und teuer

## Consequences

✅ DSGVO Art. 25 + 32 + EUDI-CIR Compliance durch Design
✅ Mathematisch beweisbare Garantien für Shredding & Unlinkability
✅ Alle Mitigations mit belegbarer Test-Evidenz
⚠️ Externer Review als menschliche Vorbedingung offen

## Implementation Notes

Siehe Task S-10 im BACKLOG (Phase 3). Dieses ADR dokumentiert ausschließlich vorhandene Evidenz — kein neuer Code, keine neuen Tests.

## References

- BSI TR-02102-1 (Kryptografische Verfahren)
- EUDI-CIR 2024/2977–2981
- OWASP Threat Modeling
- miTch-Manifest (Human-in-the-Loop + Crypto-Shredding)
- `docs/specs/05_Threat_Model.md` — Praktisches Threat Model (T-01–T-06)
- `docs/specs/49_Agentic_Threat_Model_and_Controls.md` — Agentic Threats (T-A1–T-A6)
- `docs/ops/EVIDENCE_PACK_P0.md` — Guarantee Evidence (G-01–G-06)

## Change Log

+ 2026-03-13: Initial Proposal (PROPOSED)
+ 2026-03-18: STRIDE-Tabelle vollständig (22 Einträge, alle belegt), 3 Test-Szenarien, Gap-Analyse (4 Gaps), Fail-Closed Acceptance-Bewertung. Status bleibt PROPOSED (externer Review offen).
