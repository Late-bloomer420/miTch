# ADR-011 — Claim-Level Encryption Strategy (Per-Claim Protection in SD-JWT)

**Status:** PROPOSED  
**Date:** 2026-03-14  
**Owner:** Architecture Lead  
**Decision:** Optionale per-Claim AES-256-GCM-Verschlüsselung innerhalb von SD-JWTs für hoch-sensible Claims (z. B. EHDS-Gesundheitsdaten, KYC-Stufe-3)

## Context
Nach ADR-010 (TEE) fehlt eine Strategie für Claim-Level Encryption.  
SD-JWT schützt durch Selective Disclosure, aber bei physischem Device-Compromise oder Debug-Export können einzelne Claims (z. B. medizinische Diagnosen) trotzdem lesbar werden.  
EUDI-CIR Art. 14 und DSGVO Art. 32 + 25 verlangen zusätzlichen Schutz für „besonders sensible“ Daten – ohne die Blind-Provider-Eigenschaft zu verletzen.

## Decision
**Claim-Level Encryption wird als progressive Layer umgesetzt:**
- **Opt-in pro Claim**: Policy-Engine entscheidet lokal (`needsEncryption(claim)`) → nur sensible Claims werden zusätzlich mit ephemerem per-Claim-Key (HKDF-derived) verschlüsselt
- **Double-Wrapping**: SD-JWT-Claim → AES-256-GCM → dann in SD-JWT-Payload → sofortiger $0x00-Shredding des per-Claim-Keys nach Auslieferung
- **Decryption nur im Wallet**: Verifier erhält verschlüsselten Claim nur bei explizitem User-Consent + WebAuthn; Decryption bleibt immer im Wallet (nie beim Verifier)
- **Fallback**: Bei nicht-TEE-Geräten bleibt Software-Only (WebCrypto), TEE nutzt Hardware-AES

**Technische Umsetzung:**
- `@mitch/shared-crypto` erweitert um `encryptClaimLevel(claim, sensitivity)`
- `@mitch/policy-engine` fügt neue Regel `claim_encryption_score` hinzu
- Fail-Closed: Bei fehlendem Key oder schwachem Storage → gesamte Session DENY

## Alternatives Considered
- Nur SD-JWT Selective Disclosure → ausreichend für Low-Sensitivity, aber nicht für EHDS/KYC-Stufe-3  
- Vollständige Wallet-Encryption → schlechte Performance + UX

## Consequences
✅ **Human-in-the-Loop** bleibt Root (extra WebAuthn nur bei encrypted Claims)  
✅ **Crypto-Shredding** gilt auch für per-Claim-Keys ($0x00 sofort nach Decryption)  
✅ **Smart Policy Engine** entscheidet lokal über Verschlüsselungs-Level  
✅ **Blind Provider** bleibt blind (verschlüsselte Claims sind für die Infrastruktur unsichtbar)

## Acceptance Evidence
- Test-Suite: Cold-Boot + Claim-Export-Attack (encrypted vs. unencrypted)
- Demo in `wallet-pwa` (EHDS-Break-Glass mit Claim-Encryption)
- EVIDENCE_PACK-Erweiterung + DSGVO-Art.32-Mapping

## Implementation Notes
- Task E-11 in BACKLOG Phase 3 (Claim-Level Encryption)
- Verknüpfung mit ADR-009 (Threat Model), ADR-010 (TEE) und ADR-003 (Revocation)

## References
- miTch-Manifest (Crypto-Shredding + Blind Provider)
- EUDI-CIR Art. 14 (Sensitive Data Protection)
- DSGVO Art. 32 + 25
- AES-256-GCM RFC + SD-JWT RFC (Encrypted Payloads)

## Change Log
+ 2026-03-14: Initial Proposal (PROPOSED)