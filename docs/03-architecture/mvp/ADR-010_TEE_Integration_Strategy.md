# ADR-010 — Trusted Execution Environment (TEE) Integration Strategy (Hardware Root-Key Protection)

**Status:** PROPOSED  
**Date:** 2026-03-14  
**Owner:** Architecture Lead  
**Decision:** Optional TEE/ Secure Element als erweiterter Root-Key-Speicher mit Fallback auf Software (WebCrypto + IndexedDB-AES)

## Context
Nach ADR-009 (Threat Model) und Phase-3 Security Hardening fehlt eine Strategie für Hardware-gestützte Root-Key-Protection.  
Device-Loss, Cold-Boot und Memory-Remanence sind im Threat Model als hohes Risiko identifiziert.  
EUDI-CIR und BSI TR-02102 verlangen nachweisbaren Schutz des Root-Keys (Mensch = Root-Key).

## Decision
**TEE-Integration wird als progressive Enhancement umgesetzt:**
- **Primär**: WebAuthn + Secure Element (Android StrongBox / iOS Secure Enclave) für Root-Key-Generierung und -Speicherung
- **Fallback**: Software-Only (WebCrypto + AES-256-GCM + $0x00-Shredding) bei Geräten ohne TEE
- **Hybrid Mode**: Root-Key wird nie außerhalb des TEE entschlüsselt; Policy-Engine und Crypto-Shredding laufen immer im TEE-Kontext
- **Migration Path**: Bestehende Software-Wallets können per ZKP-Proof auf TEE migrieren (kein PII-Transfer)

**Technische Umsetzung:**
- `@mitch/secure-memory` erweitert um `TEE-awareKeyStorage` (WebCrypto + platform APIs)
- Policy-Engine prüft `isTEEProtected()` vor jeder Operation → Fail-Closed bei schwachem Storage
- Crypto-Shredding: TEE-spezifisches Wipe (SecureElement.eraseKey)

## Alternatives Considered
- Nur Software (aktueller Stand) → ausreichend für MVP, aber nicht maximaler Schutz gegen physische Angriffe  
- Obligatorisches TEE → schließt viele Geräte aus (verstößt gegen Inclusivity)

## Consequences
✅ **Human-in-the-Loop** wird hardware-gestützt (Root-Key nie im normalen RAM)  
✅ **Crypto-Shredding** wird hardware-enforced (SecureElement.erase + $0x00)  
✅ **Smart Policy Engine** entscheidet lokal inkl. TEE-Status  
✅ **Blind Provider** bleibt unverändert (stateless, keine neuen Server-Daten)

## Acceptance Evidence
- Test-Szenarien: Cold-Boot, Device-Compromise, TEE-Fallback
- Demo in `wallet-pwa` (TEE-Status-Indicator)
- EVIDENCE_PACK-Erweiterung + BSI-TR-02102 Mapping

## Implementation Notes
- Task T-10 in BACKLOG Phase 3 (TEE Migration)
- Verknüpfung mit ADR-006 (Recovery) und ADR-009 (Threat Model)

## References
- miTch-Manifest (Human-in-the-Loop + Crypto-Shredding)
- EUDI-CIR Art. 13 (Wallet Security)
- BSI TR-02102-2 (Hardware Security Modules)
- Android/iOS Secure Element Specs

## Change Log
+ 2026-03-14: Initial Proposal (PROPOSED)