# ADR-006 — Recovery Strategy (Human-in-the-Loop Preservation on Device Loss)

**Status:** PROPOSED  
**Date:** 2026-03-14  
**Owner:** Architecture Lead  
**Decision:** Geräteunabhängige Recovery ohne zentrale Instanz und ohne persistenten Seed

## Context
Nach ADR-005 (Metadata Minimization) fehlt eine explizite Recovery-Strategie.  
Der aktuelle RecoveryService-Stub im Refactoring-Roadmap ist nur ein Platzhalter.  
Device-Verlust oder -Wechsel ist der einzige reale Break für Human-in-the-Loop – klassische Wallets (Google, Apple) lösen das mit Cloud-Backup (verstößt gegen Blind Provider + Shredding).

## Decision
**Recovery wird rein client-seitig und seed-less umgesetzt:**
- **Mnemonic + WebAuthn-Biometrie** als Root-Key-Export (nur einmalig, lokal verschlüsselt)
- **Sharded Backup** über 2–3 Trusted Devices (kein Cloud, kein Server)
- **Crypto-Shredding** des alten Devices: vollständiges $0x00-Überschreiben aller IndexedDB-Keys + SecureMemory
- **Fail-Closed Migration**: Neues Device muss alten Root-Key per ZKP beweisen (kein PII-Transfer)
- Kein zentraler Recovery-Code oder Server-seitiger Seed

**Technische Umsetzung:**
- `@mitch/secure-memory` erweitert um `exportRootKey` + `importSharded`
- Policy-Engine blockt jede Recovery ohne explizite WebAuthn + User-Confirm
- Ephemere pairwise DIDs werden nach Recovery neu generiert (Unlinkability bleibt)

## Alternatives Considered
- Cloud-Backup (wie bei EUDI-Wallets heute) → verstößt massiv gegen Blind Provider + Crypto-Shredding
- Permanenter Master-Seed → verstößt gegen $0x00-Shredding nach jeder Session

## Consequences
✅ **Human-in-the-Loop** bleibt erhalten (User muss aktiv bestätigen + biometrisch)  
✅ **Crypto-Shredding** wird auf Device-Wechsel erweitert (alter Root-Key wird mathematisch gelöscht)  
✅ **Smart Policy Engine** prüft lokal die Recovery-Berechtigung  
✅ **Blind Provider** sieht niemals Recovery-Daten (stateless, kein Leak)

## Acceptance Evidence
- Test-Szenarien: Device-Loss, Device-Transfer, Cold-Boot-Attack
- Demo-Script in `wallet-pwa` (Recovery-Flow)
- EVIDENCE_PACK-Erweiterung mit ZKP-Proof-of-Recovery

## Implementation Notes
- Task R-06 in BACKLOG Phase 3 (RecoveryService -> RecoveryClient)
- Verknüpfung mit ADR-002 (WebAuthn) und ADR-003 (Revocation)

## References
- miTch-Manifest (Human-in-the-Loop + Crypto-Shredding)
- EUDI-CIR Art. 10 (Wallet Portability)
- BSI TR-02102 (Schlüsselmanagement)
- NIST SP 800-63B (Authenticator Recovery)

## Change Log
+ 2026-03-14: Initial Proposal (PROPOSED)