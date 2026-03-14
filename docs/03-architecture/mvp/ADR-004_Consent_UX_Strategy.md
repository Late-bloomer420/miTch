# ADR-004 — Consent UX Strategy (Human-in-the-Loop First)

**Status:** PROPOSED  
**Date:** 2026-03-13  
**Owner:** Architecture Lead  
**Decision:** Einheitliche Consent-UX als Root-Key-Interaktion (Wallet as Lawyer)

## Context
Nach ADR-003 (Revocation) fehlt eine explizite Entscheidung zur Consent-UX.  
Die Parallel-DECISION_004 existiert als lightweight Note, aber keine formale ADR.  
EUDI-CIR und DSGVO Art. 7 + 25 verlangen nachweisbare, granular steuerbare Zustimmung – ohne zentrale Logs.

## Decision
**Consent erfolgt ausschließlich lokal im Wallet-PWA** über:
- WebAuthn-gesicherte Bestätigung pro Request
- Granulare Prädikat-Auswahl (`isOver18`, `isStudent`, `hasLicense` etc.)
- One-Click / Explicit-Deny-Button mit Fail-Closed (Default = DENY)
- Kein Consent-Tracking auf Serverseite (Blind Provider)

**Technische Umsetzung:**
- `@mitch/wallet-core` rendert dynamisches Consent-Screen aus Policy-Engine
- SD-JWT-Payload wird erst nach User-Confirm + WebAuthn generiert
- Ephemere Schlüssel + Crypto-Shredding direkt nach Bestätigung

## Alternatives Considered
- Zentrale Consent-Log (wie bei klassischen IDPs) → verstößt gegen Blind Provider
- Nur „Accept All“-Button → verstößt gegen Human-in-the-Loop + Datenminimierung

## Consequences
✅ Human-in-the-Loop wird strukturell erzwungen (Mensch = Root-Key)  
✅ Crypto-Shredding bleibt erhalten (kein persistenter Consent-State)  
✅ Smart Policy Engine entscheidet lokal vor der Freigabe  
✅ Blind Provider sieht niemals Consent-Details  

## Acceptance Evidence
- Demo-Flow in `wallet-pwa` (siehe DEMO_SCRIPT.md Update)
- 3 Test-Cases: Explicit-Deny, Partial-Consent, Revoke-later
- Screenshot-Sequence in EVIDENCE_PACK

## Implementation Notes
- Task C-04 in BACKLOG Phase 2 (Consent-UI Component)
- Verknüpfung mit ADR-002 (WebAuthn)

## References
- miTch-Manifest (Human-in-the-Loop + Blind Provider)
- EUDI-CIR Art. 5 & 6 (User-centric consent)
- DSGVO Art. 7 + 25

## Change Log
+ 2026-03-13: Initial Proposal (PROPOSED)