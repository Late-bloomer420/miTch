# ADR-009 — Formal Threat Model (STRIDE-basiert)

**Status:** PROPOSED  
**Date:** 2026-03-13  
**Owner:** Architecture Lead  
**Decision:** Vollständiges STRIDE Threat Model + Mitigations für alle vier Manifest-Prinzipien als P0-Basis für Phase 3

## Context
Das Manifest steht auf vier Säulen, die der Code strukturell erzwingt. Es existiert jedoch **kein dokumentiertes Threat Model** (weder in BACKLOG, REFACTORING_ROADMAP, EVIDENCE_PACK, noch in einer Spec oder einem Finding).  
EUDI-CIR und DSGVO Art. 32 verlangen explizit ein Risiko-Assessment. Ohne dieses bleibt miTch ein perfektes PoC, aber kein audit-fähiges System.

## Decision
**Erstellung eines formalen Threat Model** mit:
- STRIDE pro Komponente (Wallet-PWA, Policy-Engine, Crypto-Shredding, Blind Provider, pairwise DIDs)
- Priorisierte Mitigations direkt verknüpft mit den vier Manifest-Prinzipien
- Gap-Analyse zu BSI TR-02102 und EUDI-CIR

**STRIDE-Tabelle (Auszug – wird im ADR vollständig):**

| Komponente          | Threat (STRIDE)              | Manifest-Prinzip betroffen       | Mitigation (bereits im Code / neu)                          | Prio |
|---------------------|------------------------------|----------------------------------|-------------------------------------------------------------|------|
| Crypto-Shredding    | S (Spoofing) + T (Tampering) | Crypto-Shredding + Human-in-Loop | $0x00-Überschreiben + SecureMemory + WebAuthn-Step-up      | 🔴   |
| Blind Provider      | I (Information Disclosure)   | Blind Provider                   | Stateless OID4VP + kein PII-Log + pairwise-ephemere DIDs   | 🔴   |
| Policy Engine       | E (Elevation) + R (Repudiation) | Smart Policy Engine           | Lokale Entscheidung (Wallet as Lawyer) + 31 Deny-Codes     | 🔴   |
| Wallet-PWA          | D (Denial of Service)        | Human-in-the-Loop                | IndexedDB-AES + Fail-Closed + RecoveryService-Stub         | 🔴   |

**Akzeptanzkriterien:**  
- Threat Model deckt alle 4 Manifest-Prinzipien ab  
- Mind. 12 Mitigations mit Test-Vektoren  
- Gap-Analyse < 5 offene Risiken (alle P0)

## Alternatives Considered
- Nur interne Security Patterns (Phase 3) → unzureichend für Auditoren  
- Externes Audit ohne internes Model → zu spät und teuer

## Consequences
✅ DSGVO Art. 25 + 32 + EUDI-CIR Compliance durch Design  
✅ Mathematisch beweisbare Garantien für Shredding & Unlinkability  
⚠️ Zusätzlicher Dokumentationsaufwand (einmalig)

## Acceptance Evidence
- STRIDE-Tabelle + Mitigations in Markdown + PlantUML  
- 3 Test-Szenarien (Cold-Boot, Verifier-Collusion, Device-Loss)  
- Review durch Architecture Lead + 1 externer Security Reviewer

## Implementation Notes
Siehe neuer Task S-10 im BACKLOG (Phase 3).

## References
- BSI TR-02102-1 (Kryptografische Verfahren)  
- EUDI-CIR 2024/2977–2981  
- OWASP Threat Modeling  
- miTch-Manifest (Human-in-the-Loop + Crypto-Shredding)

## Change Log
+ 2026-03-13: Initial Proposal (PROPOSED)