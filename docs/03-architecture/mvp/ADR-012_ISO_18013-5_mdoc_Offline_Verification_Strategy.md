# ADR-012 — ISO 18013-5 mdoc & Offline Verification Strategy (Digitaler Führerschein & Tier-1 Offline Use Cases)

**Status:** PROPOSED  
**Date:** 2026-03-14  
**Owner:** Architecture Lead  
**Decision:** Parallele Unterstützung von ISO 18013-5 mdoc neben SD-JWT für echte Offline-Verifikation mit vollem Manifest-Schutz

## Context
Nach ADR-011 (Claim-Level Encryption) fehlt die formale Strategie für mdoc (Backlog Task E-11 + application_domains.md Tier 1 „Digitaler Führerschein“).  
SD-JWT ist online stark, aber Behörden und Offline-Szenarien (Grenze, Polizei, Club-Eintritt ohne Internet) brauchen mdoc.  
EUDI-CIR und ISO 18013-5 verlangen Offline-Proofs ohne Linkability oder PII-Leak.

## Decision
**mdoc wird als gleichwertiges zweites Format integriert:**
- **Hybrid Issuance**: Issuer liefert SD-JWT + mdoc in einer Session (ein WebAuthn-Confirm)
- **Offline-First Flow**: mdoc wird lokal im Wallet gespeichert (Secure Element / TEE) und kann per QR/NFC ohne miTch-Proxy verifiziert werden
- **Per-mdoc Shredding**: Jeder mdoc-Key ist ephemer + $0x00-Überschreiben nach Verifikation
- **Policy-Engine Offline-Check**: `allowOffline(mdoc)` prüft lokal Datensparsamkeit + Unlinkability vor Freigabe
- **Blind Provider Enforcement**: miTch-Proxy sieht nur die Issuance, niemals den späteren Offline-Proof

**Technische Umsetzung:**
- `@mitch/wallet-core` erweitert um `issueMdoc(claims)` + `verifyOfflineMdoc()`
- `@mitch/shared-crypto` nutzt CBOR + COSE für mdoc (parallel zu SD-JWT)
- Fail-Closed: Bei fehlendem Offline-Consent → gesamter Batch DENY

## Alternatives Considered
- Nur SD-JWT (aktueller Stand) → keine echte Offline-Fähigkeit  
- Zentrale mdoc-Proxy → verstößt gegen Blind Provider + Human-in-the-Loop

## Consequences
✅ **Human-in-the-Loop** bleibt Root (ein WebAuthn für Issuance + Offline-Consent)  
✅ **Crypto-Shredding** gilt auch für mdoc-Keys ($0x00 nach jeder Verifikation)  
✅ **Smart Policy Engine** entscheidet lokal auch offline  
✅ **Blind Provider** bleibt blind (Offline-Proofs laufen komplett ohne Infrastruktur)

## Acceptance Evidence
- Test-Suite: Offline-Verifikation (NFC/QR) + Linkability-Tests
- Demo in `verifier-demo` + `wallet-pwa` (Führerschein-Offline-Flow)
- EVIDENCE_PACK-Erweiterung + ISO 18013-5 Mapping

## Implementation Notes
- Task M-12 in BACKLOG Phase 3 (mdoc Support + Offline Engine)
- Verknüpfung mit ADR-001 (Credential Stack), ADR-008 (Batch), ADR-010 (TEE) und ADR-011 (Claim-Encryption)

## References
- miTch-Manifest (Human-in-the-Loop + Crypto-Shredding + Blind Provider)
- EUDI-CIR Art. 15 (Offline Use Cases)
- ISO 18013-5:2021 (mdoc)
- application_domains.md (Tier 1 Digitaler Führerschein)

## Change Log
+ 2026-03-14: Initial Proposal (PROPOSED)