# ADR-005 — Metadata Minimization Strategy (Unlinkability First)

**Status:** PROPOSED  
**Date:** 2026-03-14  
**Owner:** Architecture Lead  
**Decision:** Strenge Metadata-Minimierung in allen SD-JWTs und pairwise DIDs

## Context
Nach ADR-004 (Consent UX) fehlt eine explizite Regel für Metadata.  
Heutige Systeme (OID4VCI, mdoc, Veriff) leaken Issuer-ID, Key-ID, Timestamps oder Audience-Hints → ermöglichen Linkability.  
EUDI-CIR und DSGVO Art. 25 verlangen „Datenminimierung durch Design“ – das muss strukturell erzwungen werden.

## Decision
**Metadata-Minimierung wird auf drei Ebenen erzwungen:**
1. **Pairwise-ephemere DIDs** (nie reuse einer DID über Verifier hinweg)
2. **Minimal SD-JWT Header** (nur `alg`, `typ`, `kid` als blinded HKDF; kein `iss`, kein `iat`, kein `exp` außer absolut notwendig)
3. **Nullifier-basierte Unlinkability** (ZKP-Prädikate erzeugen pro Request einen frischen nullifier, niemals persistent)
4. **Blind Provider Enforcement** – die Infrastruktur (miTch-Proxy) strippt automatisch jede nicht-prädikatsrelevante Metadata

**Technische Umsetzung:**
- `@mitch/shared-crypto` HKDF-Derivation pro Session
- `@mitch/policy-engine` prüft vor SD-JWT-Generierung: `metadata_leak_score == 0`
- Fail-Closed: Bei jedem Metadata-Rest → DENY + Crypto-Shredding

## Alternatives Considered
- Vollständige Metadata (wie bei klassischen JWTs) → verstößt gegen Blind Provider + Unlinkability
- Nur „best effort“ Minimierung → verstößt gegen strukturelle Erzwingung

## Consequences
✅ **Blind Provider** bleibt 100 % blind (kein PII, kein Linkability-Metadata)  
✅ **Crypto-Shredding** wird erweitert auf Metadata (ephemere Keys + $0x00 nach jeder Session)  
✅ **Smart Policy Engine** entscheidet lokal über Metadata-Freigabe  
✅ **Human-in-the-Loop** bleibt erhalten (User sieht exakt, welche Metadata freigegeben werden)

## Acceptance Evidence
- Test-Suite mit 5 Linkability-Attack-Vektoren (Timing, Issuer-Correlation, Nullifier-Reuse)
- Coverage-Report in `@mitch/shared-crypto`
- Demo in `verifier-demo` (Metadata-Stripping sichtbar)

## Implementation Notes
- Task M-05 in BACKLOG Phase 2 (Metadata Stripper + Pairwise DID Rotation)
- Verknüpfung mit ADR-001 (Credential Stack) und ADR-004 (Consent)

## References
- miTch-Manifest (Blind Provider + Crypto-Shredding)
- EUDI-CIR Art. 9 (Unlinkability)
- DSGVO Art. 25 + 5(1)c (Datenminimierung)
- RFC 7519 + SD-JWT RFC (Minimal Header Profile)

## Change Log
+ 2026-03-14: Initial Proposal (PROPOSED)