# docs/compliance/ADR/ — Compliance- und Implementierungs-ADRs

Compliance- und implementierungsnahe ADRs, teils mit CIR/BSI/RFC-Bezug. Diese Sammlung dokumentiert konkrete Technologieentscheidungen mit Verweis auf Backlog-IDs und Code-Pfade.

## Scope

Jede ADR beschreibt eine Implementierungsentscheidung — welches Protokoll, welche Library, welcher Algorithmus — und verknüpft sie mit dem betroffenen Backlog-Item und den relevanten Quellcode-Dateien.

## Nummernkollision

Die Nummern ADR-001 bis ADR-009 existieren auch in `docs/03-architecture/mvp/` — dort handelt es sich um **andere Dokumente** mit anderem Fokus (Architekturstrategie, Manifest-Prinzipien). Die Nummerierung ist unabhängig voneinander.

## Index

| ADR | Titel | Status |
|-----|-------|--------|
| [ADR-001](ADR-001.md) | SD-JWT VC as Credential Format (E-10) | Accepted |
| [ADR-002](ADR-002.md) | DPoP (RFC 9449) for Proof of Key Possession (E-05) | Accepted |
| [ADR-003](ADR-003.md) | SIOPv2 + OID4VP + HAIP for Presentation Protocol (E-03, E-04, E-13) | Accepted |
| [ADR-004](ADR-004.md) | Brainpool Curves (BSI/SOG-IS) + ECDH-HMAC MAC (C-01, C-02) | Accepted (C-01 partial) |
| [ADR-005](ADR-005.md) | Pairwise DIDs over Pseudonymous Attestations | Accepted |
| [ADR-006](ADR-006.md) | StatusList2021 over OCSP for Revocation | Accepted |
| [ADR-007](ADR-007.md) | Client-Side Crypto over Server-Side Processing | Accepted |
| [ADR-008](ADR-008.md) | Fail-Closed Policy Engine with Deny-Bias | Accepted |
| [ADR-009](ADR-009.md) | Native WebAuthn Verifier statt HMAC-Proxy-Mode-System | Accepted (retrospective) |

## Verwandte Sammlungen

- [`docs/03-architecture/mvp/`](../../03-architecture/mvp/) — formale Architektur-Strategie-ADRs (ADR-001–012)
- [`docs/03-architecture/decisions/`](../../03-architecture/decisions/) — frühe, lightweight Decision Notes (Phase 0)
