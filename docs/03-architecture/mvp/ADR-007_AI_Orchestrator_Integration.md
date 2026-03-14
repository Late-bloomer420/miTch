# ADR-007 — AI Orchestrator Integration Strategy (Scoped Delegation)

**Status:** PROPOSED  
**Date:** 2026-03-14  
**Owner:** Architecture Lead  
**Decision:** Lokaler AI-Orchestrator mit human-pre-authorized Scoped Delegation Tokens (Model C)

## Context
Nach ADR-006 (Recovery) fehlt eine formale Entscheidung zur AI-Orchestrierung.  
Die parallel existierende DECISION-007_AI_Orchestrator.md beschreibt bereits scoped delegation, wird aber nicht als ADR geführt.  
EUDI-CIR und DSGVO verlangen, dass auch automatisierte Entscheidungen (AI) unter voller Human-in-the-Loop-Kontrolle und ohne PII-Leak bleiben.

## Decision
**AI-Orchestrator wird ausschließlich lokal (Edge) und mit vier Schichten integriert:**
- **Human pre-authorization**: Scoped Delegation Token (Claims + Verifier + Time-Window + Use-Count) wird nur per WebAuthn + Policy-Engine erzeugt
- **Scoped Token**: AI erhält nur genau die Claims, die der User freigegeben hat – niemals Root-Key oder vollen Wallet-Zugriff
- **Four-Layer Enforcement**: 1. Policy-Engine (lokal), 2. Schema-Sanitization, 3. Runtime-ZKP-Check, 4. Post-Action Shredding
- **Model C**: AI darf nur innerhalb des Tokens agieren; Full-Wallet- oder per-Action-Human-Approval werden explizit abgelehnt (Skalierbarkeit + Sicherheit)

**Technische Umsetzung:**
- `@mitch/policy-engine` erweitert um `generateScopedDelegationToken`
- `@mitch/shared-crypto` signiert Token mit ephemerem Key + sofortigem $0x00-Shredding nach Use-Count
- AI-Inference läuft im Browser (WebAssembly / ONNX) – niemals Cloud

## Alternatives Considered
- Full Wallet Access für AI → verstößt massiv gegen Human-in-the-Loop + Blind Provider  
- Per-Action WebAuthn → skalierbar nicht möglich (verstößt gegen User Experience)  
- Cloud-AI → verstößt gegen Blind Provider + Crypto-Shredding

## Consequences
✅ **Human-in-the-Loop** bleibt Root (pre-authorization + Token-Lifetime)  
✅ **Crypto-Shredding** gilt auch für AI-Tokens ($0x00 nach Use-Count)  
✅ **Smart Policy Engine** entscheidet lokal über Scope + Sanitization  
✅ **Blind Provider** sieht niemals AI-Input oder Token-Inhalt (stateless)

## Acceptance Evidence
- Demo in `wallet-pwa` mit scoped AI-Query (z. B. „prüfe EHDS-Break-Glass“)
- 4 Test-Vektoren (Token-Overuse, Scope-Escape, Cold-Boot, Collusion)
- EVIDENCE_PACK-Erweiterung + Verknüpfung mit DECISION-007

## Implementation Notes
- Task A-07 in BACKLOG Phase 3 (AI-Orchestrator Integration)
- Verknüpfung mit ADR-002 (WebAuthn), ADR-004 (Consent) und ADR-006 (Recovery)

## References
- miTch-Manifest (Human-in-the-Loop + Crypto-Shredding)
- DECISION-007_AI_Orchestrator.md (Model C)
- EUDI-CIR Art. 11 (Automated Decision Making)
- DSGVO Art. 22 + 25

## Change Log
+ 2026-03-14: Initial Proposal (PROPOSED)