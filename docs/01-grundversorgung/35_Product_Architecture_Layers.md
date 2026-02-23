# 35 — Product Architecture Layers (Core → Shield → Orchestrator)

Stand: 2026-02-11

## Purpose
Keep scope focused while preserving the long-term vision.

---

## Layer 1: miTch Core (MVP / now)
**Mission:** Verifiable trust with minimal disclosure.

### Included
- Policy-based request evaluation
- Proof mediation (no raw identity disclosure)
- Binding/replay protection
- Deterministic deny reason codes
- PII-minimal receipts/audit trail

### Excluded (for now)
- Browser runtime protection
- AI orchestration privacy middleware
- User-wide telemetry/privacy dashboard

### Success metric
Business Case #1 (Age Verification) works end-to-end with 2 RPs and zero raw-PII leakage in verifier path.

---

## Layer 2: miTch Shield (Phase 2)
**Mission:** Privacy/safety runtime for web interactions.

### Candidate capabilities
- Metadata minimization beyond payload controls
- Web request visibility (who asks for what)
- User notifications for high-risk/hidden data requests
- Policy controls for block/allow/notify behavior

### Dependency on Core
Uses Core policy primitives and decision receipts for user-visible trust events.

---

## Layer 3: miTch Orchestrator (Phase 2/3)
**Mission:** User-controlled AI mediation across external models/tools.

### Candidate capabilities
- Semantic sanitization before external model calls
- Per-model/per-tool policy boundaries
- Secret/PII redaction with purpose constraints
- User-readable evidence of what left the boundary

### Dependency on Core
Reuses identity/authorization and policy semantics from Core; extends to AI I/O governance.

---

## Non-negotiable cross-layer rule
No layer may reintroduce centralized identity custody or hidden profiling.
