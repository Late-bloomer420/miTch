# 55 — External Findings (Expanded): Systemic, Governance, and Long-Horizon Risks

Stand: 2026-02-11  
Source integrated from: `VON_CLAUDE.txt` (expanded section)

## Why this file exists
These risks typically appear after early success (scale, ecosystem effects, regulatory pressure).
They are not all immediate blockers for MVP, but ignoring them early creates expensive redesign later.

---

## A) Ecosystem / Scale Risks

### A1) Credential Inflation & Trust Erosion
- Risk: too many low-quality issuers reduce trust in credentials.
- Impact: verifier centralization around few issuers; ecosystem lock-in.
- Action: issuer quality metadata, trust scoring policy, freshness decay model.
- Phase target: 8

### A2) Verifier Cartel / Exclusion Behavior
- Risk: major verifiers enforce proprietary issuer lock-in.
- Impact: open standards erode, user sovereignty weakens.
- Action: verifier transparency reports + compliance policy + certification model.
- Phase target: 8

### A3) Revocation at Scale
- Risk: credential status checks become bottleneck/latency/failure domain.
- Impact: unsafe accepts or operational collapse under load.
- Action: Status List 2021-style architecture, caching strategy, SLA-aware fail-closed rules.
- Phase target: 6-7

---

## B) Advanced Security / Cryptography Risks

### B1) Quantum Readiness (Harvest-now, decrypt-later)
- Risk: long-term breakage of classical signatures/encryption.
- Impact: retroactive compromise of stored encrypted artifacts.
- Action: crypto-agility roadmap + hybrid signature readiness + migration protocol.
- Phase target: 7+

### B2) Supply Chain Attack Surface
- Risk: compromised dependency introduces malicious behavior.
- Impact: key exfiltration, policy bypass, hidden backdoors.
- Action: dependency pinning, SBOM, automated scanning, source allowlists.
- Phase target: 6

### B3) DID Resolution Integrity / Eclipse-style Risks
- Risk: manipulated resolver output (network/path compromise).
- Impact: trust anchor spoofing.
- Action: multi-resolver quorum + cache strategy + resolver integrity checks.
- Phase target: 7

---

## C) Governance / Legal / Jurisdiction Risks

### C1) State Backdoor Pressure
- Risk: legal demands for access mechanisms.
- Impact: architecture compromise vs market exclusion.
- Action: explicit legal strategy + transparency statement + technical impossibility position.
- Phase target: now (strategy), 7+ (institutionalization)

### C2) Jurisdictional Policy Conflict
- Risk: incompatible legal demands across regions.
- Impact: inconsistent policy outcomes, compliance deadlocks.
- Action: jurisdiction-aware policy profiles + incompatibility deny rule.
- Phase target: 8

### C3) Policy Governance Ambiguity
- Risk: unclear authority for rule changes.
- Impact: trust breakdown and policy drift.
- Action: change governance model + versioning + stakeholder review protocol.
- Phase target: 8-9

### C4) GDPR Legal Opinion Gap
- Risk: assumptions around crypto-shredding and roles not externally validated.
- Impact: pilot/legal friction.
- Action: external legal memo and role mapping before scaled pilot.
- Phase target: pre-pilot

---

## D) Human / Inclusion Risks

### D1) Credential Hoarding & Unsafe Backup Behavior
- Risk: users keep/export too many credentials unsafely.
- Impact: expanded leak surface.
- Action: lifecycle UX, expiry nudges, export warnings.
- Phase target: 7+

### D2) Accessibility vs Security Trade-offs
- Risk: secure UX patterns may conflict with assistive flows.
- Impact: exclusion or security bypass.
- Action: accessibility-aware secure interaction patterns + targeted testing.
- Phase target: 7+

---

## E) Prioritization Signal
- Immediate/Pilot-Critical: supply chain controls, revocation baseline, legal opinion, backdoor strategy statement.
- Near-term: issuer/verifier governance mechanics, DID resilience.
- Long-term: quantum migration, DAO-grade policy governance.
