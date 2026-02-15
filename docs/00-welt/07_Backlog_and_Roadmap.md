# Backlog & Roadmap (Pilot Hardening Track)

Stand: 2026-02-12
Status: **IMPLEMENTATION ACTIVE** (security-first, fail-closed, pilot-focused)

---

## 1) Current reality (not concept-only anymore)
miTch is now a working TypeScript verifier service with:
- fail-closed verification gates
- deny-code model + KPI observability
- audit/evidence flows
- resolver quorum hardening
- WebAuthn re-auth hardening path (allowlist/signed/native-hook with strict checks)

This backlog replaces the old concept-only framing.

---

## 2) Done (pilot-critical baseline)

### Core verifier + operations
- [x] Request schema/semantic guards
- [x] Binding checks (nonce/hash/audience/expiry)
- [x] Rate limiting + distributed request budget
- [x] Policy evaluation + crypto verification path
- [x] Append-only receipts + audit verification
- [x] KPI endpoints/dashboard/check CLI + CI security gate

### Security hardening shipped
- [x] Strong re-auth gate + proof-fatigue controls
- [x] WebAuthn signed assertion verification scaffold
- [x] Native hook mode moved from global bypass to request-bound cryptographic evidence
- [x] Revocation baseline (credentialId + strict status source checks + revoked-only cache)
- [x] DID resolver multi-source quorum + inconsistency telemetry
- [x] No-silent-allow assertion + dedicated deny codes
- [x] false_allow_total zero-tolerance (critical)

### Governance/repo readiness
- [x] LICENSE / SECURITY.md / CONTRIBUTING.md / CODEOWNERS / NOTICE
- [x] CI workflow for compile/tests/KPI checks

---

## 3) Active priorities (next highest value)

### P0 — Must for stronger pilot assurance
- [ ] **WebAuthn native verifier real implementation**
  - replace hook/scaffold with authenticator-level verification (counter/key/challenge binding)
- [ ] **Revocation semantics v2+**
  - move from light scaffold toward fuller StatusList2021 behavior (still scope-controlled)
- [ ] **Recovery security design**
  - practical anti-abuse model (social recovery/coercion/phishing resistance)

### P1 — Important near-term
- [ ] **PQ/hybrid signature migration path v1**
  - crypto-agility exists; add dual/hybrid verification profile scaffolding
- [ ] **Issuer trust/reputation controls**
  - basic policy-driven trust constraints + evidence traceability
- [ ] **Pilot legal completion track**
  - external GDPR legal opinion + binding pilot policy language

### P2 — Operational maturity
- [ ] Alert routing playbook + escalation ownership
- [ ] KPI trend snapshots for weekly pilot governance
- [ ] Hardening regression bundle (attack replay pack)

---

## 4) Immediate next batch queue (small autonomous batches)

1. [x] Add WebAuthn native-mode metric for **actual usage events** (not only config posture)
2. [x] Add targeted test vectors for signed/native mismatch and replay edge cases
3. [ ] Add doc: "security_profile_score interpretation + limitations" with runbook actions
4. [ ] Start native verifier adapter interface contract (strict input/output and deny mapping)

## 4b) Repo-first memory discipline (while embeddings recall is blocked)

### Files to keep current every batch
- `STATE.md` (single-screen status)
- `07_Backlog_and_Roadmap.md` (Now/Next/Later priorities)
- `00_README.md` (index of new artifacts)
- workspace `memory/YYYY-MM-DD.md` (short daily chronology)

### End-of-batch update protocol
1. Confirm test baseline: `npm test` + `npm run kpi:check`
2. Update/append numbered design/security note if behavior changed
3. Refresh `STATE.md` (last batch + next 3 actions + blockers)
4. Refresh backlog queue ordering (keep “Now” small)
5. Commit and push with explicit hardening intent

---

## 5) Hard guardrails (do not violate)
- False allow tolerance: **0**
- Fail-open behavior: **forbidden**
- Raw PII leakage in logs/evidence: **forbidden**
- “Strong mode” claims without matching verifier config/evidence: **forbidden**

---

## 6) Definition of pilot-ready (minimum)
Pilot-ready only when all are true:
- [ ] false_allow_total remains 0 under adversarial tests
- [ ] WebAuthn path is cryptographically verified end-to-end for selected mode
- [ ] Revocation path degrades safely under source failure (deny-biased)
- [ ] Resolver quorum drift is observable + actionable
- [ ] Evidence export supports incident/adjudication workflow
- [ ] Legal/privacy claims match implemented behavior (no overclaiming)
