# 25 — Sprint 1 Task Board (Execution-Ready)

Stand: 2026-02-11  
Sprint length: 1 week

## Goal
Freeze MVP contracts and implement deterministic policy/binding core with test scaffolding.

---

## Must-do Tasks

1. **ADR closure workshop (001/004/006/008)**
- Owner: Architecture
- Output: accepted/rejected decisions with rationale

2. **Policy evaluator skeleton**
- Owner: Backend
- Output: deterministic evaluator pipeline + fail-closed default

3. **Deny code integration**
- Owner: Backend
- Output: all reject paths mapped to `21_Deny_Reason_Code_Catalog.md`

4. **Canonical hash implementation (v0)**
- Owner: Security Eng
- Output: hash module + 10 test vectors

5. **Nonce store baseline**
- Owner: Platform
- Output: atomic consume + TTL behavior

6. **Test harness bootstrap**
- Owner: QA
- Output: automated suite for schema/policy/binding deny cases

---

## Acceptance Criteria
- No unresolved normative ambiguity in v0 API + binding spec
- At least 20 automated deny-path tests passing
- Replay test (same nonce same audience) reliably denied
- One happy-path ALLOW test passing end-to-end (mock proof)
