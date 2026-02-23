# 11 — MVP Gap Analysis (Concept → Buildable MVP)

Stand: 2026-02-11  
Status: Derived from current concept pack (T0) and normalized into implementation gaps.

---

## 1) Executive Summary

miTch has a strong conceptual foundation (principles, boundaries, threat model), but the current package is still concept-first.
The main gap is **operationalization**: deterministic runtime behavior, concrete crypto stack choices, issuer/RP integrations, and verifiable delivery evidence.

**Primary blocker to MVP:** no fully specified and tested end-to-end implementation contract yet (policy runtime + proof stack + binding + revocation + RP integration).

---

## 2) Gap Matrix (Current vs Required for MVP)

## A. Credential & Proof Stack
**Current:** Options and principles documented; no final stack lock for each predicate class.  
**Gap:** Lack of implementable proof strategy per use case.  
**Needed:**
- Final stack decision per predicate type (boolean/range/membership/equality)
- Interop profile with at least 1 issuer format
- Verifier implementation contract (algorithms, key formats, status checks)
- Performance budget per flow (target + measured)

**MVP Exit Criteria:** 2 predicates verified E2E with measured latency and deterministic verification outcomes.

## B. Policy Engine Runtime
**Current:** Policy concept + gate precedence in docs.  
**Gap:** No proven deterministic evaluator behavior in code + migration strategy.  
**Needed:**
- Versioned policy schema + semantic versioning rules
- Deterministic evaluator with explicit deny reason codes
- Deny precedence and fail-closed behavior guaranteed in tests
- Policy migration compatibility rules (v0→v1)

**MVP Exit Criteria:** Full regression suite passes, no ambiguous/missing path that can fail open.

## C. Binding / Replay Protection
**Current:** Binding principles documented (nonce/hash/audience/expiry).  
**Gap:** No complete canonicalization and replay handling implementation contract.  
**Needed:**
- Canonical request hashing spec (stable across implementations)
- Nonce storage/TTL and replay semantics
- Audience and expiry validation rules
- Clock skew policy

**MVP Exit Criteria:** Replay/context-swap attacks fail in adversarial tests.

## D. Issuer & Status/Revocation Integration
**Current:** Actor model exists; integration boundary open.  
**Gap:** No committed issuer adapter and status strategy.  
**Needed:**
- One concrete issuer connector (or realistic issuer simulator with fidelity constraints)
- Revocation/status privacy-preserving checks
- Degraded-mode policy (issuer/status unavailable)

**MVP Exit Criteria:** One real/realistic issuer flow works in full E2E scenario.

## E. Wallet / Device Runtime
**Current:** Edge-first principle clear, implementation unspecified.  
**Gap:** Key lifecycle, storage, and user-side transparency not fully defined.  
**Needed:**
- Key lifecycle (generate/use/rotate/destroy)
- OS-backed secure storage where available
- User-visible local receipt trail
- Multi-device baseline strategy

**MVP Exit Criteria:** User can inspect what was shared, for whom, and why.

## F. Metadata Privacy Controls
**Current:** Good conceptual controls documented.  
**Gap:** No enforceable “privacy budget” in runtime/logging pipeline.  
**Needed:**
- Log redaction/minimization rules in code
- Stable identifier prohibition checks
- Pairwise audience separation
- Retention/TTL enforcement by field class

**MVP Exit Criteria:** Privacy review passes; no stable cross-RP identifier leakage.

## G. API/SDK for RPs
**Current:** High-level integration intent.  
**Gap:** No strict integration contract for independent RP onboarding.  
**Needed:**
- Versioned request/response schemas
- Error and deny reason taxonomy
- Verification SDK starter package
- Reference integration example

**MVP Exit Criteria:** External RP can integrate with docs + SDK without direct core team intervention.

## H. Security Delivery (DevSecOps)
**Current:** Threat model exists.  
**Gap:** Supply chain and release assurance not formalized.  
**Needed:**
- Dependency pinning + SBOM generation
- CI security scans and policy checks
- Release signing/provenance
- Secrets handling and environment segregation

**MVP Exit Criteria:** Build/release pipeline produces auditable artifacts with security gates.

## I. Test Evidence & Operations
**Current:** Test directions exist in text.  
**Gap:** No integrated evidence package for pilot readiness.  
**Needed:**
- E2E + adversarial test packs
- Performance baselines (p50/p95)
- Incident and compromise response playbook
- Operational SLOs and runbooks

**MVP Exit Criteria:** Pilot readiness evidence pack available and reproducible.

---

## 3) Missing Specs to Add Immediately (High Leverage)

1. **Canonicalization Spec** for request hash/signature inputs
2. **Clock & Expiry Policy** (clock skew windows, hard/soft expiry)
3. **Policy Version Migration Spec**
4. **Deny Reason Code Catalog** (machine + human readable)
5. **Data Retention Matrix** (field × location × TTL × legal basis)
6. **Compromise Playbooks** (device key compromise, issuer key compromise, verifier key rotation)
7. **Cryptographic Agility Plan** (algorithm updates without ecosystem break)

---

## 4) Recommended MVP Scope (Strict)

To avoid scope creep, MVP should include:
- 1 issuer integration
- 2 relying parties
- 2 predicate classes (e.g., age threshold + residency)
- Deterministic policy evaluation + fail-closed proof
- Replay/binding hardening in adversarial tests
- PII-minimal WORM receipts

Everything else remains post-MVP.

---

## 5) MVP Go/No-Go Criteria

**Go only if all are true:**
- No raw PII on verification server paths
- Deterministic deny behavior with reason codes
- Replay/context swap resistant in tests
- Audit receipts verifiable and PII-minimal
- External RP integration completed from docs
- Residual risk explicitly documented (no “unhackable” claims)
