# Design: Versioned EUDI-shaped Claim/Predicate Contract (G-100.2 → G-100.1)

**Date:** 2026-06-10
**Status:** Draft for review
**Branch:** `feature/g100-claim-contract`
**Scope decisions (brainstorming):** Scope **A** (age beachhead only) · Home **A** (`@askmi/shared-types`) · Vocabulary **A** (EUDI/ISO-aligned + alias layer) · Representation **B** (JSON-Schema-first + ajv, with dependency-hygiene refinement) · EUDI-shaping **A** (SD-JWT path full, mdoc-PID/AV + ZKP as reserved additive bindings).

---

## 1. Problem

`AGE_NOT_VERIFIED` is non-deterministic in the beachhead (liquor age-check) flow (G-100.1). Root cause: the same age concept is spelled differently across layers with **no single source of truth**:

- policy-engine liquor test: `allowedClaims:['age']`, `provenClaims:['isOver18']`
- audit-export-schema: `dataCategories:['age_over_18']`
- predicates `CommonPredicates.ageAtLeast`: id `age_gte_18`, path `credentialSubject.dateOfBirth`, type `age_years`
- ConsentModal test: `proven_claims:['age >= 18']`
- mdoc package: flat `age_over_18` / `birth_date` (ISO 18013-5 mDL style)

Verification passes or fails depending on which name/path flows through. A second non-determinism source: `calculateAgeFromBirthDate()` uses `new Date()` (wall clock), so age-boundary cases flip with the test-run date.

## 2. EUDI reality (researched 2026-06-10)

Three relevant EU specs for proof-of-age — our planned flat `age_over_18`-over-`birthdate`-SD-JWT matches **none** precisely:

| Spec | Format | Age encoding | birthdate? | ZKP |
|---|---|---|---|---|
| EUDI PID (SD-JWT VC) `urn:eudi:pid:1` | SD-JWT VC | **nested** `age_equal_or_over: { "18": true }` | yes (`birthdate`, ISO-8601) | – |
| EUDI PID (mdoc) `eu.europa.ec.eudi.pid.1` | ISO 18013-5 | flat `age_over_18` (bool) | yes (`birth_date`) | – |
| EU Age Verification (AV) Profile `eu.europa.ec.av.1` | **mdoc only** | flat `age_over_18`/`age_over_NN` (bool) | **no** ("SHALL NOT include any other attribute") | **recommended** (ECDSA-ZKP) |

Two distinct data/trust models: **derived** (wallet holds `birthdate`, predicate computes age — our SD-JWT/C1 path) vs **pre-attested** (issuer already minimized to a boolean `age_over_18`, no birthdate — the EU AV product). They cannot share one predicate (AV carries no birthdate to derive from).

Sources:
- EUDI ARF PID Rulebook (Annex 3.01 v2.4.0): https://eudi.dev/2.4.0/annexes/annex-3/annex-3.01-pid-rulebook/
- EU Age Verification Blueprint — AV Profile (Annex A): https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/

## 3. Already in the codebase (reuse, do not rebuild)

- `mdoc` package: flat `age_over_18`/`age_over_21`, `birth_date` element identifiers (ISO mDL style).
- `predicates/evaluate.ts`: `age_years` type, `CommonPredicates.ageAtLeast`, dot-path resolution, fail-closed on missing path.
- `shared-types/predicates.ts`: `Predicate`/`PredicateClause`/`PredicateRequest` DSL + canonicalisation; `policy-engine` age-over-18 policy test; `oid4vp` HAIP test.

**Missing for EUDI shape:** SD-JWT-VC `age_equal_or_over` nested object; `urn:eudi:pid:1` vct; the canonical contract + format-binding layer; alias resolver; injectable `asOf`; `eu.europa.ec.av.1` reserved binding.

## 4. Design

### 4.1 One logical canonical claim + format bindings

A single logical canonical claim `age_over_18` (boolean predicate result), with a **format-binding table** describing how it is read/written per credential format:

- **SD-JWT VC** (`urn:eudi:pid:1`): `age_equal_or_over["18"]` (nested object) — binding logic + tests fully implemented in PR-A; wired into the live beachhead flow in PR-B (pilot path).
- **mdoc PID** (`eu.europa.ec.eudi.pid.1`): flat `age_over_18` — binding declared + tested against existing mdoc element ids; reuse current mdoc support.
- **AV Profile** (`eu.europa.ec.av.1`, mdoc-only, no birthdate): flat `age_over_18` — **reserved** binding: declared + contract-tested as a known target, not fully wired in v1.

Input modes: **derived** (`birthdate` ISO-8601 → compute) for SD-JWT path; **pre-attested** boolean for AV/mdoc. ZKP: contract capability flag, **off** in v1 (note: AV uses ECDSA-ZKP, not BBS+); additive later.

### 4.2 Placement (dependency hygiene)

- **Source of truth:** versioned JSON Schema (Draft 2020-12) `shared-types/src/contracts/claim-contract.v1.json`, `$id` suffix `/v1`. Pure JSON data → keeps `shared-types` a zero-runtime-dependency leaf (it has none today; the browser wallet bundle imports it).
- **`shared-types`:** canonical TS types (hand-authored to the schema), `CLAIM_CONTRACT_VERSION = "1.0.0"`, alias→canonical map, `resolveClaim(name)` pure fail-closed resolver, format-binding table.
- **`predicates`:** canonical age predicate builder with **injectable `asOf: Date`** (replaces ad-hoc `CommonPredicates.ageAtLeast`; defaults to `new Date()` in prod, fixed in tests).
- **`verifier-sdk`:** the only new `ajv` dependency — `validateClaimRequest()` compiles the schema and fail-closed-validates external requests; re-exports schema + canonical types for external verifiers.

### 4.3 Contract content v1.0.0

- Canonical claims: `birthdate` (disclosed input, ISO-8601 full-date) · `age_over_18` (boolean predicate result).
- Canonical predicate: `age_over_18` ≔ age(`birthdate`, `asOf`) ≥ 18 — stable id, stable canonical hash.
- Alias table (deprecated → canonical, fail-closed on unknown → `UNKNOWN_CLAIM`):
  - → `birthdate`: `dateOfBirth`, `birthDate`, `birth_date`, `age`
  - → `age_over_18`: `isOver18`, `age >= 18`, `over18`, `age_gte_18`
- Format-binding table as in §4.1.

### 4.4 Data flow

External request → `verifier-sdk.validateClaimRequest` (ajv, fail-closed) → `resolveClaim` (alias→canonical) → canonical predicate builder (with `asOf`) → existing `evaluatePredicates` → `age_over_18` result. policy-engine uses canonical names internally; format bindings translate at the credential edge.

### 4.5 Versioning

`CLAIM_CONTRACT_VERSION` + schema `$id` `/v1`. Additive (new claims, new bindings, ZKP flag) = minor. Rename/remove canonical = major + new `claim-contract.v2.json`. Aliases never removed within a major.

### 4.6 Error handling (fail-closed)

Unknown claim name → `UNKNOWN_CLAIM`. Malformed request → ajv rejection (privacy-safe message, no PII echo). Missing `birthdate` on derived path → existing `MISSING_PATH`. No silent defaults anywhere.

### 4.7 Testing

Contract tests (merge-blocking): alias resolution (every alias → expected canonical) · fail-closed on unknown claim · canonical predicate hash stable (snapshot) · ajv accepts valid / rejects malformed+unknown · `CLAIM_CONTRACT_VERSION` matches schema `$id` · deterministic round-trip (fixed `birthdate` + fixed `asOf` → stable `age_over_18`, incl. the on/just-before-birthday boundary) · format-binding read/write for SD-JWT `age_equal_or_over` and mdoc flat; AV binding declared/asserted as reserved.

## 5. Work breakdown — clean, self-contained PRs

**PR-A — G-100.2 contract core (additive, no flow behavior change).**
shared-types schema + types + version + alias map + `resolveClaim` + format-binding table; predicates canonical age builder with `asOf`; verifier-sdk ajv validator + re-export; full contract test suite. Green and mergeable on its own; changes no existing flow output.

**PR-B — G-100.1 wiring + determinism (depends on PR-A).**
Wire policy-engine, `predicates/evaluate.ts`, verifier-demo backend to the canonical contract via `resolveClaim`; migrate `CommonPredicates.ageAtLeast` → canonical builder; thread `asOf`; make the liquor scenario deterministic 10/10. Behavior fix.

**PR-C — verifier-browser deprecation (independent).**
Move `verifier-browser` (mockResponse `success:true` stub) to `archive/`; add CI import-guard preventing re-import from active tree. Closes the CRITICAL-if-active security-narrative gap. Independent of A/B.

Sequence: PR-C anytime (independent) · PR-A → PR-B. Each is one signed squash-merge to `master`.

## 6. Out of scope (reserved, additive later)

- Full mdoc `eu.europa.ec.av.1` issuance/presentation path.
- ZKP (ECDSA-based per AV Profile; distinct from deferred BBS+).
- Claims beyond the age beachhead (residency, EHDS, medical) — same contract pattern, later minor versions.
