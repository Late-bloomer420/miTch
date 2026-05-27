---
name: mitch-privacy-firewall
description: Use for miTch privacy, policy-engine, fail-closed, GDPR-by-construction, DecisionCapsule, deny-code, verifier, wallet, credential, storage, audit-log, unlinkability, crypto-shredding, and zero-knowledge review work. Trigger on requests to audit code or architecture for privacy risks, validate PolicyManifest or disclosure decisions, design privacy-preserving data flows, or check whether an implementation preserves structural non-existence and user-only custody.
---

# miTch Privacy Firewall

Use this skill as a strict review workflow for miTch's privacy boundary. The default posture is fail-closed: unknown, ambiguous, or unverifiable behavior must be treated as DENY or FAIL until the code proves otherwise.

## Core Workflow

1. Load current repo context before relying on references:
   - `AGENTS.md`
   - `docs/_core/02_POLICY.md`
   - `docs/_core/03_ARCHITECTURE.md`
   - `docs/00-welt/mitch_policy_manifest.md`
   - `docs/specs/04_Data_Flows_and_PII_Boundaries.md`
   - `docs/specs/06_Policy_Engine_Spec.md`
   - `src/packages/shared-types/specs/decision_capsule.md`
2. Identify the privacy boundary:
   - What data, credential, claim, proof, key, nonce, DID, or policy artifact enters?
   - Which package owns the boundary?
   - Which actor has custody: wallet, issuer, verifier, policy engine, or storage?
3. Trace sinks:
   - logs, telemetry, audit events, IndexedDB/local storage, network calls, caches, exported evidence, and UI state.
   - Raw PII at a sink is a failure unless there is an explicit documented basis and protection.
4. Check fail-closed behavior:
   - Missing policy -> DENY.
   - Unknown verifier, issuer, schema, DID resolution, revocation status, jurisdiction, or credential status -> DENY unless the strict profile explicitly defines another safe behavior.
   - Exceptions and parse errors must map to safe failure, not silent ALLOW.
5. Check DecisionCapsule binding:
   - Required fields are `verdict`, `decision_id`, and `policy_hash`.
   - `policy_hash` means the hash of the active PolicyManifest. Do not replace it with `policy_manifest_id` or a matched-rule hash.
6. Produce findings first:
   - Use `PASS`, `FAIL`, or `UNKNOWN`.
   - Treat `UNKNOWN` as `FAIL` for implementation decisions.
   - Cite concrete files, functions, and tests.

## Repo Hotspots

- Policy firewall: `src/packages/policy-engine/src/`
- Shared policy types: `src/packages/shared-types/src/policy.ts`
- Decision capsule schema/spec: `src/packages/shared-types/schemas/decision_capsule.schema.json`, `src/packages/shared-types/specs/decision_capsule.md`
- Crypto and DID boundaries: `src/packages/shared-crypto/src/`
- Secure storage and memory: `src/packages/secure-storage/`, `src/packages/secure-memory/`
- Verifier flows: `src/packages/oid4vp-verifier/`, `src/packages/verifier-sdk/`, `src/apps/verifier-demo/`
- Wallet flows: `src/packages/wallet-core/`, `src/apps/wallet-pwa/`
- Evidence and audit: `src/packages/audit-log/`, `docs/ops/EVIDENCE_PACK_P0.md`

## References

- Read `references/axioms.md` for the invariant set.
- Read `references/audit-checklist.md` for privacy audit steps.
- Read `references/reason-codes.md` when mapping a failure to a stable finding category.
