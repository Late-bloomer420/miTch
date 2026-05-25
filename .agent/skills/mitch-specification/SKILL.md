---
name: mitch-specification
description: Use for creating, refining, or validating miTch technical specifications, API contracts, TypeScript interfaces, Zod schemas, architecture notes, ADRs, backlog-to-spec breakdowns, and privacy-by-design implementation plans. Trigger on requests to draft a spec, design an interface, validate architecture consistency, map GDPR/EUDI requirements to code, or turn docs/backlog items into actionable implementation tasks.
---

# miTch Specification

Use this skill to turn vague work into precise, privacy-preserving engineering artifacts. Specs must be implementable in the current TypeScript monorepo and must preserve fail-closed behavior, minimization, and user-only custody.

## Workflow

1. Load current project sources before drafting:
   - `AGENTS.md`
   - `docs/BACKLOG.md`
   - `docs/_core/02_POLICY.md`
   - `docs/_core/03_ARCHITECTURE.md`
   - `docs/specs/02_Principles_and_NonNegotiables.md`
   - `docs/specs/04_Data_Flows_and_PII_Boundaries.md`
   - existing package `README.md`, `SPEC.md`, and tests near the target package.
2. Define the strict purpose:
   - What user or relying-party outcome is needed?
   - What data is strictly necessary?
   - Can a proof, predicate, or derived claim replace a raw value?
3. Specify boundaries:
   - wallet, issuer, verifier, policy engine, storage, audit log, shared crypto, shared types.
   - mark PII, metadata, proofs, keys, DIDs, nonces, and retention.
4. Define interfaces:
   - TypeScript types and Zod schemas for external inputs.
   - Explicit `Result`-style failure paths for business/security decisions where practical.
   - No `any` in new public interfaces unless the repo already requires it and the reason is documented.
5. Add privacy/compliance sections:
   - GDPR basis and minimization strategy.
   - Retention and crypto-shredding behavior.
   - Fail-closed behavior for unknown or malformed state.
   - Audit evidence that does not leak PII.
6. End with implementation and verification tasks:
   - files/packages touched,
   - negative tests,
   - command to run,
   - open decisions.

## Output Shape

Use `assets/templates/spec-template.md` for a full component spec. Keep generated docs concrete and cite existing repo paths. Do not invent package names when an existing package owns the behavior.

## References

- Read `references/api-patterns.md` for interface rules.
- Read `references/gdpr-mapping.md` for GDPR-to-architecture mapping.
