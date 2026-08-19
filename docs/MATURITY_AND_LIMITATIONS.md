# AskMI maturity and known limitations

**Status:** living product-readiness statement
**Canonical product name:** AskMI
**Repository name:** `miTch`

## Current maturity

AskMI is development and evaluation software. The repository demonstrates a substantial, tested implementation, but it has not been independently certified, formally evaluated, or validated as production-ready.

Use these labels when reading or writing documentation:

- **Implemented / repository-tested:** code exists and repository-controlled tests exercise specified cases. Coverage is bounded by those tests.
- **Demo-only:** mock issuer, verifier scenarios, local trust material, sample credentials, browser demo, and reference UX used to illustrate a flow.
- **Experimental:** code-backed exploration that may have incomplete interoperability, unstable interfaces, or unresolved assurance questions.
- **Planned:** roadmap, specification, proposed integration, stub, or design without a completed implementation claim.
- **Externally unvalidated:** no independent security audit, certification, conformance decision, or production ecosystem validation has established the claim.

Unless an artifact explicitly identifies independent evidence, all implementation and compliance claims are externally unvalidated.

## Product boundary: middleware and reference wallet

AskMI’s product direction is wallet-edge identity middleware: policy evaluation, minimal-disclosure decisions, protocol/crypto components, verifier integration, and transparency/audit functions that can be integrated into compatible wallet systems.

The repository also embeds `wallet-pwa`. It is a **reference wallet and integration harness** used to develop and demonstrate AskMI. Its existence does not make AskMI a certified wallet product, and behavior demonstrated with `issuer-mock` and `verifier-demo` does not establish interoperability with national EUDI Wallets, production issuers, or relying parties.

## Known limitations and open assurance work

- No external security audit, penetration test, Common Criteria evaluation, EUDI certification, or regulator approval is evidenced for the product as a whole.
- Standards-related tests are repository tests, not official conformance-suite results.
- Demo and local development flows rely on mock services, fixtures, sample credentials, and development trust configuration.
- Browser JavaScript cannot provide strong guarantees about secret erasure or constant-time execution; browser RAM exposure remains a residual risk.
- WebAuthn behavior depends on platform/authenticator support and deployment configuration. Development fallbacks or fixtures must not be treated as production hardware binding.
- Secure storage and key-management components require deployment-specific threat modeling, platform integration, recovery design, and operational controls.
- Network trust, issuer/verifier onboarding, trust-list governance, certificate lifecycle, revocation availability, telemetry, backups, incident response, and privacy operations are not solved merely by running the demos.
- Protocol and mdoc support is scoped to implemented/tested paths and is not a claim of complete profile or ecosystem interoperability.
- Post-quantum, anchoring/L2, AI/MCP, and similar forward-looking components should be treated as experimental unless a narrower artifact provides current evidence.
- Legal and compliance mappings are engineering analyses, not legal advice or proof of compliance. Historical percentages count internally mapped requirements and must not be presented as certification or objective readiness scores.
- Documentation includes historical plans and dated evidence. A plan is not implementation; a dated passing result is not a guarantee about the current checkout.

## Evidence rules

1. Prefer reproducible commands and current CI results over static totals.
2. State exactly what was tested, on which revision/date, and what was not tested.
3. Do not use “certified-ready,” “production-ready,” “fully compliant,” or percentage readiness claims without a named external authority and evidence.
4. Qualify security absolutes such as “never,” “all,” and “zero” to the specific tested design path.
5. Treat `docs/qa/` as dated internal evidence records, not third-party assurance.
6. Treat compliance matrices and security targets as evaluation inputs until an external body validates them.

## Naming rule

Use **AskMI** for the product, architecture, active applications, and `@askmi/*` packages. Use **`miTch`** only for the repository name/path, historical references, or compatibility identifiers that still exist. Historical documents retain context but do not override this rule.
