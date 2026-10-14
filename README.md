# AskMI — The Forgetting Layer

Development/evaluation tooling for purpose-bound identity request governance, selective disclosure and evidence.
`miTch` is the historical repository name; active packages use `@askmi/*`.

> **Current boundary:** not certified or production-ready. The browser wallet and mock issuer are reference/test harnesses.
> The real SD-JWT demo currently discloses numeric age, not exclusively an age boolean. Known request-binding,
> eligibility, single-use and audit/evidence gaps are open. Do not use demo `ok:true` as authorization.

## Read the evidence first

| Source | Purpose |
|---|---|
| [Current findings and claim limits](docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md) | Implemented scope, reproduced findings, unimplemented designs and residuals |
| [Dated executable-path evidence](docs/qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) | Exact source SHA/runtime, tests and synthetic counterexamples |
| [STATE](STATE.md) / [BACKLOG](docs/BACKLOG.md) | Current snapshot / task state |
| [Release roadmap](docs/RELEASE_READINESS_ROADMAP.md) / [#142](https://github.com/Late-bloomer420/miTch/issues/142) | Technical gates; no unchecked gate inferred complete |
| [GTM roadmap](docs/GTM_SPRINT_ROADMAP.md) / [#143](https://github.com/Late-bloomer420/miTch/issues/143) | Buyer hypotheses, stop rules and conditional pilot |
| [Docs canon](docs/DOCS_CANON.md) | One authority per topic and historical-document rules |

## What exists

The monorepo contains policy, crypto, protocol, storage, audit, data-flow and demonstration components.
Issuer signatures, SD-JWT disclosure-digest validation, KB-JWT and scoped policy negatives are repository-tested.
Pairwise DIDs and a legacy single-use credential pool are implemented in named paths, not proof of universal unlinkability.
Local buffer overwrites and tamper-evident receipts are not physical RAM erasure or proof of verifier deletion.

The `@askmi/connect` product/session/API contracts were accepted in #158/#159/#160. The package is not yet implemented
at executable baseline `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`; #170 owns the first safe active slice.

## Quick start — synthetic local evaluation only

```bash
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch
pnpm install --frozen-lockfile   # packageManager: pnpm 9.15.9
pnpm build
pnpm test
pnpm lint
pnpm guard:rebrand
pnpm guard:archived-imports
```

Use the repository's pinned pnpm for child commands too. CI uses Node 22; local 14 October evidence used Node 24.19.0.
Run counts are dated evidence, never static success badges. `pnpm dev` has a documented isolated PoC startup limitation;
see [ADOPT path evidence](docs/qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md) for per-service startup and known gaps.

## Reference paths

- `wallet-pwa`: local credential/policy reference harness.
- `issuer-mock`: synthetic SD-JWT issuance, not national PID issuance.
- `verifier-demo`: distinct real SD-JWT, locally signed predicate and simulated routes; they do not share identical guarantees.
- [Public synthetic demo](https://late-bloomer420.github.io/miTch/): illustrative UI, not executable-path/interoperability/certification evidence.

## Next work

[#170](https://github.com/Late-bloomer420/miTch/issues/170): server-owned request and eligibility;
[#171](https://github.com/Late-bloomer420/miTch/issues/171): real SD-JWT single-use;
[#172](https://github.com/Late-bloomer420/miTch/issues/172): runtime audit/telemetry sinks;
[#173](https://github.com/Late-bloomer420/miTch/issues/173): source-bound, exact-byte evidence.
Baseline security reconciliation remains with #141 and the existing security remediation roadmap.

External security review, exact-profile official Android/iOS interoperability, conformance and deployment-specific privacy/operations
remain gates. No CIR percentage, LoA High or “never PII on any server” claim is established by this repository.

## License

[Apache 2.0](LICENSE). Maintainer: [@Late-bloomer420](https://github.com/Late-bloomer420).
