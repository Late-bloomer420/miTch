# AskMI release-candidate checklist

This checklist defines the minimum evidence for an AskMI release candidate. An RC is development/evaluation software; it is not certification or production approval.

## Scope and product truth

- [x] AskMI is the canonical product name; `miTch` is the historical repository name.
- [x] README links the current maturity and limitations statement.
- [x] Implemented, demo-only, experimental, planned, and externally unvalidated claims are distinguished.
- [ ] Release notes identify the exact commit and date tested.
- [ ] Known limitations and unresolved advisories are copied into the GitHub release notes.

## Security baseline

- [x] Browser CORS is deny-by-default and configured by explicit origin allowlist.
- [x] Verifier demo state is session-isolated, bounded, expiring, and rejects malformed session IDs.
- [x] Verifier keys are ephemeral by default; plaintext local persistence is explicit demo-only opt-in.
- [x] Wallet recovery share generation fails closed without an injected recovery-key provider.
- [x] CI blocks high-severity dependency advisories.
- [ ] External security review completed. **Not satisfied for this RC.**
- [ ] External EUDI interoperability/conformance evaluation completed. **Not satisfied for this RC.**

## Reproducible verification

Run from a clean checkout using the repository-pinned package manager:

```bash
pnpm install --frozen-lockfile
pnpm guard:rebrand
pnpm guard:archived-imports
pnpm audit --audit-level=high
pnpm test
pnpm lint
pnpm build
```

Record:

Full validation run recorded on 2026-08-19 against repository-resolvable revision
`04dee0f99754a8686195709348ca5b02ccc415e2`. Later PR review fixes require their own
focused validation record and do not retroactively inherit the full-run claim below.

- Install: passed with `--frozen-lockfile`
- Guards: rebrand and archived-import guards passed
- Audit: high-severity gate passed; 0 high, 0 moderate, 4 low advisories remain
- Tests: 47/47 Turbo tasks passed; wallet PWA 194/194 tests passed in the full run
- Lint: passed with 0 errors and 7 pre-existing `no-explicit-any` warnings
- Build: 30/30 Turbo tasks passed
- Residual runtime/test warnings: React `act(...)` warnings, missing PoC trust anchor warning in targeted verifier tests, and Node `url.parse()` deprecation warnings from dependencies

Focused PR-review validation was recorded on 2026-08-19 against executable revision
`818fc500524b5a48a1066caba47467bb9c5cd652`:

- Verifier backend: 16/16 files and 116/116 tests passed
- Verifier frontend: 1/1 file and 6/6 tests passed
- Wallet PWA: 16/16 files and 196/196 tests passed
- Production builds: verifier backend, verifier frontend, and wallet PWA passed
- Lint/type checks: verifier frontend passed; wallet passed with 0 errors and the same 7 pre-existing warnings
- Launchers: PowerShell syntax passed; Bash execution was unavailable because the validation host has no WSL distribution
- Browser behavior: configured origins `http://localhost:5174` and `http://localhost:5175` accepted; unlisted origin rejected with HTTP 403
- Session continuity: the same session ID was asserted across deep link, wallet requests, presentation, and status polling through `VERIFIED`

## Operational readiness still outside this RC

- Production key management/HSM or platform-keystore integration
- Independent penetration test and cryptographic review
- Official conformance testing and ecosystem interoperability
- Multi-instance/distributed verifier session storage
- Production issuer/verifier onboarding and trust governance
- Monitoring, incident response, backup/restore, privacy operations, and support ownership
