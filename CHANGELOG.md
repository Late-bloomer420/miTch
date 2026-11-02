# Changelog

What changed on `master`, one line per merged pull request, newest first.

**Rules**

- This file records _what_ was merged, not whether it works. Test results, verified scope and dates live in the linked records under [`docs/qa/`](docs/qa/README.md); task state lives in [`docs/BACKLOG.md`](docs/BACKLOG.md); the current operating snapshot lives in [`STATE.md`](STATE.md). Do not copy test counts or status claims here.
- Every pull request adds its own line under the current month: its title, the PR link and, if it adds or updates a QA record, a link to that record.
- Entries are not rewritten after merge. A later correction is a new line that links the earlier PR.
- The log starts at the evidence baseline of 2026-10-14. Earlier changes: [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md) and `git log`.

## 2026-11

- docs: introduce CHANGELOG.md and record the #189 merge in STATE and backlog ([#249](https://github.com/Late-bloomer420/miTch/pull/249))

## 2026-10

- fix(deps): pin fast-uri >=3.1.7 — clear 7 high advisories (SEC-AUDIT-2) ([#229](https://github.com/Late-bloomer420/miTch/pull/229)) — evidence: [`SECURITY_AUDIT_2_FAST_URI_2026-10-25.md`](docs/qa/SECURITY_AUDIT_2_FAST_URI_2026-10-25.md)
- chore: pre-transfer cleanup — restore ADOPT-1 spec, ignore local tool output ([#233](https://github.com/Late-bloomer420/miTch/pull/233))
- fix(deps): pin body-parser 1.20.9 for the Express 4 runtime chain (SEC-AUDIT-2) ([#227](https://github.com/Late-bloomer420/miTch/pull/227)) — evidence: [`SECURITY_AUDIT_2_BODY_PARSER_2026-10-25.md`](docs/qa/SECURITY_AUDIT_2_BODY_PARSER_2026-10-25.md)
- chore(deps): upgrade Vite 6 to 8 in wallet-pwa and verifier-demo frontend ([#230](https://github.com/Late-bloomer420/miTch/pull/230))
- test(shared-crypto): share SLH-DSA keygen/sign fixture on top of #225 ([#226](https://github.com/Late-bloomer420/miTch/pull/226)) — evidence: [`PQC_SLH_DSA_TEST_TIMEOUT_2026-10-25.md`](docs/qa/PQC_SLH_DSA_TEST_TIMEOUT_2026-10-25.md)
- test(shared-crypto): scoped 120s timeout for SLH-DSA-SHA2-128s tests ([#225](https://github.com/Late-bloomer420/miTch/pull/225))
- docs(qa): record wallet-side WebAuthn assertion verification (#218) ([#223](https://github.com/Late-bloomer420/miTch/pull/223)) — evidence: [`WEBAUTHN_ASSERTION_VERIFICATION_2026-10-25.md`](docs/qa/WEBAUTHN_ASSERTION_VERIFICATION_2026-10-25.md), [`WEBAUTHN_FAIL_CLOSED_2026-07-12.md`](docs/qa/WEBAUTHN_FAIL_CLOSED_2026-07-12.md)
- fix(connect): enforce stored age profile and integrate wallet handoff ([#224](https://github.com/Late-bloomer420/miTch/pull/224)) — evidence: [`CONNECT_PROFILE_INTEGRATION_2026-10-25.md`](docs/qa/CONNECT_PROFILE_INTEGRATION_2026-10-25.md)
- feat(wallet): verify passkey-signed decision capsules (closes #218) ([#222](https://github.com/Late-bloomer420/miTch/pull/222))
- feat(wallet): verifiable proof tokens signed with the identity key ([#221](https://github.com/Late-bloomer420/miTch/pull/221))
- feat(shared-crypto): verifiable passkey identity assertions ([#219](https://github.com/Late-bloomer420/miTch/pull/219))
- test(verifier-backend): raise vitest timeout to 30s — app-import flake fix ([#211](https://github.com/Late-bloomer420/miTch/pull/211))
- fix(wallet): boot once per mount under StrictMode ([#217](https://github.com/Late-bloomer420/miTch/pull/217))
- fix(wallet-pwa,shared-crypto): resolve onboarding and WebAuthn console warnings ([#216](https://github.com/Late-bloomer420/miTch/pull/216))
- chore: unblock the merge queue — advisory Gemini review, re-applied #147/#148 ([#153](https://github.com/Late-bloomer420/miTch/pull/153))
- style(wallet): run Prettier on App.tsx ([#215](https://github.com/Late-bloomer420/miTch/pull/215))
- feat(wallet): cut navigation from 10 to 7 tabs ([#213](https://github.com/Late-bloomer420/miTch/pull/213))
- fix(wallet): honest trust badge and polish the trusted channel layout ([#210](https://github.com/Late-bloomer420/miTch/pull/210))
- fix(wallet-pwa): move CSP frame-ancestors from meta tag to HTTP response headers ([#212](https://github.com/Late-bloomer420/miTch/pull/212))
- fix(verifier): enforce one-shot numeric-age presentation profile ([#208](https://github.com/Late-bloomer420/miTch/pull/208)) — evidence: [`ACTIVE_AGE_PROFILE_2026-10-25.md`](docs/qa/ACTIVE_AGE_PROFILE_2026-10-25.md)
- fix(ci): fail on critical audit findings and unverifiable reports ([#194](https://github.com/Late-bloomer420/miTch/pull/194)) — evidence: [`SECURITY_AUDIT_GATE_2026-10-24.md`](docs/qa/SECURITY_AUDIT_GATE_2026-10-24.md), [`SECURITY_AUDIT_GATE_2026-10-25.md`](docs/qa/SECURITY_AUDIT_GATE_2026-10-25.md)
- fix(deps): pin proxy-addr >=2.0.8 — clear the critical audit advisory (SEC-AUDIT-2) ([#206](https://github.com/Late-bloomer420/miTch/pull/206))
- ci: run required checks on merge_group events ([#209](https://github.com/Late-bloomer420/miTch/pull/209))
- style(wallet): calm trusted channel surface ([#129](https://github.com/Late-bloomer420/miTch/pull/129))
- fix(deps): raise postcss override floor to 8.5.25 ([#207](https://github.com/Late-bloomer420/miTch/pull/207))
- docs: harden G1 interview kit against accidental PII commits ([#202](https://github.com/Late-bloomer420/miTch/pull/202))
- docs: carry repository ecosystem map over from #141 ([#205](https://github.com/Late-bloomer420/miTch/pull/205))
- chore(phase0-security): remove commented-out erasure demo ([#204](https://github.com/Late-bloomer420/miTch/pull/204))
- fix(predicates): use crypto.randomUUID for decisionId ([#203](https://github.com/Late-bloomer420/miTch/pull/203))
- docs(poc-hardened): scope DPIA erasure and breach claims to what AskMI can prove ([#191](https://github.com/Late-bloomer420/miTch/pull/191))
- fix(security): port #141 code hardening — recovery fail-closed, verifier CORS/session isolation ([#195](https://github.com/Late-bloomer420/miTch/pull/195))
- feat(discrete-core): Vorlesung „Mengen & Abbildungen" als fail-closed Kernbibliothek ([#189](https://github.com/Late-bloomer420/miTch/pull/189)) — evidence: [`DISCRETE_CORE_REVIEW_2026-10-23.md`](docs/qa/DISCRETE_CORE_REVIEW_2026-10-23.md)
- docs: add AskMI G1 interview kit ([#201](https://github.com/Late-bloomer420/miTch/pull/201))
- feat(connect): ADOPT-1.2-code — first @askmi/connect implementation slice ([#193](https://github.com/Late-bloomer420/miTch/pull/193)) — evidence: [`CONNECT_LIFECYCLE_CORRECTION_2026-10-24.md`](docs/qa/CONNECT_LIFECYCLE_CORRECTION_2026-10-24.md)
- test(verifier-sdk): make ciphertext-tamper test deterministic ([#190](https://github.com/Late-bloomer420/miTch/pull/190))
- docs: preserve goals and scoped evidence; qualify demo assurances ([#174](https://github.com/Late-bloomer420/miTch/pull/174)) — evidence: [`PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md`](docs/qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md)
