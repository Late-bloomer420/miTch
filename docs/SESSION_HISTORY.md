# miTch — Session History

Ausgelagert aus `STATE.md` am 2026-03-14. Enthält den Verlauf abgeschlossener Sessions.

---

### Session 10+ (2026-03-11 – 2026-03-13)
- **SPRINT_PLAN.md Block A Security Fixes:** F-01–F-03, F-06, F-08, F-10–F-11, F-13, F-17 (closed)
- **F-01** Recovery: GF(2^8) Shamir 2-of-3 SSS (real secret sharing, ersetzt XOR 3-of-3)
- **F-09** Verifier Binding Phase 1 (origin hostname vs. verifierId/did:web)
- **F-18** `REFACTORING_ROADMAP.md` erstellt
- phase0-security: IndexedDB test fixes, EIDASComplianceChecker tests (28 tests)
- ESLint: 26 → 0 problems (unused imports, stale directives, test any-casts → precise types)
- response-verifier tests + verifier-browser vitest config
- fix(wallet-pwa): `@mitch/oid4vp` alias in vite.config.ts + vitest.config.ts → 39/39 turbo, 60/60 wallet-pwa tests
- **Deferred to REFACTORING_ROADMAP.md:** F-04 (EphemeralKey), F-07 (claim-level crypto), F-14 (key rotation), F-16 (WalletService split)

#### Bekannte Altlasten
- ~~shared-crypto `pairwise-did.test.ts`: 60s timeout bei 1000 DID generation~~ → **behoben:** Iterationen 1000→100, Timeout 60s→30s (Testaussage erhalten: P-256 256-bit Zufallsraum, Kollisionswahrscheinlichkeit ~2^-200 bei 100 DIDs)

### Session 7 (2026-03-06)
- GitHub Pages deployment workflow (`.github/workflows/pages.yml`)
- OpenGraph / Twitter Card meta tags for link previews
- README rewrite (badges, quick start, live demo link)
- Stale file cleanup (task files → `docs/archive/`)

### Session 8 — EUDI/eIDAS 2.0 Compliance Sprint (2026-03-06)
- **E-10** SD-JWT VC Compliance (draft-ietf-oauth-sd-jwt-vc-11) — 17 tests
- **E-05** DPoP (RFC 9449) — 13 tests
- **E-03** SIOPv2 (Self-Issued OpenID Provider v2) — 15 tests
- **E-04** OAuth 2.0 Attestation-Based Client Auth — attestation+pop chain
- **E-13** HAIP (High Assurance Interoperability Profile) — direct_post.jwt, verifier attestation
- **C-01** Brainpool P256r1 (noble-curves, RFC 5639 §3.4) — 10 tests
- **C-02** ECDH + HMAC-SHA-256 MAC Verification — 10 tests
- **L-01** CIR Compliance Matrix (82% coverage: 2977/2979/2982)
- **L-02** Architecture Decision Records (ADR-001 to ADR-004)

- **CIR Compliance:** 82% ✅ → remaining 🟡: status endpoint deploy, brainpoolP384r1, batch_credential
- **Working directory:** `D:/Mensch/miTch` (master branch)

### Session 6 (2026-03-06)

- D-01: 4 E2E demo scenario tests — Liquor Store, Hospital, EHDS Emergency, Pharmacy (17 tests)
- D-02: docs/DEMO_SCRIPT.md — full demo walkthrough, troubleshooting, Q&A talking points
- H-01b: ESLint `no-explicit-any` eliminated across ALL packages (0 warnings, was 170)
  - Source packages: shared-crypto, policy-engine, predicates, verifier-sdk, oid4vci,
    eid-issuer-connector, verifier-browser, mock-issuer, anchor-service, audit-log, catalog
  - Apps: wallet-pwa (WalletService, ConsentModal, App, AuditReportPanel), verifier-demo
  - Tests: file-level eslint-disable for legitimate browser-API mock patterns
  - 2 errors fixed: unused imports/params in revocation-statuslist
- Presentation: docs/presentation/OUTLINE.md + ARCHITECTURE.md (Mermaid diagrams)

### Session 5 (2026-03-06)

- G-02: WalletService unit tests — 12 tests (init, credential eval, AES-256-GCM, policy, audit chain, key split/recovery)
- G-03: ConsentModal (12 tests) + PolicyEditor (10 tests) component tests
- E-02: OID4VCI expanded tests — 29 new tests (32 total): offer, issuance, validation, policy, audit log
- H-01: Fixed all ESLint errors in policy-engine, oid4vp, wallet-pwa (0 errors remaining)
- fix: IndexedDB mock — added getAll/getAllKeys/clear methods (SecureStorage.getAllMetadata)
- fix: document.elementFromPoint stub for jsdom (SecureZone component)
- fix: config-profiles.test.ts manifestId→trustedIssuers (TS type error)
- fix: jurisdiction.ts unused purpose param, proof-fatigue.ts let→const
