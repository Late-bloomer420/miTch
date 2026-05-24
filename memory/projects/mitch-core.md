# Projekt: miTch Core

**Status:** Pilot-Ready (`pilot-ready-p0`)
**Repo:** https://github.com/Late-bloomer420/miTch.git
**Branch:** `master`
**Live Demo:** https://late-bloomer420.github.io/miTch/
**Stand:** 2026-05-25

---

## Was ist miTch?

Privacy-preserving proof mediation middleware — "The Forgetting Layer".

Kernprinzip: ZK-style Credential-Verifikation mit Crypto-Shredding. Das System beweist Attribute (z.B. Alter ≥ 18), ohne die Rohdaten weiterzugeben oder dauerhaft zu speichern. Fail-closed per Design.

Standards: GDPR Art. 25, eIDAS 2.0 / EUDI, OID4VP, OID4VCI, SD-JWT VC, ISO 18013-5 (mdoc).

---

## Aktueller Zustand

- **Tests:** 1618 individual tests, 43/43 turbo tasks ✅
- **Lint:** 0 errors, 0 warnings ✅
- **Audit:** 7 npm vulns (alle in devDependencies, upstream-Abhängig)
- **Demo:** Altersverifikation (18+) — `pnpm dev` → Verifier (3004) + Wallet (5173)

---

## Phasen-Überblick

| Phase | Status | Beschreibung |
|-------|--------|--------------|
| 0 — Foundation | ✅ DONE | DID, Revocation, Policy, Crypto-Primitiven |
| 1 — Unlinkability | ✅ DONE | Pairwise DIDs, Key Shredding, Data Flow Transparency |
| 2 — EUDI/eIDAS 2.0 | 🟡 PARTIAL | OID4VP/VCI/SIOPv2 done; mdoc done; Regulatory Compliance offen |
| 3 — Security Hardening | 🟡 PARTIAL | Salt Typhoon Patterns; STRIDE Threat Model braucht ext. Review |

---

## Monorepo Struktur

- `src/packages/` — 27 Package-Workspaces (aktueller Scan 2026-05-25)
- `src/apps/` — fachlich 3 Apps (wallet-pwa, issuer-mock, verifier-demo); workspace-technisch 5 App-bezogene Projekte durch verifier-demo root/backend/frontend
- Build: `pnpm turbo` (turbo.json mit `pipeline`, nicht `tasks`)

---

## Kritische Konventionen

- **Fail-closed:** Ambiguität → DENY
- **DecisionCapsule:** `verdict`, `decision_id`, `policy_hash` (NICHT `policy_manifest_id`)
- **Keine Breaking Changes** ohne explizite Freigabe
- **policy-engine/index.ts:** Viele Exports — Naming Conflicts prüfen

---

## Aktuelle Arbeit (Stand 2026-05-22)

- **U-20/U-21 (Active):** Identity Firewall — Implementation v1 complete. Abschlussreview durch Security/Reviewer ausstehend. Sprint-Doc: `docs/tasks/SPRINT_01_IDENTITY_FIREWALL.md`
- **Sprint 2 (Fertig):** Consent Manager Data Visualization — Implementation v5 complete (2026-05-21). ConsentModal + DataFlowPanel + ConsentReceipt als gemeinsame Schicht.

## Architecture Handoff (Stand 2026-05-25)

- Neuer Review-Standard: `docs/03-architecture/ARCHITECTURE_ANALYSIS_PROCESS_V2_2026-05-24.md`
- Coding-Agent-Übergabe: `docs/03-architecture/CODING_AGENT_HANDOFF_2026-05-25.md`
- Leitregel für Architekturprüfungen: `UNKNOWN => FAIL`
- Aktuelle P0-Findings: Dirty Tree als Risiko, ADR-/Decision-Drift, `policy_hash` Semantik widerspricht DecisionCapsule-Spec.
- Aktuelle P1-Findings: WalletService-Decomposition, ConsentReceipt-Kanonisierung, signierter ConsentReceipt-Export, echte Claim-Level Encryption, Pairwise DID Fail-Closed-Entscheidung.
- Wichtige Code-Hotspots: `policy-engine/src/engine.ts`, `shared-types/src/policy.ts`, `WalletService.ts`, `secure-storage/src/index.ts`, `consent-manager/receipt-store.ts`, `oid4vp/src/demo-flow.ts`.
- Vor Folgearbeiten zuerst `git status --short --branch` prüfen. Der Stand vor dem Handoff war `master...origin/master [ahead 2]` mit gemischten Code-/Doc-Änderungen.

## Offene P1-Prioritäten (nächste Schritte)

1. Abschlussreview U-20/U-21 (Identity Firewall) — Reviewer/Security gefragt
2. BBS+ / SD-JWT Ephemeral Keys (U-10/U-11) — Proof-Randomisierung
3. EU Regulatory Compliance (E-30–E-33) — CIR 2024/2977–2982
4. STRIDE Threat Model — externer Security Review (menschliche Vorbedingung für S-10)

---

## Referenzdokumente

- `STATE.md` — Operativer Health-Snapshot
- `docs/BACKLOG.md` — Autoritatives Task-Tracking
- `docs/SESSION_HISTORY.md` — Vollständiger Session-Verlauf
- `docs/DOCS_CANON.md` — Documentation Authority Map
- `docs/03-architecture/ARCHITECTURE_ANALYSIS_PROCESS_V2_2026-05-24.md` — Architekturprüfprozess v2
- `docs/03-architecture/CODING_AGENT_HANDOFF_2026-05-25.md` — Coding-Agent-Übergabe
- `docs/ops/EVIDENCE_PACK_P0.md` — P0 Evidence
- `docs/pilot/PILOT_DRY_RUN_01.md` — Pilot Dry Run
- `docs/pilot/FINDINGS_BACKLOG.md` — Pilot Findings
