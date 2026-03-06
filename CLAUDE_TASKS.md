# CLAUDE_TASKS.md — Session 6: E2E Demo + ESLint + BACKLOG Update

**Datum:** 2026-03-06
**Vorgabe:** Autonome Abarbeitung, keine Rückfragen. Bei Blocker → `BLOCKED.md` schreiben.
**Branch:** `master` (direkt committen)
**Commit-Stil:** `feat/test/fix/docs(package): Kurzbeschreibung`
**Tests:** `npx turbo run test` muss am Ende grün sein.
**Arbeitsverzeichnis:** `/mnt/d/Mensch/miTch`

---

## Aktueller Stand

- 38/38 turbo tasks, 734 Tests, 0 lint errors
- Phase 0 + Phase 1 (Unlinkability U-01–U-05) + Phase 3 (Security S-01–S-05) ✅
- OID4VP + OID4VCI Scaffolds + Tests existieren
- UX Polish (UX-01 bis UX-08) ✅
- ESLint Errors: 0, Warnings: ~260

---

## Block D — Demo E2E Flow 🔴

### D-01: E2E Integration Test — Full Verification Flow
**Paket:** `integration-tests` oder `poc-hardened`
**Was:**
- [ ] Test: Liquor Store Szenario End-to-End
  - Verifier Request erstellen → Policy Engine evaluiert → ALLOW → VP Token generiert → Pairwise DID verwendet → Key Shredding nach Delivery
- [ ] Test: Hospital Doctor Login (Multi-VC, PROMPT verdict)
  - Zwei Credential Types → Policy Engine → PROMPT → Consent simulieren → VP Token mit beiden VCs
- [ ] Test: EHDS Emergency Room (Biometric required)
  - PatientSummary Request → PROMPT+BIOMETRIC → WebAuthn Mock → Approve → VP Token
- [ ] Test: Pharmacy (ePrescription, time-limited)
  - Prescription Request → Policy Engine → Freshness Check → VP Token mit TTL

**Acceptance:** 4 E2E Szenarien als Tests, alle grün. Jedes Szenario testet den kompletten Flow von Request bis Response.

### D-02: Demo Script Documentation
**Datei:** `docs/DEMO_SCRIPT.md`
**Was:**
- [ ] Schritt-für-Schritt Anleitung für Live-Demo (Uni-Präsentation)
- [ ] Welche Szenarien in welcher Reihenfolge
- [ ] Was der Zuschauer sehen soll (Expected Output)
- [ ] Troubleshooting: "Was tun wenn X nicht funktioniert"
- [ ] Setup-Anweisungen: `pnpm install`, `pnpm dev`, Browser öffnen

**Acceptance:** Ein Nicht-Techniker kann der Anleitung folgen und die Demo vorführen.

---

## Block H — ESLint Warnings Cleanup 🟡

### H-01b: ESLint Warnings eliminieren
**Was:**
- [ ] `no-unused-vars`: Unbenutzte Variablen entfernen oder mit `_` prefixen
- [ ] `no-explicit-any`: Durch spezifische Types ersetzen wo möglich, `unknown` wo nötig
- [ ] Package für Package durchgehen (shared-types → shared-crypto → policy-engine → ... → wallet-pwa)
- [ ] KEINE funktionalen Änderungen — nur Type-Fixes und Dead Code Removal
- [ ] Nach jedem Package: `npx turbo run test` muss grün bleiben

**Acceptance:** `npx eslint src/` zeigt 0 warnings (oder < 10 unvermeidbare).

---

## Block B — BACKLOG.md aktualisieren 🟡

### B-01: BACKLOG.md auf aktuellen Stand bringen
**Was:**
- [ ] Alle erledigten Tasks als ✅ markieren:
  - U-01 bis U-05 ✅
  - E-01 (OID4VP) ✅
  - E-02 (OID4VCI) ✅
  - S-01 bis S-05 ✅
  - H-01 (ESLint Errors) ✅
  - G-01 bis G-03 (Wallet Tests) ✅
  - EHDS T-A1 bis T-D1 ✅
- [ ] H-01b Status updaten (Warnings)
- [ ] Neue Tasks aus Session 4+5 eintragen falls fehlend

### B-02: STATE.md finalisieren
- [ ] Aktuelle Test-Zahlen
- [ ] Alle abgeschlossenen Phasen dokumentieren
- [ ] "Recent changes" auf Session 6 updaten

---

## Block P — Präsentations-Vorbereitung 🟡

### P-01: Uni-Präsentation Outline
**Datei:** `docs/presentation/OUTLINE.md`
**Was:**
- [ ] Gliederung der Präsentation (ca. 20 Min):
  1. Problem: Warum brauchen wir Privacy by Design?
  2. Lösung: miTch — The Forgetting Layer
  3. Architektur: Policy Engine, Wallet, Unlinkability
  4. Live Demo: 4 Szenarien
  5. EHDS/eIDAS Compliance
  6. Ausblick: "Alle sind miTch"
- [ ] Talking Points pro Folie
- [ ] Technische Tiefe für Rückfragen vorbereiten

### P-02: Architecture Diagram (Mermaid)
**Datei:** `docs/presentation/ARCHITECTURE.md`
**Was:**
- [ ] Mermaid Diagramm: Wallet ↔ Policy Engine ↔ Verifier
- [ ] Datenfluss: Request → Evaluation → Consent → Proof → Shredding
- [ ] Unlinkability: Pairwise DID Generierung visualisieren
- [ ] EHDS: Break-Glass + Cross-Border Flow

---

## Reihenfolge

1. **Block D** (E2E Tests) — beweist dass alles zusammen funktioniert
2. **Block H** (ESLint Warnings) — Code-Qualität
3. **Block B** (BACKLOG + STATE) — Dokumentation aktuell halten
4. **Block P** (Präsentation) — Uni-Vorbereitung

## Regeln

- Nach jedem Block: `npx turbo run test` (MUSS grün sein)
- Commits nach jedem Task
- TypeScript strict, keine `any` (außer unvermeidlich)
- Existing Code NICHT unnötig refactoren
- STATE.md + BACKLOG.md am Ende updaten
- WSL Hinweis: `npm rebuild esbuild` falls esbuild Platform-Error kommt

---

*Erstellt von Claw 🦀 — 2026-03-06*
