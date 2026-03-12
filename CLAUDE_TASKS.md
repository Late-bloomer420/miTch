# CLAUDE_TASKS.md — Session 10: Security Hardening + E2E Completion

**Datum:** 2026-03-12
**Vorgabe:** Autonome Abarbeitung, keine Rückfragen. Bei Blocker → `BLOCKED.md` schreiben.
**Branch:** `master` (direkt committen + pushen nach jedem Block)
**Commit-Stil:** `feat/fix/test/docs(package): Kurzbeschreibung`
**Tests:** `npx turbo run test` muss nach jedem Block grün sein.
**Arbeitsverzeichnis:** `D:/Mensch/miTch`
**Referenz:** `SPRINT_PLAN.md` (Audit-Findings), `CLAUDE_TASKS.md` Session 9 (E2E Blocks W-03, W-04)

---

## ⚠️ Build Rules (ALWAYS follow these)

1. **tsconfig.build.json:** If you add test dependencies without type declarations (e.g. `fake-indexeddb`), ensure the package has a `tsconfig.build.json` that excludes `test/` from the build.
2. **CI must stay green:** After every push, all 4 GitHub Actions workflows must pass.
3. **Do NOT touch:** `standalone.html` (Antigravity owns UX), `.github/workflows/` (already fixed), `memory/` (Claw's workspace).
4. **Security fixes first:** Block A before Block B. Don't skip to E2E until security is closed.

---

## Kontext

Session 9 hat E2E Wiring begonnen — W-01 (Verifier Request Gen) und W-02 (Wallet Request Parsing) sind teilweise committed (`6cd7f3a`, `ecf94f3`). Aber der Security-Audit (`SPRINT_PLAN.md`) hat offene HOCH/MITTEL-Findings die vor dem Pilot gefixt werden müssen.

**Reihenfolge:** Security Fixes → E2E fertig verdrahten → Integration Tests

---

## Block A — Security Fixes (aus SPRINT_PLAN.md) 🔴

Alle Findings mit Status "Bestätigt" aus `SPRINT_PLAN.md` Block A. Lies den SPRINT_PLAN.md für Details.

### A-01: ReDoS in `matchesPattern` (F-02, HOCH)
**Datei:** `src/packages/policy-engine/src/engine.ts`
**Fix:** Regex-Sonderzeichen escapen vor Glob-Replace ODER Pattern-Matching ohne RegExp (split auf `*`, prefix/suffix check).
**Tests:** Unit-Tests mit evil Patterns: `(foo+)+`, `a{1,32000}b`, `did:mitch:(evil.com` — kein Hang, korrektes Matching.

### A-02: Echtes SHA-256 im DecisionCapsule (F-03, HOCH)
**Datei:** `src/packages/policy-engine/src/` (DecisionCapsule)
**Fix:** Fake-Hash durch echtes `crypto.subtle.digest('SHA-256', ...)` ersetzen. Async machen wo nötig.
**Tests:** Hash-Output prüfen (deterministisch für gleichen Input, 32 bytes hex).

### A-03: `getRawDocument()` Input Guard (F-08, NIEDRIG)
**Fix:** Null/undefined check + Typ-Validierung bevor auf Document zugegriffen wird.
**Tests:** Aufruf mit `null`, `undefined`, `{}`, ungültigem Typ.

### A-04: Algorithmus-Verfügbarkeits-Check (F-17, NIEDRIG)
**Fix:** Beim Start prüfen ob benötigte WebCrypto-Algorithmen verfügbar sind. Fail-fast mit klarer Fehlermeldung.
**Tests:** Mock `crypto.subtle` ohne ES256 → erwarte Error.

### A-05: Pairwise-DID HKDF Error-Handling (F-06, teilweise korrigiert)
**Fix:** try/catch um `importKey` + `deriveBits`. Klare Fehlermeldung bei Failure.
**Tests:** Invalider Key-Input → definierter Error (nicht uncaught).

### A-06: CSP-Headers für Wallet-PWA (F-13, MITTEL)
**Datei:** `src/apps/wallet-pwa/`
**Fix:** Meta-Tag `<meta http-equiv="Content-Security-Policy" content="...">` in index.html. Strict: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; img-src 'self' data:;`
**Tests:** Manuell (CSP ist HTML-Level). Optional: Check dass index.html den Meta-Tag enthält.

### A-07: Stale-Dateien aufräumen (F-11, NIEDRIG)
**Fix:** Finde und lösche tote Imports, unused exports, leere Dateien. `pnpm lint` muss danach clean sein.

**Commit nach Block A:** `fix(security): close audit findings F-02, F-03, F-06, F-08, F-11, F-13, F-17`
(Oder einzeln committen — Hauptsache nachvollziehbar.)

---

## Block B — E2E Completion (W-03 + W-04 aus Session 9) 🟡

W-01 und W-02 sind begonnen. Jetzt den Flow fertig verdrahten.

### B-01: Wallet Presentation Response (W-03)
**Paket:** `src/apps/wallet-pwa/` + `src/packages/shared-crypto/`
- [ ] SD-JWT VP Token generieren (nur selected disclosures)
- [ ] Key Binding JWT (nonce + aud vom Verifier)
- [ ] DPoP Proof für Response
- [ ] Response via `direct_post` an Verifier redirect_uri
- [ ] WebAuthn/Biometric gate vor Release (bestehenden Auth-Flow nutzen)

### B-02: Verifier Response Validation (W-04)
**Paket:** `src/apps/verifier-demo/`
- [ ] VP Token empfangen + parsen
- [ ] SD-JWT Issuer Signatur verifizieren
- [ ] Key Binding JWT validieren (nonce, aud, iat freshness)
- [ ] DPoP Proof validieren
- [ ] Disclosed Claims extrahieren + anzeigen
- [ ] Ergebnis-UI: Was der Verifier sieht vs. was hidden bleibt

### B-03: Crypto-Shredding nach Verification
- [ ] Ephemeral Session Keys nach erfolgreicher Verification löschen
- [ ] Audit-Log Entry (was wurde geteilt, wann, mit wem — ohne PII)

**Commit:** `feat(e2e): complete OID4VP presentation + verification flow`

---

## Block C — Integration Tests 🟢

Erst wenn Block A + B grün sind.

### C-01: E2E Happy Path Test
**Datei:** `src/apps/verifier-demo/test/e2e.test.ts` (neu)
- [ ] Vollständiger Flow: Issue Credential → Verifier Request → Wallet Consent (auto-allow) → VP Token → Verifier Validates → Success
- [ ] Programmatisch, kein Browser nötig (HTTP-Calls zwischen Apps)

### C-02: E2E Deny Path Test
- [ ] Verifier requestet verbotene Claims → Policy Engine DENY → kein VP Token
- [ ] Verifier mit ungültigem Client Attestation → Wallet rejects

### C-03: E2E Selective Disclosure Test
- [ ] Verifier requestet 3 Claims, Wallet disclosed nur 2 → Verifier sieht nur 2
- [ ] Key Binding JWT nur für disclosed Claims

**Commit:** `test(e2e): integration tests for OID4VP happy/deny/selective paths`

---

## Abschluss-Checkliste

- [ ] `npx turbo run test` — alle grün
- [ ] `pnpm lint` — 0 errors
- [ ] Alle Änderungen committed + gepusht
- [ ] Kein `BLOCKED.md` übrig (oder begründet)
- [ ] CI Actions: alle 4 Workflows grün
