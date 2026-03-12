# CLAUDE_TASKS.md — Session 9: Demo Wiring Sprint (E2E Live Flow)

**Datum:** 2026-03-06
**Vorgabe:** Autonome Abarbeitung, keine Rückfragen. Bei Blocker → `BLOCKED.md` schreiben.
**Branch:** `master` (direkt committen)
**Commit-Stil:** `feat/test/fix/docs(package): Kurzbeschreibung`
**Tests:** `npx turbo run test` muss am Ende grün sein.
**Arbeitsverzeichnis:** `/mnt/d/Mensch/miTch`

---

## ⚠️ Build Rules (ALWAYS follow these)

1. **tsconfig.build.json:** If you add test dependencies without type declarations (e.g. `fake-indexeddb`), ensure the package has a `tsconfig.build.json` that excludes `test/` from the build. The build command in `package.json` must be `tsc -p tsconfig.build.json`, not plain `tsc`.
2. **CI must stay green:** After every push, all 4 GitHub Actions workflows must pass (ci.yml, ci-security.yml, pages.yml, push).
3. **Do NOT touch:** `standalone.html` (Antigravity owns UX), `.github/workflows/` (already fixed), `memory/` (Claw's workspace).

---

## Ziel

Die Protokolle (SIOPv2, OID4VP, DPoP, SD-JWT VC, HAIP) sind implementiert und unit-getestet.
Jetzt müssen sie **end-to-end verdrahtet** werden, damit ein echter Demo-Flow läuft:

> Verifier → SIOPv2/OID4VP Request → Policy Engine → Wallet Consent → Key Binding JWT → VP Token → Verifier validates → Crypto-Shred

Das ist was für Pitch/Pilot zählt — nicht mehr isolierte Unit-Tests, sondern ein lauffähiges System.

---

## Block W — Wire E2E Protocol Flow 🔴

### W-01: Verifier Backend — Request Generation
**Paket:** `src/apps/verifier-demo/` (erweitern) oder `src/packages/oid4vp/`
**Was:**
- [ ] Verifier generiert echten SIOPv2 + OID4VP Authorization Request
- [ ] Presentation Definition eingebettet (requested claims konfigurierbar)
- [ ] DPoP-bound Request Token
- [ ] Client Attestation JWT mitliefern (E-04)
- [ ] Request als URL oder QR-encodiert (für Wallet Scan)
- [ ] Endpoint: `GET /authorize` → returns request_uri oder direct request

**Acceptance:** Verifier erzeugt spec-konformen OID4VP Request den das Wallet parsen kann.

### W-02: Wallet — Request Parsing + Consent Flow
**Paket:** `src/apps/wallet-pwa/`
**Was:**
- [ ] OID4VP Authorization Request empfangen (URL param oder QR scan)
- [ ] Presentation Definition parsen → benötigte Claims extrahieren
- [ ] Client Attestation des Verifiers validieren
- [ ] Policy Engine aufrufen → ALLOW/PROMPT/DENY
- [ ] Bei PROMPT: Consent UI zeigen (welche Claims werden released)
- [ ] Bei ALLOW: Auto-proceed mit Notification
- [ ] Claims-Selection UI: User kann einzelne Disclosures togglen

**Acceptance:** Wallet zeigt Consent-Modal mit korrekten Claims aus dem Verifier-Request.

### W-03: Wallet — Presentation Response
**Paket:** `src/apps/wallet-pwa/` + `src/packages/shared-crypto/`
**Was:**
- [ ] SD-JWT VP Token generieren (nur selected disclosures)
- [ ] Key Binding JWT erstellen (nonce + aud vom Verifier)
- [ ] Pairwise DID als Subject (U-01 Integration)
- [ ] DPoP Proof für Response
- [ ] Response via `direct_post` an Verifier redirect_uri
- [ ] WebAuthn/Biometric gate vor Release (bestehender Auth-Flow nutzen)

**Acceptance:** Wallet sendet spec-konformen VP Token mit Key Binding an Verifier.

### W-04: Verifier — Response Validation
**Paket:** `src/apps/verifier-demo/`
**Was:**
- [ ] VP Token empfangen + parsen
- [ ] SD-JWT Issuer Signatur verifizieren
- [ ] Key Binding JWT validieren (nonce, aud, iat freshness)
- [ ] DPoP Proof validieren
- [ ] StatusList2021 Revocation Check
- [ ] Disclosed Claims extrahieren + anzeigen
- [ ] Ergebnis-UI: Was der Verifier sieht vs. was hidden bleibt

**Acceptance:** Verifier validiert den kompletten VP Token und zeigt nur disclosed Claims.

### W-05: Post-Presentation Cleanup
**Was:**
- [ ] Session Key Shredding nach erfolgreicher Presentation
- [ ] Audit Chain Entry mit Presentation Hash
- [ ] Consent Receipt generieren + in Wallet speichern
- [ ] Ephemeral DID Material löschen

**Acceptance:** Nach Presentation ist kein Session-Material mehr vorhanden.

---

## Block D — Dev Server Integration 🔴

### D-01: Unified Dev Server
**Was:**
- [ ] `pnpm dev` startet Wallet (5173) + Verifier (3004) parallel
- [ ] Verifier hat "Start Verification" Button → generiert QR/Link
- [ ] Wallet öffnet Link → Flow startet automatisch
- [ ] Turborepo `dev` Task konfigurieren falls noch nicht vorhanden
- [ ] `.env.example` mit Default-Ports und Config

**Acceptance:** `pnpm dev` → Browser öffnen → ein Klick startet den ganzen Flow.

### D-02: Demo Scenarios (Live)
**Was:**
- [ ] Scenario 1: Age Verification (single predicate, auto-approve)
- [ ] Scenario 2: Full ID Check (multi-claim, consent required)
- [ ] Scenario 3: EHDS Patient Summary (biometric + emergency)
- [ ] Scenario 4: Revoked Credential (deny flow)
- [ ] Verifier UI: Dropdown zur Scenario-Auswahl
- [ ] Jedes Scenario hat vorkonfigurierte Presentation Definition

**Acceptance:** 4 Szenarien durchklickbar, jeweils unterschiedlicher Flow.

---

## Block T — E2E Integration Tests 🟡

### T-01: Protocol E2E Tests
**Was:**
- [ ] Test: Verifier Request → Wallet Parse → Consent → VP Token → Verifier Validate
- [ ] Test: Revoked Credential → Verifier rejects
- [ ] Test: Expired Request (nonce too old) → Wallet rejects
- [ ] Test: Tampered VP Token → Verifier rejects
- [ ] Test: Wrong Audience → Key Binding validation fails
- [ ] Alles mit echten Crypto Operations (kein Mock)

**Acceptance:** 6+ E2E Tests die den kompletten Protocol Stack testen.

---

## Reihenfolge
1. W-01 (Verifier Request) — Fundament
2. W-02 (Wallet Parsing + Consent) — User-facing
3. W-03 (Wallet Response) — Crypto
4. W-04 (Verifier Validation) — Schließt den Loop
5. W-05 (Cleanup) — Security
6. D-01 (Dev Server) — Alles zusammen
7. D-02 (Demo Scenarios) — Polish
8. T-01 (E2E Tests) — Absicherung

**Erwartung:** ~30-50 neue Tests, 8-10 Commits, lauffähiger E2E Demo Flow.
