# CLAUDE_TASKS.md — Session 4: Unlinkability + OID4VP + Tests

**Datum:** 2026-03-06
**Vorgabe:** Autonome Abarbeitung, keine Rückfragen. Bei Blocker → `BLOCKED.md` schreiben.
**Branch:** `master` (direkt committen, kein PR)
**Commit-Stil:** `feat/test/fix/docs(package): Kurzbeschreibung`
**Tests:** Jeder Task muss Tests haben. `npx turbo run test` muss am Ende grün sein.

---

## Block U — Unlinkability Phase 1 vervollständigen (Spec 111) 🔴

U-05 (Policy Engine Integration) ist bereits ✅. U-01 bis U-04 fehlen.

### U-01: Pairwise DID Generation härten + Tests
**Paket:** `shared-crypto`
**Datei:** `src/pairwise-did.ts` (existiert bereits!)
**Was fehlt:**
- [ ] Verifiziere dass `generatePairwiseDID()` korrekt HKDF-SHA256 mit verifierOrigin + sessionNonce ableitet
- [ ] Sicherstellen: gleicher Verifier + unterschiedlicher sessionNonce → unterschiedliche DIDs
- [ ] Sicherstellen: unterschiedliche Verifier → unterschiedliche DIDs
- [ ] Unit Tests: mindestens 10 Tests (Uniqueness, Determinismus-Check, Edge Cases: leerer nonce, langer origin)
- [ ] Property Test: 100 generierte DIDs → keine Kollision

**Acceptance:** `pairwise-did.test.ts` existiert und alle Tests grün.

### U-02: did:peer Resolution in DID Resolver
**Paket:** `shared-crypto`
**Datei:** `src/did.ts`
**Was:**
- [ ] `did:peer:0z...` Method in `resolveDID()` / `resolveVerificationKey()` unterstützen
- [ ] did:peer method 0: Public Key ist inline im DID encoded (Multicodec + Base58)
- [ ] Kein Netzwerk-Lookup nötig — Key direkt aus dem DID extrahieren
- [ ] Cache-Bypass für did:peer (ephemeral, cachen macht keinen Sinn)
- [ ] Tests: did:peer auflösen → korrekter Public Key, unbekanntes Format → Fehler

**Acceptance:** `resolveDID('did:peer:0z...')` gibt korrektes DID Document + Key zurück. Tests grün.

### U-03: Cross-Verifier Unlinkability Tests
**Paket:** `shared-crypto` oder `poc-hardened`
**Datei:** Neue Testdatei `unlinkability.test.ts`
**Was:**
- [ ] Test: 2 verschiedene Verifier → DIDs sind unterschiedlich (kein Overlap)
- [ ] Test: Gleicher Verifier, 2 Sessions → DIDs sind unterschiedlich
- [ ] Test: Generierte DIDs enthalten KEINE Information über den Master Key
- [ ] Test: Statistische Verteilung — 1000 DIDs, keine Clusterung
- [ ] Test: Timing-Gleichheit — Generierung darf nicht von Input-Länge abhängen (± 10%)

**Acceptance:** Eigene Testsuite mit ≥ 8 Tests, alle grün.

### U-04: Key Shredding nach Interaktion
**Paket:** `shared-crypto`
**Datei:** `src/pairwise-did.ts` + `src/ephemeral-key.ts`
**Was:**
- [ ] `PairwiseDIDResult.destroy()` muss ALLE Keys shredden (signing + encryption)
- [ ] Nach `destroy()`: `sign()` wirft Error
- [ ] Nach `destroy()`: `signingKey.getKey()` wirft Error
- [ ] Nach `destroy()`: `encryptionKey.getKey()` wirft Error
- [ ] Test: Double-destroy ist safe (kein Crash)
- [ ] Test: Key-Memory ist tatsächlich mit Nullen überschrieben (Buffer-Check)

**Acceptance:** Lifecycle-Tests (create → use → destroy → verify destroyed). Alle grün.

---

## Block E — OID4VP Integration 🔴

### E-01a: OID4VP Presentation Request Parser
**Paket:** `oid4vp`
**Dateien:** `src/presentation-request.ts`, `src/types.ts` (Scaffolds existieren!)
**Was:**
- [ ] `parsePresentationRequest(url: string)` — URI parsen (request_uri oder inline)
- [ ] Presentation Definition validieren (input_descriptors, constraints)
- [ ] `client_id` + `redirect_uri` + `nonce` extrahieren
- [ ] response_mode: `direct_post` und `direct_post.jwt` unterstützen
- [ ] Fehler bei ungültigen/fehlenden Pflichtfeldern
- [ ] Tests: gültige Requests, fehlende Felder, ungültige URIs

**Acceptance:** Parser + ≥ 8 Tests grün.

### E-01b: OID4VP VP Token Builder
**Paket:** `oid4vp`
**Dateien:** `src/vp-token.ts`, `src/response-builder.ts`
**Was:**
- [ ] `buildVPToken(credential, presentationDef, pairwiseDID)` — VP Token erstellen
- [ ] SD-JWT Disclosure Mapping: nur angeforderte Claims includen
- [ ] Pairwise DID als `holder` im VP Token einbinden (U-05 Integration!)
- [ ] `buildAuthorizationResponse(vpToken, state, redirectUri)` — direct_post Payload
- [ ] Tests: Token-Struktur, Disclosure-Filtering, Pairwise-DID im Token

**Acceptance:** Builder + ≥ 10 Tests grün.

### E-01c: OID4VP Verifier — Response Verification
**Paket:** `oid4vp-verifier`
**Dateien:** `src/response-verifier.ts`, `src/request-builder.ts`
**Was:**
- [ ] `verifyVPToken(vpToken, expectedNonce, presentationDef)` — Signatur + Nonce + Disclosure prüfen
- [ ] `buildAuthorizationRequest(presentationDef, redirectUri)` — Request URL generieren
- [ ] Nonce-Replay Schutz (NonceStore aus shared-crypto nutzen)
- [ ] Tests: gültige Tokens, abgelaufene Nonce, falsche Signatur, fehlende Disclosures

**Acceptance:** Verifier + ≥ 8 Tests grün.

### E-01d: OID4VP ↔ Policy Engine Consent Flow
**Paket:** Integration (wo am sinnvollsten — evtl. `poc-hardened` oder neues `integration-tests`)
**Was:**
- [ ] OID4VP Request kommt rein → Policy Engine evaluiert → ALLOW/DENY/PROMPT
- [ ] Bei ALLOW: VP Token automatisch mit Pairwise DID bauen + senden
- [ ] Bei PROMPT: Consent UI Signal (Event/Callback)
- [ ] Bei DENY: Reason Code in Authorization Error Response
- [ ] Integration Test: Full Flow (Request → Policy → Response)

**Acceptance:** E2E Integration Test grün.

---

## Block G — Wallet-PWA Tests 🟡

### G-01: Testing Setup
**Was:**
- [ ] `@testing-library/react` + `jsdom` als devDeps installieren
- [ ] Vitest config für React/JSX in wallet-pwa anpassen
- [ ] Smoke Test: leerer React-Render funktioniert

### G-02: WalletService Unit Tests
- [ ] Credential Store/Retrieve/Delete
- [ ] Verschlüsselung (AES-256-GCM) roundtrip
- [ ] Fehler bei korruptem Storage

### G-03: ConsentModal + PolicyEditor Component Tests
- [ ] ConsentModal rendert Claims korrekt
- [ ] Approve/Deny Callbacks funktionieren
- [ ] PolicyEditor zeigt Rules an

---

## Reihenfolge

1. **Block U** zuerst (U-01 → U-02 → U-03 → U-04) — das ist die Grundlage
2. **Block E** (E-01a → E-01b → E-01c → E-01d) — baut auf Pairwise DIDs auf
3. **Block G** wenn Zeit bleibt

## Regeln

- Nach jedem Block: `npx turbo run test` (MUSS grün sein)
- Commits nach jedem Task (nicht alles am Ende)
- TypeScript strict, keine `any` (außer unvermeidlich)
- Imports aus Monorepo: `@mitch/shared-crypto`, `@mitch/shared-types` etc.
- Existing Code NICHT unnötig refactoren — additiv arbeiten
- STATE.md + BACKLOG.md am Ende updaten

---

*Erstellt von Claw 🦀 — 2026-03-06*
