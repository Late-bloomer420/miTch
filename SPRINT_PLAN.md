# Sprint Plan — Audit-Response März 2026

**Grundlage:** `docs/AUDIT_2026_03.md` (17 Findings, F-01–F-17)
**Erstellt:** 2026-03-11
**Methode:** Jedes Finding gegen aktuellen Code (master, Post-Session-6) validiert.
**Kontext:** Ziel ist ein realer Pilot-Flow. Alles was den Flow blockiert oder unglaubwürdig macht, hat Vorrang.

---

## Validierungs-Überblick

| ID | Kategorie | Schwere | Status nach Validierung |
|----|-----------|---------|------------------------|
| F-01 | Kryptographie | HOCH | Bestätigt |
| F-02 | Sicherheit | HOCH | Bestätigt |
| F-03 | Sicherheit | MITTEL | Bestätigt |
| F-04 | Architektur | MITTEL | Bestätigt |
| F-05 | Sicherheit | MITTEL | Bestätigt |
| F-06 | Korrektheit | NIEDRIG | Korrigiert (teilweise) |
| F-07 | Architektur | MITTEL | Bestätigt (Kommentar ehrlich) |
| F-08 | Sicherheit | NIEDRIG | Bestätigt |
| F-09 | Architektur | MITTEL | Bestätigt |
| F-10 | Infrastruktur | HOCH | Bestätigt, schlimmer als beschrieben |
| F-11 | Hygiene | NIEDRIG | Bestätigt |
| F-12 | Infrastruktur | MITTEL | Korrigiert (Merkle-Tree, Env-Vars in Session 6 erledigt; Stub-Doku fehlt noch) |
| F-13 | Sicherheit | MITTEL | Bestätigt |
| F-14 | Architektur | NIEDRIG | Bestätigt |
| F-15 | Qualität | MITTEL | Bestätigt (phase0-security, layer-resolver weiter 0 Tests) |
| F-16 | Architektur | BEKANNT | Korrigiert: REFACTORING_ROADMAP.md existiert nicht |
| F-17 | Kryptographie | NIEDRIG | Bestätigt |
| F-18 | Infrastruktur | MITTEL | **Neu** — REFACTORING_ROADMAP.md fehlt |

---

## Block A — Sofort (Sicherheit & Korrektheit)

Alle innerhalb 1–2 Tagen behebbar. Reihenfolge: Abhängigkeiten zuerst, dann S vor M.

---

#### F-02: ReDoS in `matchesPattern`

- **Status:** Bestätigt
- **Dateien:** `src/packages/policy-engine/src/engine.ts:489–494`, `:185`
- **Validierung:** `new RegExp('^' + pattern.replace(/\*/g, '.*') + '$')` ohne Escaping der übrigen Regex-Sonderzeichen bestätigt. Zeile 185: `verifierPattern: request.verifierId` — Verifier-kontrollierter Input landet direkt als Pattern-String in `matchesPattern()`. ReDoS-Vektor ist real.
- **Konkreter Fix:** Sonderzeichen vor dem Glob-Replace escapen:
  ```typescript
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp('^' + escaped.replace(/\*/g, '.*') + '$');
  ```
  Alternativ: Pattern-Matching ohne RegExp implementieren (split auf `*`, prefix/suffix/infix-Check).
- **Aufwand:** S
- **Abhängigkeiten:** keine
- **Test-Strategie:** Unit-Test mit Patterns `(foo+)+`, `a{1,32000}b`, `did:mitch:(evil.com` — prüfen dass kein hängenbleiben und korrekte Matching-Ergebnisse.

---

#### F-03: Fake SHA-256 im DecisionCapsule

- **Status:** Bestätigt
- **Dateien:** `src/packages/policy-engine/src/engine.ts:606–607`
- **Validierung:** `const requestHash = \`sha256(req:${request.verifierId})\`` — Literal-String, kein tatsächlicher Hash. Ebenso `policyHash`. Bestätigt.
- **Konkreter Fix:** Beide durch echte SHA-256-Aufrufe ersetzen:
  ```typescript
  const requestHash = await sha256Hash(JSON.stringify({
      verifierId: request.verifierId,
      nonce: request.nonce,
      requirements: request.requirements,
  }));
  const policyHash = await sha256Hash(JSON.stringify({
      version: policy.version,
      rules: policy.rules.map(r => r.id),
  }));
  ```
  `sha256Hash` aus `@mitch/shared-crypto/hashing` importieren (dort bereits vorhanden).
  `createDecisionCapsule()` muss dafür `async` werden, sofern noch nicht.
- **Aufwand:** S
- **Abhängigkeiten:** keine
- **Test-Strategie:** Vorhandene DecisionCapsule-Tests um Assertions erweitern: `request_hash` muss `/^[0-9a-f]{64}$/` matchen, muss sich bei verschiedenen `verifierId`-Inputs unterscheiden.

---

#### F-10: CI-Pipeline reparieren

- **Status:** Bestätigt, schlimmer als im Audit beschrieben
- **Dateien:** `.github/workflows/ci.yml`, `.github/workflows/ci-security.yml`
- **Validierung:**
  - `ci.yml:40`: `echo "Tests skipped for now"` — bestätigt
  - `ci.yml:55`: Security-KPI-Check mit `continue-on-error: true` — bestätigt
  - `ci-security.yml:5`: Trigger auf `branches: ["main"]` — der Default-Branch heißt `master`; `ci-security.yml` läuft damit nie auf regulären Pushes
  - `ci-security.yml:24`: `npm ci` und `npm test` — kein `pnpm`. Die Scripts `swarm:test`, `evidence`, `kpi:check`, `security:deps` existieren in `package.json` wahrscheinlich nicht → Pipeline würde bei erstem Run sofort fehlschlagen
- **Konkreter Fix:**
  1. `ci.yml:40`: `echo "Tests skipped"` ersetzen durch `pnpm turbo test`
  2. `ci.yml:55`: `continue-on-error: true` entfernen (oder Security-KPI-Report erst generieren)
  3. `ci-security.yml`: Branch von `"main"` auf `master` korrigieren; `npm` durchgehend durch `pnpm` ersetzen; fehlende Scripts entweder anlegen oder Steps entfernen
  4. `layer-validation`-Job: `pnpm test -- --run e2e-liquor-store.test.ts` nur wenn Datei existiert (prüfen)
- **Aufwand:** S
- **Abhängigkeiten:** keine; sollte als erstes erledigt werden damit Folge-Fixes automatisch validiert werden
- **Test-Strategie:** Push auf master → GitHub Actions muss grün durchlaufen (alle Jobs).

---

#### F-11: Stale-Dateien entfernen

- **Status:** Bestätigt
- **Dateien:** `pnpm-lock.yaml.1184410667`, `mitch_context_pack_updated.zip`
- **Validierung:** Beide Dateien existieren im Repo-Root bestätigt (`ls`-Ausgabe). `phase0-security/` hat `ADVANCED_SECURITY_HARDENING.ts` sowohl im Root als auch in `src/` — Inhalte nicht identisch (Root enthält `MemoryHardeningProtection`, `src/` nicht), aber beide exportieren `SplitKeyProtection`. Doppelung ist real.
- **Konkreter Fix:**
  1. `pnpm-lock.yaml.1184410667` löschen, `.gitignore` um `pnpm-lock.yaml.*` ergänzen
  2. `mitch_context_pack_updated.zip` löschen, `.gitignore` um `*.zip` ergänzen
  3. `phase0-security/`-Struktur: entscheiden welche Datei kanonisch ist (`src/` oder Root), andere löschen oder als explizites Re-Export belassen — nicht beides ohne Kommentar
- **Aufwand:** S
- **Abhängigkeiten:** keine
- **Test-Strategie:** `git ls-files | grep -E '\.(zip|yaml\.[0-9]+)$'` muss leer sein. `pnpm turbo test` nach Löschen grün.

---

#### F-08: `getRawDocument()` ohne Guard

- **Status:** Bestätigt
- **Dateien:** `src/packages/secure-storage/src/index.ts:262–276`
- **Validierung:** Methode ist `public`, kein `@internal`, kein Build-Flag. Kommentar im Code ("NOT for production use") ist vorhanden aber nicht durchgesetzt.
- **Konkreter Fix:** `@internal` JSDoc-Tag hinzufügen + Guard:
  ```typescript
  /** @internal — nur für Tests. In Production wirft diese Methode. */
  async getRawDocument(id: string): Promise<EncryptedDocument | null> {
      if (typeof process !== 'undefined' && process.env?.['NODE_ENV'] === 'production') {
          throw new Error('getRawDocument() ist in Production nicht verfügbar');
      }
      // ... rest unchanged
  }
  ```
  Langfristig: `package.json` `exports`-Map mit separatem `/test`-Entry.
- **Aufwand:** S
- **Abhängigkeiten:** keine
- **Test-Strategie:** Bestehende Tests die `getRawDocument()` nutzen müssen weiter grün sein. Neuer Test: In einem Mock-Production-Env (`NODE_ENV=production`) wirft die Methode.

---

#### F-17: Kein Algorithmus-Verfügbarkeits-Check

- **Status:** Bestätigt
- **Dateien:** `src/packages/shared-crypto/src/platform.ts`
- **Validierung:** Datei prüft nur `globalThis.crypto !== 'undefined'` (Zeile 9). Keine Prüfung ob AES-GCM, ECDSA P-256, HKDF verfügbar. Bestätigt.
- **Konkreter Fix:** Probe-Funktion ergänzen, aufgerufen einmalig beim Import:
  ```typescript
  export async function assertCryptoCapabilities(): Promise<void> {
      await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
      await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'HKDF' }, false, ['deriveBits']);
  }
  ```
  Aufruf in `WalletService.initialize()` vor dem ersten kryptographischen Vorgang.
- **Aufwand:** S
- **Abhängigkeiten:** keine
- **Test-Strategie:** Unit-Test der Funktion im Browser-Environment (vitest jsdom). Negativtest: `crypto.subtle` durch Mock ersetzen der AES-GCM-Keygen ablehnt — `assertCryptoCapabilities()` muss werfen.

---

#### F-13: Keine CSP-Header für Wallet-PWA

- **Status:** Bestätigt
- **Dateien:** `src/apps/wallet-pwa/vite.config.ts`, `src/apps/wallet-pwa/index.html`
- **Validierung:** `index.html` hat kein `<meta http-equiv="Content-Security-Policy">`. `vite.config.ts` konfiguriert keine `headers`. Bestätigt.
- **Konkreter Fix:** Meta-Tag in `index.html`:
  ```html
  <meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self';
    style-src 'self' 'unsafe-inline';
    connect-src 'self' http://localhost:3005 http://localhost:3004;
    img-src 'self' data:;
    worker-src 'self' blob:;
    frame-ancestors 'none';
  ">
  ```
  Anmerkung: `'unsafe-inline'` für styles ist ein Kompromiss mit Vite/React; Scripts müssen `'self'`-only bleiben. `connect-src` für lokale Issuer/Verifier-Ports anpassen wenn Deployment-URLs bekannt.
- **Aufwand:** S
- **Abhängigkeiten:** keine; nach Deployment-URL-Entscheidung ggf. anpassen
- **Test-Strategie:** Browser-DevTools: Keine CSP-Violations bei normalem App-Betrieb. Manuell: `eval()` im Konsole → muss von CSP blockiert werden.

---

#### F-06: Pairwise-DID HKDF — kein Error-Handling um `importKey`

- **Status:** Korrigiert (teilweise)
- **Dateien:** `src/packages/shared-crypto/src/pairwise-did.ts:363–368`
- **Validierung:** Der Audit schreibt "32 HKDF-Bytes werden direkt als P-256 Private Key verwendet". Das ist nicht ganz korrekt: es wird `buildP256PKCS8(derivedSigningBits)` aufgerufen, das die PKCS8-Struktur aufbaut. Dann folgt `importKey('pkcs8', ...)` ohne Try/Catch. Die Kernaussage — kein Error-Handling — ist korrekt. Die Wahrscheinlichkeit des Fehlers ist extrem gering (HKDF-Output ist uniform random, für P-256 gilt n ≈ 2^256 − 4.3×10^38 ≈ 2^256 − 2^128, also ca. 1 in 2^128 Chance eines ungültigen Skalars). Für einen Pilot akzeptabel, aber das Fehlen des Try/Catch ist trotzdem eine Lücke.
- **Konkreter Fix:**
  ```typescript
  let signingCryptoKey: CryptoKey;
  try {
      signingCryptoKey = await crypto.subtle.importKey(
          'pkcs8', signingPKCS8.slice(0) as unknown as Uint8Array<ArrayBuffer>,
          { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
      );
  } catch (e) {
      throw new Error(`PAIRWISE_DID_KEYGEN_FAILED: ungültiger P-256-Skalar — ${e}`);
  }
  ```
- **Aufwand:** S
- **Abhängigkeiten:** keine
- **Test-Strategie:** Bestehende Pairwise-DID-Tests müssen grün bleiben. Negativtest mit manipuliertem `buildP256PKCS8` der invalides Material zurückgibt.

---

## Block B — Phase 6 Gate (Refactoring)

Erledigen bevor nächster Meilenstein (Pilot-Deployment). Sortierung: Abhängigkeiten zuerst.

---

#### F-18: `REFACTORING_ROADMAP.md` fehlt [NEU]

- **Status:** Neu identifiziert
- **Dateien:** Datei `REFACTORING_ROADMAP.md` existiert nicht im Repo
- **Problem:** F-16 des Audits referenziert explizit `REFACTORING_ROADMAP.md` mit "klarem Refactoring-Plan (Phase 6 Gate)". Die Datei existiert nicht. Wer den Audit liest und die Datei sucht, findet nichts. Das untergräbt die Glaubwürdigkeit des "bereits dokumentiert"-Status.
- **Konkreter Fix:** `REFACTORING_ROADMAP.md` im Repo-Root anlegen. Inhalt mindestens:
  - WalletService-Aufspaltung (aus F-16)
  - EphemeralKey-Konsolidierung (aus F-04)
  - Phasenzuordnung (Phase 6 Gate)
  - Verweis auf diesen Sprint Plan
- **Aufwand:** S
- **Abhängigkeiten:** muss vor F-16 erledigt sein
- **Test-Strategie:** `ls REFACTORING_ROADMAP.md` existiert; enthält Abschnitte für WalletService und EphemeralKey.

---

#### F-01: Recovery ist 3-of-3 XOR, nicht Shamir 2-of-3

- **Status:** Bestätigt
- **Dateien:** `src/packages/shared-crypto/src/recovery.ts`
- **Validierung:** Code eindeutig: `fragment3[i] = keyBytes[i] ^ fragment1[i] ^ fragment2[i]`, `recover()` wirft bei `fragments.length < 3`. Kommentar in Zeile 10–11 widerspricht sich selbst ("Shamir's 2-of-3" vs "Simplified XOR-based 2-of-2"). Tatsächliches Schema: 3-of-3 XOR. Kein Fragment verlierbar.
  Hinweis: Session 6 hat echtes GF(2^8)-SSS in `phase0-security/src/ADVANCED_SECURITY_HARDENING.ts` (`SplitKeyProtection`) implementiert, aber `recovery.ts` (das exportierte Package-Interface) ist unverändert XOR.
- **Konkreter Fix:** Zwei Optionen:
  - **Option A (empfohlen):** `recovery.ts` auf die in Session 6 implementierte GF(2^8)-SSS-Logik umstellen. `shamirSplit`/`shamirReconstruct` aus `phase0-security` extrahieren und in `shared-crypto/src/recovery.ts` einbetten (keine Abhängigkeit auf `phase0-security`). Interface anpassen: `recover(fragments: string[])` muss bereits mit 2 von 3 Fragmenten funktionieren.
  - **Option B:** Kommentar und Dokumentation korrigieren: "3-of-3 XOR-Schema (PoC). Alle drei Fragmente erforderlich. Kein Fragment verlierbar. Für Production: GF(2^8)-SSS implementieren (Ticket: F-01)." API-Breaking: `recover()` wirft weiter bei `< 3`, das aber klar dokumentiert.
- **Aufwand:** M (Option A) / S (Option B)
- **Abhängigkeiten:** keine; aber Zusammenhang mit F-04 (EphemeralKey-Konsolidierung)
- **Test-Strategie:** Option A: Test der 2-of-3-Eigenschaft — split in 3 Fragmente, recover mit Fragment 0+1, Fragment 0+2, Fragment 1+2 — alle müssen den ursprünglichen Key liefern. Option B: Dokumentations-Review, kein Code-Test nötig.

---

#### F-04: Drei EphemeralKey-Klassen konsolidieren

- **Status:** Bestätigt
- **Dateien:**
  - `src/packages/shared-crypto/src/ephemeral.ts` (CryptoKey-basiert, `extractable: true`, vollständig mit `shred()` + Lifecycle)
  - `src/packages/shared-crypto/src/ephemeral-key.ts` (Uint8Array-basiert, 33 Zeilen, `fill(0)` + null-Reference)
  - `src/packages/secure-memory/src/ephemeral_key.ts` (Node-only, zu verifizieren)
- **Validierung:** `pairwise-did.ts:12` importiert `ephemeral-key.ts` (Uint8Array-Variante). `ephemeral.ts` wird von `WalletService` verwendet. Beide co-existieren ohne gemeinsames Interface. Bestätigt.
- **Konkreter Fix:**
  1. `IEphemeralKey`-Interface in `shared-crypto/src/interfaces/` definieren: `shred()`, `isShredded()`, optionale `getKey()`
  2. `ephemeral-key.ts` und `ephemeral.ts` als separate Implementierungen mit dem Interface markieren
  3. `pairwise-did.ts`: Dokumentieren warum Uint8Array-Variante, nicht CryptoKey-Variante (Shredding von raw bytes vor dem GC)
  4. Kein Merge der Klassen nötig — sie haben unterschiedliche Use-Cases. Interface reicht.
- **Aufwand:** M
- **Abhängigkeiten:** F-18 (REFACTORING_ROADMAP.md) muss existieren um das als Phase-6-Gate zu vermerken
- **Test-Strategie:** Beide Implementierungen müssen Interface-konform sein (TypeScript-Compile als Test). Bestehende Tests für beide Varianten unverändert grün.

---

#### F-09: Strict Verifier Binding implementieren (Phase 1)

- **Status:** Bestätigt
- **Dateien:** `src/packages/policy-engine/src/engine.ts:460–470`
- **Validierung:** Der gesamte Origin-Check-Block (Zeilen 465–469) ist auskommentiert. `policy.globalSettings?.strictVerifierBinding` wird zwar gelesen (Zeile 460), der eigentliche Check passiert nicht. Bestätigt.
- **Konkreter Fix:** Phase 1 — einfacher Origin-Host-gegen-VerifierPattern-Check:
  ```typescript
  if (policy.globalSettings?.strictVerifierBinding && request.origin) {
      const originHost = new URL(request.origin).hostname;
      if (!this.matchesPattern(rule.verifierPattern, originHost)) {
          console.warn(`[PolicyEngine] Verifier-Binding fehlgeschlagen: ${request.verifierId} von ${originHost}`);
          return null; // Binding fehlgeschlagen → Kein Match
      }
  }
  ```
  Erfordert F-02 (ReDoS-Fix) als Voraussetzung, da `matchesPattern` hier aufgerufen wird.
  Phase 2 (`.well-known/did-configuration`): Backlog.
- **Aufwand:** M (Phase 1)
- **Abhängigkeiten:** F-02 muss vorher erledigt sein
- **Test-Strategie:** Test: `strictVerifierBinding: true`, Request mit `origin: 'https://evil.com'`, Verifier-Pattern `did:mitch:liquor-store` → muss `DENY_NO_MATCHING_RULE` zurückgeben. Test: `origin: 'https://liquor-store.at'`, Pattern `*liquor-store*` → muss durchlassen.

---

#### F-15: Test-Coverage für kritische Packages

- **Status:** Bestätigt
- **Dateien:** `src/packages/shared-crypto/src/recovery.ts`, `src/packages/layer-resolver/src/`
- **Validierung:** `phase0-security` hat weiterhin `"test": "node -e \"console.log('phase0-security: no tests')\""`. `layer-resolver` hat laut Audit 0 Tests — prüfen. `recovery.ts` hat keine direkten Tests in `shared-crypto/test/`.
- **Konkreter Fix:** Prioritätsreihenfolge:
  1. `shared-crypto/test/recovery.test.ts` — Tests für `splitMasterKey()` + `recover()` (Roundtrip, Fehlerfall < 3 Fragmente, Korrektheit des XOR-Schemas)
  2. `layer-resolver`: Wenn keine Tests, mindestens Smoke-Tests für die Haupt-Export-Funktion
  3. `phase0-security`: Entweder `vitest` konfigurieren oder Package als "kein öffentliches API" markieren
- **Aufwand:** M
- **Abhängigkeiten:** F-01 (wenn Option A gewählt, müssen Recovery-Tests das SSS-Verhalten testen)
- **Test-Strategie:** `pnpm turbo test` muss alle neuen Tests grün zeigen. Coverage-Report: `recovery.ts` > 80% Branch-Coverage.

---

#### F-16: WalletService God Object

- **Status:** Korrigiert — Audit behauptet "bereits in `REFACTORING_ROADMAP.md` dokumentiert", diese Datei existiert nicht.
- **Dateien:** `src/apps/wallet-pwa/src/services/WalletService.ts` (1081 LOC)
- **Validierung:** `REFACTORING_ROADMAP.md` — nicht im Repo. Der Audit-Status "BEKANNT / bereits dokumentiert" ist damit nicht belegt.
- **Konkreter Fix:**
  1. F-18 erledigen (REFACTORING_ROADMAP.md erstellen)
  2. Dort WalletService-Aufspaltungsplan dokumentieren: welche Verantwortlichkeiten in welche neuen Services (z.B. `CredentialService`, `KeyService`, `AuditService`, `PresentationService`)
  3. Implementierung als Phase-6-Gate markieren — kein Code jetzt
- **Aufwand:** S (Dokumentation), L (eigentliche Aufspaltung — Phase 6)
- **Abhängigkeiten:** F-18 zuerst
- **Test-Strategie:** Dokumentation vorhanden. Für die eigentliche Aufspaltung: Alle bestehenden WalletService-Tests müssen nach Refactoring grün bleiben.

---

#### F-12: L2-Anchoring-Status klar kommunizieren [KORRIGIERT]

- **Status:** Korrigiert (teilweise erledigt in Session 6)
- **Dateien:** `src/packages/audit-log/src/storage/l2-anchor-client.ts`
- **Validierung:** Session 6 hat erledigt: Merkle-Tree in `calculateBatchRoot()`, Env-Var-Adressen in `getDefaultContractAddress()`, strukturierter `verifyAnchor()`-Stub. Noch nicht erledigt: `submitToL2()` fällt weiter auf `mockAnchor()` zurück. Der Audit-Befund "5 TODOs" trifft noch auf 2 zu. README/ARCHITECTURE.md-Aussage des Audits — ob das Dokument L2 ohne Mock-Markierung bewirbt — nicht verifiziert.
- **Konkreter Fix:** Klare Mock-Markierung in allen öffentlichen Dokumenten die L2-Anchoring erwähnen: "L2-Anchoring ist vorbereitet und partiell implementiert (Merkle-Tree, Env-Var-Konfiguration). `submitToL2()` gibt noch einen Mock-Receipt zurück bis die Anchor-Contracts deployed sind. Deployment: Backlog." Kein weiterer Code nötig.
- **Aufwand:** S (Dokumentation)
- **Abhängigkeiten:** keine
- **Test-Strategie:** Alle Doku-Dateien die "L2" erwähnen reviewen, Mock-Status kommunizieren.

---

#### F-05: EphemeralKey `extractable: true` dokumentieren

- **Status:** Bestätigt
- **Dateien:** `src/packages/shared-crypto/src/ephemeral.ts:43`
- **Validierung:** `true, // extractable` bestätigt. Der Kommentar erklärt den Grund (Key-Wrapping). Das ist eine bewusste Entscheidung, keine Nachlässigkeit.
- **Konkreter Fix:** Keine Code-Änderung. Kommentar erweitern:
  ```typescript
  true, // extractable — KNOWN LIMITATION: ermöglicht Key-Wrapping für Recovery,
        // bedeutet aber dass ein Angreifer mit Heap-Zugriff exportKey() aufrufen könnte.
        // Langfristig: TEE-Migration (T-31). Für Pilot: akzeptiert und dokumentiert.
  ```
  Eintrag in REFACTORING_ROADMAP.md: TEE-Migration als langfristige Maßnahme.
- **Aufwand:** S
- **Abhängigkeiten:** F-18 (REFACTORING_ROADMAP.md) als Ablageort
- **Test-Strategie:** Code-Review. Kein Funktionstest nötig.

---

## Block C — Backlog

Kein Pilot-Blocker. Erledigen wenn Kapazität.

---

#### F-07: Selective Decryption ist Post-Decrypt-Filtering

- **Status:** Bestätigt (Code-Kommentar ist ehrlich)
- **Dateien:** `src/packages/secure-storage/src/index.ts:197–209`
- **Validierung:** Zeilen 197–199 geben es explizit zu: "Decrypt full payload (currently we don't have per-claim encryption blobs)". Post-decryption filtering ist klar implementiert. Die Aussage nach außen ("Minimize before decrypt") ist irreführend, der interne Kommentar aber ehrlich.
- **Konkreter Fix:** Kurzfristig: Außen-Dokumentation anpassen. Langfristig: Claim-Level-Encryption (jeder Claim separater AES-GCM-Ciphertext mit eigenem Key). Das ist eine architekturelle Änderung — kein Sprint-Item.
- **Aufwand:** S (Doku) / L (echte Claim-Level-Encryption)
- **Abhängigkeiten:** keine
- **Test-Strategie:** N/A für Doku-Fix.

---

#### F-14: Kein Key-Rotation-Mechanismus

- **Status:** Bestätigt (wahrscheinlich — `rotateKey()` nicht in `secure-storage/src/index.ts` gesehen)
- **Dateien:** `src/packages/secure-storage/src/index.ts`
- **Konkreter Fix:** `async rotateKey(oldKey: CryptoKey, newKey: CryptoKey): Promise<void>` — iteriert alle Einträge, entschlüsselt mit `oldKey`, verschlüsselt mit `newKey`. Für Pilot nicht nötig.
- **Aufwand:** M
- **Abhängigkeiten:** keine
- **Test-Strategie:** Test: Credential speichern, rotateKey() aufrufen, mit neuem Key lesen → Inhalt unverändert. Mit altem Key → Decryption fehlschlägt.

---

## Reihenfolge-Zusammenfassung

```
Block A (Sofort, 1–2 Tage):
  1. F-10 — CI reparieren          (S, kein Code, alles andere profitiert davon)
  2. F-02 — ReDoS fixen            (S, Sicherheit, Voraussetzung für F-09)
  3. F-03 — Echter SHA-256         (S, Integrität)
  4. F-11 — Stale files löschen    (S, Hygiene)
  5. F-08 — getRawDocument() Guard (S)
  6. F-06 — importKey Error-Handling (S)
  7. F-17 — Algorithm-Probe        (S)
  8. F-13 — CSP-Header             (S)

Block B (Phase 6 Gate, diese Woche):
  1. F-18 — REFACTORING_ROADMAP.md erstellen (S, Voraussetzung für F-04, F-16)
  2. F-01 — Recovery: Option A oder B        (M, kritischstes inhaltliches Finding)
  3. F-12 — L2-Stub-Status dokumentieren     (S)
  4. F-05 — Extractable-Kommentar            (S)
  5. F-09 — Verifier Binding Phase 1         (M, braucht F-02)
  6. F-04 — EphemeralKey-Interface           (M)
  7. F-15 — Test-Coverage                    (M, braucht F-01-Entscheidung)
  8. F-16 — WalletService-Plan in Roadmap    (S Doku, L Implementierung = Backlog)

Block C (Backlog):
  F-07, F-14 — kein Pilot-Blocker
```

---

## Neue Findings aus der Validierung

#### F-18: `REFACTORING_ROADMAP.md` wird referenziert, existiert nicht

- **Gefunden durch:** Validierung von F-16
- **Datei:** Repo-Root (fehlend)
- **Problem:** Audit F-16 markiert WalletService als "bereits in REFACTORING_ROADMAP.md dokumentiert". Datei existiert nicht. Ein externer Reviewer der das nachprüft findet nichts und verliert Vertrauen in die restlichen "bereits dokumentiert"-Aussagen.
- **Konkreter Fix:** Datei anlegen. Mindestinhalt: WalletService-Aufspaltungsplan, EphemeralKey-Konsolidierung, TEE-Migration-Verweis, Phasenzuordnung.
- **Aufwand:** S
- **Block:** B (Phase 6 Gate, Voraussetzung für andere B-Items)
