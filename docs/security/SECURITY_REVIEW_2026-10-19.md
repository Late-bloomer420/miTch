# Security- und Privacy-Review: miTch

## Abgleich vom 24.10.2026 — aktuelle Einordnung

Geprüfter `master`: [`a21ac24`](https://github.com/Late-bloomer420/miTch/commit/a21ac24e2e7f091b3652f91dfd26162f5a822914).
Gegenüber `624cf9a` ist nur der Ciphertext-Tamper-Test aus [#190](https://github.com/Late-bloomer420/miTch/pull/190) geändert
([Vergleich](https://github.com/Late-bloomer420/miTch/compare/624cf9af919fe58a7cba34a05b316b17e49c7e0f...a21ac24e2e7f091b3652f91dfd26162f5a822914)).
Die betroffenen Runtime-Dateien sind unverändert. Die HTTP-Gegenbeispiele bleiben **datierte
Reproduktionen vom 14.10.**, ergänzt durch statischen Code-Abgleich; hier wurde kein neuer
Runtime-/Browser-/Interop-Test durchgeführt. Ein SHA oder statisches Lesen ist kein Security-PASS.

| Bereich | Belegte Einordnung / kleinster nächster Schritt |
|---|---|
| P0-1 / #170 | Weiter offen auf master: ursprünglicher Server-Request fehlt in der aktiven Route. Fix plus echte HTTP-/Signatur-Negativtests für Replay, Nonce/State/Audience, Ablauf/Konkurrenz, Eligibility und überschüssige Claims nötig. Erst mit Fix-Commit und Artefakten schließen. |
| P0-2 / Connect | Auf master fehlt das Paket; [#193](https://github.com/Late-bloomer420/miTch/pull/193) bietet es an Head `afea2a778f31d18785eed5aaa981701ac24a94f4` an, ist aber **offen/unmerged** und integriert verifier-demo ausdrücklich noch nicht. Connect ist **RP-seitige** Verifier-/Policy-Integration gemäß [Produktentscheidung](../tasks/ADOPT_1_PRODUCT_BOUNDARY_DECISION.md), kein Beleg für fehlende wallet-seitige Policy-Komponenten. |
| #193 Restarbeit | Unaufgelöste Reviews: [P1 Resolver-Rejection](https://github.com/Late-bloomer420/miTch/pull/193#discussion_r4364763904), [P2 terminale Expiry überschrieben](https://github.com/Late-bloomer420/miTch/pull/193#discussion_r4364763898). Required checks am genannten Head erfolgreich; alte CodeQL-Regex-Threads resolved/outdated. Grüne Checks schließen diese Reviews nicht. [Core-Tests](https://github.com/Late-bloomer420/miTch/blob/afea2a778f31d18785eed5aaa981701ac24a94f4/src/packages/connect/test/core.test.ts#L7) verwenden einen Validator-Stub; echte aktive HTTP-/Krypto-Integration bleibt separat nachzuweisen. Im Core werden erforderliche Claims geprüft, überschüssige Claims jedoch nicht ausdrücklich abgelehnt ([verifier.ts:312–347](https://github.com/Late-bloomer420/miTch/blob/afea2a778f31d18785eed5aaa981701ac24a94f4/src/packages/connect/src/core/verifier.ts#L312) am genannten Head). |
| Wallet-Enforcement | Eigenständige offene Grenze: [#180](https://github.com/Late-bloomer420/miTch/issues/180) finaler Disclosure-PEP und [#181](https://github.com/Late-bloomer420/miTch/issues/181) adversariale Tests. Fehlendes Connect allein beweist keinen generellen PolicyEngine-Ausfall. |
| P1 Hardware | [`IdentityKeyGuardian.getLevel()`](../../src/packages/shared-crypto/src/IdentityKeyGuardian.ts) produziert HARDWARE_BOUND aus registriertem WebAuthn; [WalletService](../../src/apps/wallet-pwa/src/services/WalletService.ts) instanziiert den Guardian. Die Aussagen „nie produziert/test-only/nicht wired“ in der Juli-Key-Reality-Datei sind hierfür überholt. Kein allgemeiner TEE-/Hardware-Attestationsnachweis; Registrierung nutzt `attestation: 'none'`. BE/BS bedeutet **Backup Eligibility/Backup State**, nicht Browser-Enforcement. |
| P1 AV / #97 | Lokale Wallet-Predicates, echter ADOPT-Pfad mit numerischem age und offizielles AV-Profil sind unterschiedliche Verträge. #97 bleibt offen; [#182](https://github.com/Late-bloomer420/miTch/issues/182) plant ein predicate-only Profil. Kein stiller Wechsel des akzeptierten Numeric-age-Piloten; aktuelle offizielle Profil-/Issuer-Versionen vor Umsetzung festlegen. |
| P1 decisionId | Math.random() weiterhin in [`evaluate.ts:375`](../../src/packages/predicates/src/evaluate.ts#L375); #151 offen. Nicht-kryptographische Entropie und eingebetteter Zeitstempel sind belegt, kein Signatur-Forgery- oder allgemeiner Tracking-Exploit. Patch am aktuellen Head mit gezielten Randomness-/Format-Tests prüfen. |
| EV-05 | Weiter offen: [`ci-security.yml`](../../.github/workflows/ci-security.yml) ist advisory und fängt Audit-Fehler ab. Datierte synthetische Fehl-Erfolge sind belegt; aktuelle CVE-Zahlen nicht. #141 / SEC-AUDIT-1/2 bleiben zuständig, #185 ergänzt Assurance-Planung. |

**Merge-Abgleich:** [#152](https://github.com/Late-bloomer420/miTch/pull/152) seit 02.10.2026 gemergt
(`80587d00f8ca185d0d921e0d6221c8aa800d41ae`), nicht erneut als offenen Blocker führen.
[#141](https://github.com/Late-bloomer420/miTch/pull/141) offen mit Konflikten: relevante CORS/Session/Key/Recovery-/Audit-Änderungen
auf aktuellem master gezielt versöhnen, keinen alten Tree pauschal mergen.
[#150](https://github.com/Late-bloomer420/miTch/pull/150) und [#151](https://github.com/Late-bloomer420/miTch/pull/151) sind offen; aktuelle
Signaturformat-/Key-Consumer- bzw. Randomness-Evidenz entscheidet über Merge, nicht diese Doku.

**Neuere Doku:** [#178](https://github.com/Late-bloomer420/miTch/pull/178) Assurance-Verträge,
[#187](https://github.com/Late-bloomer420/miTch/pull/187) STRIDE × LINDDUN (Wallet TB-W / Verifier TB-S),
[#188](https://github.com/Late-bloomer420/miTch/pull/188) statischer Architektur-Audit (u. a. Proximity-Authorization/Mock-DeviceAuth,
EV-09), [#179](https://github.com/Late-bloomer420/miTch/pull/179) Source-Watch und [#191](https://github.com/Late-bloomer420/miTch/pull/191) DPIA-Wording
sind offen/unmerged. Sie sind Review-/Planungsinput, keine implementierten Kontrollen oder neue
Zertifizierung. `624cf9a` als statische Re-Check-Baseline in #188 darf nicht als
dynamischer Sicherheitsnachweis für #192 ausgegeben werden.

**Roadmap bleibt kanonisch:** [BACKLOG](../BACKLOG.md), [Release-Roadmap](../RELEASE_READINESS_ROADMAP.md),
[#142](https://github.com/Late-bloomer420/miTch/issues/142) / [#143](https://github.com/Late-bloomer420/miTch/issues/143).
G0/G1 bleiben offen; kein Gate, Zieldatum oder Produktziel wird durch diese Korrektur geändert.
[#171](https://github.com/Late-bloomer420/miTch/issues/171), [#172](https://github.com/Late-bloomer420/miTch/issues/172), [#173](https://github.com/Late-bloomer420/miTch/issues/173) bleiben gesonderte Lifecycle-/Audit-/Evidence-Arbeit.

---

**Historische Review-Baseline:** `624cf9a` (nach PR #174, 2026-10-15)
**Gelesene Quellen:**
- [Issue #170](https://github.com/Late-bloomer420/miTch/issues/170) (P0 ADOPT-1: enforce server-owned SD-JWT request binding)
- [PR #174](https://github.com/Late-bloomer420/miTch/pull/174) (docs: preserve scoped evidence)
- [PR #130](https://github.com/Late-bloomer420/miTch/pull/130) (chore: wire credential-pool)
- [PR #151](https://github.com/Late-bloomer420/miTch/pull/151) (fix: Secure decisionId generation – **OPEN**)
- [Issue #97](https://github.com/Late-bloomer420/miTch/issues/97) (EUDI interop gap: mdoc AV Profile)
- [Issue #140](https://github.com/Late-bloomer420/miTch/pull/140) (Dependabot: PostCSS 8.5.15→8.5.25)
- [`docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md`](REPO_EVIDENCE_STATUS_2026-10-14.md)
- [`docs/_core/10_KEY_PROTECTION_REALITY.md`](../_core/10_KEY_PROTECTION_REALITY.md)
- [`docs/tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](../tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md)

**Code-Quellen:**
- `src/apps/verifier-demo/backend/src/app.ts` (Zeilen 260-340: `/oid4vp-present` Route)
- `src/packages/predicates/src/evaluate.ts` (Zeile 375: `decisionId` Generation)
- `src/packages/shared-crypto/src/IdentityKeyGuardian.ts` (Zeilen 43-48: HARDWARE_BOUND Logic)

---

## 🔴 P0: Kritische Schwachstellen (sofort handeln)

### P0-1: Request-Binding-Lücke in `/oid4vp-present` (Issue #170)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | REAL |
| **Datei:Zeile** | `app.ts:317-340` |
| **Lücke** | Nonce und State werden **aus dem eingehenden Token/Body rekonstruiert**, nicht aus dem ursprünglichen Server-Request |
| **Reproduktion** | Issue #170: "Different holder-selected nonce/state: HTTP 200", "Identical valid VP token twice: HTTP 200 then HTTP 200" |
| **Impact** | Replay-Angriffe möglich, `ok:true` bedeutet **nur Signaturgültigkeit**, nicht Eligibility |

**Code-Beleg (`app.ts:317-340`):**
```typescript
const reconstructedRequest = {
  response_type: 'vp_token' as const,
  client_id: ASKMI_DEMO.verifierDid,
  redirect_uri: `${baseUrl}/oid4vp-present`,
  nonce: '',  // ← wird später aus KB-JWT gefüllt
  presentation_definition: { id: 'reconstructed', input_descriptors: [] }, // ← LEER!
  response_mode: 'direct_post' as const,
  state: body.state, // ← aus Request-Body (Angreifer-kontrolliert)
};
// ...
reconstructedRequest.nonce = kbPayload.nonce ?? ''; // ← aus KB-JWT (Angreifer-kontrolliert)
```

**Fehlende Prüfungen:**
- Kein Vergleich mit dem **ursprünglichen Server-Request** (nonce, state, audience)
- Keine **Eligibility-Prüfung** (`age:12` → `ok:true`)
- **Leere Presentation Definition** (`input_descriptors: []`)

**Fix:**
1. Session-Speicherung implementieren (per [`ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](../tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md))
2. Originalen Request serverseitig speichern und vergleichen
3. **4 Regressionstests** hinzufügen:
   - `[VORSCHLAG] test_replay_identical_vp_token`
   - `[VORSCHLAG] test_arbitrary_nonce_state_rejected`
   - `[VORSCHLAG] test_age_12_crypto_valid_but_not_eligible`
   - `[VORSCHLAG] test_extra_claims_rejected`

---

### P0-2: Fehlende Enforcement-Grenze (`src/packages/connect` fehlt)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | NOT PROVEN |
| **Datei** | – (Paket existiert nicht) |
| **Lücke** | Keine Implementierung von `src/packages/connect` (Issue #170: "is absent at the checked baseline") |
| **Impact** | Akzeptierter RP-seitiger Connect-Vertrag ist auf master nicht integriert; wallet-seitige PEP-Abdeckung separat unter #180/#181 offen |

**Beleg:**
- Issue #170: "`src/packages/connect` is absent at the checked baseline"
- Verzeichnisliste: Paket nicht vorhanden

**Fix:**
- `src/packages/connect` implementieren (per [`ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](../tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md))
- RP-seitige Request-/Session-/Eligibility-Enforcement integrieren; wallet-seitigen finalen Disclosure-PEP separat unter #180/#181 nachweisen

---

## 🟡 P1: Wichtige Lücken

### P1-1: HARDWARE_BOUND = nur WebAuthn (kein TEE)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | PARTIAL |
| **Datei:Zeile** | `IdentityKeyGuardian.ts:43-48` |
| **Lücke** | Label suggeriert TEE/Attestation, aber **nur WebAuthn/passkeys** |
| **Impact** | Irreführende Dokumentation – kein TEE, keine BE/BS-Flags-Prüfung |

**Code-Beleg (`IdentityKeyGuardian.ts:43-48`):**
```typescript
async getLevel(): Promise<KeyProtectionLevel> {
  if (await WebAuthnService.isIdentityRegistered()) {
    return KeyProtectionLevel.HARDWARE_BOUND; // ← nur WebAuthn!
  }
  return KeyProtectionLevel.SOFTWARE_EPHEMERAL;
}
```

**Dokumentation:**
- [`10_KEY_PROTECTION_REALITY.md`](../_core/10_KEY_PROTECTION_REALITY.md): "**There is no TEE**"
- "The one real hardware-trust seam that IS wired is **WebAuthn / passkeys**"

**Fix:**
- Label in **`WEBAUTHN_BOUND`** umbenennen **oder**
- Dokumentation klarstellen: **HARDWARE_BOUND = WebAuthn/passkeys, kein TEE/Attestation**

**Offenes Finding:**
- BE/BS = **Backup Eligibility/Backup State**; diese Flags und Hardware-Attestation sind unterschiedliche Nachweise. Getestete Durchsetzung in dieser Review nicht belegt.

---

### P1-2: Lokale Predicates vs. issuer-signierte `age_over_NN` (mdoc, Issue #97)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | OPEN |
| **Datei:Zeile** | `evaluate.ts:20-40` (`CommonPredicates.ageAtLeast(18)`) |
| **Lücke** | Wallet berechnet `age >= 18` **lokal** aus `dateOfBirth` |
| **Impact** | Lokale Predicate-Signatur ist kein Nachweis einer issuer-authentifizierten ZK-Ableitung; vollständige offizielle AV-Profil-Konformität bleibt unbelegt |

**Beleg:**
- Issue #97: "Local predicate evaluation plus a wallet signature is **not** an evidenced issuer-authenticated ZK derivation"
- Issue #97: "Current real ADOPT SD-JWT path selectively discloses **numeric age**"
- EUDI AV Profile (`eu.europa.ec.av.1`) erfordert **`age_over_NN` (boolean)**, nicht numerisches `age`

**Fix:**
- Unter #97/#182 zuerst exakte aktuelle Profil-/Quell-/Issuer-Versionen entscheiden; danach dedizierten AV-Pfad implementieren und interoperabel prüfen. Den akzeptierten Numeric-age-Connect-Piloten nicht stillschweigend ersetzen.

---

### P1-3: `decisionId` unsicher (PR #151 nicht gemergt)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | REAL |
| **Datei:Zeile** | `evaluate.ts:375` |
| **Lücke** | `Math.random()` statt `crypto.randomUUID()` |
| **Impact** | Nicht-kryptographische Entropie und eingebetteter Zeitstempel; konkreter Tracking-/Forgery-Exploit hier nicht nachgewiesen |

**Code-Beleg (`evaluate.ts:375`):**
```typescript
const decisionId = `decision_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
```

**PR-Status:**
- PR #151: `mergedAt: null`, `state: "OPEN"` (nicht gemergt)

**Fix:**
- PR #151 am aktuellen Head mit Randomness-/Format-Regressions prüfen und erst danach landen **oder**
- `decisionId` auf `globalThis.crypto.randomUUID()` ändern

---

## ⚪ P2: Offene Punkte

### P2-1: EV-05 (Security-Audits nicht gating)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | Datierte Reproduktion; statisch unverändert, keine aktuelle CVE-Anzahl abgeleitet |
| **Beleg** | `REPO_EVIDENCE_STATUS_2026-10-14.md` EV-05 und `.github/workflows/ci-security.yml` |

**Korrektur:**
- **Issue #140 ist ein Dependabot PR** (PostCSS Update), **kein Audit**
- Zahlen **"27 Findings, 10 High" sind unbelegt** → entfernen

---

### P2-2: Supply Chain (SBOM/Signaturen)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | NOT PROVEN |
| **Beleg** | Keine `sbom.json`, `.sigstore`, oder CI-Signaturprüfung gefunden |

---

### P2-3: XSS/IndexedDB (Key Extraction)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | NOT PROVEN |
| **Beleg** | Kein Exploit in dieser Review nachgewiesen. In-memory WebCrypto ist kein allgemeiner Ausschluss: `WalletService.fetchAndStoreSdJwtVc/addSdJwtVc` exportiert und speichert Holder-Private-JWKs im geschützten Store. Key-/XSS-Boundary unter #186 prüfen. |

---

## 📊 Zusammenfassung pro Punkt

| **ID** | **Priorität** | **Status** | **Kurzfassung** | **Fix** |
|--------|--------------|------------|----------------|---------|
| P0-1 | **P0** | REAL | Request-Binding-Lücke in `/oid4vp-present` | Session-Speicherung + 4 Regressionstests |
| P0-2 | **P0** | NOT PROVEN | Keine Enforcement-Grenze (`connect` fehlt) | `src/packages/connect` implementieren |
| P1-1 | **P1** | PARTIAL | HARDWARE_BOUND = nur WebAuthn (kein TEE) | Label/Doku korrigieren |
| P1-2 | **P1** | OPEN | Lokale Predicates ≠ EUDI AV Compliance | `age_over_NN` (mdoc) implementieren |
| P1-3 | **P1** | REAL | `decisionId` unsicher (`Math.random()`) | PR #151 mergen |
| P2-1 | **P0 für behauptetes Security-Gate** | Offen, datiert reproduziert | EV-05 = advisory, aktuelle CVE-Anzahl unbelegt | Gate-/Audit-Fehler-Negativtests (#141/SEC-AUDIT-1/2) |
| P2-2 | **P2** | NOT PROVEN | Keine SBOM/Signaturen | – |
| P2-3 | **P2** | NOT PROVEN | XSS/IndexedDB nicht bestätigt | – |

---

## 🎯 Empfehlung (priorisiert)

1. **#170 beheben und bis zur aktiven Integrations-Evidenz offen halten (P0)**
   - Session-Speicherung in `/oid4vp-present` implementieren
   - Request-Binding (nonce, state, audience) serverseitig validieren
   - **4 Regressionstests** hinzufügen

2. **PR #151 am aktuellen Head prüfen (P1)**
   - Randomness-/Format-Regressions und Consumer-Kompatibilität vor Merge belegen

3. **HARDWARE_BOUND klären (P1)**
   - WebAuthn von nachgewiesener Hardware-Residency/Attestation trennen; API-Umbenennung benötigt separate Freigabe
   - Dokumentation in [`10_KEY_PROTECTION_REALITY.md`](../_core/10_KEY_PROTECTION_REALITY.md) aktualisieren

4. **EUDI AV Profile separat entscheiden (P1, #97/#182)**
   - Aktuelle Profil-/Issuer-Versionen und Negativ-/Interop-Evidenz definieren; Numeric-age-Pilot unverändert als solchen benennen

5. **Enforcement-Grenze definieren (P0)**
   - `src/packages/connect` implementieren (per [`ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](../tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md))
   - RP-Enforcement in #193/aktiver Route; Wallet-PEP gesondert in #180/#181

---

## 🔗 Historisches Quellenverzeichnis (Geltungsgrenzen siehe Abgleich oben)

| **Aussage** | **Typ** | **Quelle** |
|-------------|---------|------------|
| `/oid4vp-present` rekonstruiert Nonce/State | GELESEN | [Issue #170](https://github.com/Late-bloomer420/miTch/issues/170) + `app.ts:317-340` |
| Replay: gleicher VP-Token 2x akzeptiert | GELESEN | [Issue #170](https://github.com/Late-bloomer420/miTch/issues/170) |
| `ok:true` = Signaturgültigkeit, nicht Eligibility | GELESEN | [Issue #170](https://github.com/Late-bloomer420/miTch/issues/170) |
| `age:12` wird akzeptiert | GELESEN | [Issue #170](https://github.com/Late-bloomer420/miTch/issues/170) |
| `src/packages/connect` fehlt | GELESEN | [Issue #170](https://github.com/Late-bloomer420/miTch/issues/170) + Verzeichnisliste |
| `decisionId` verwendet `Math.random()` | GELESEN | `evaluate.ts:375` |
| PR #151 nicht gemergt | GELESEN | [PR #151](https://github.com/Late-bloomer420/miTch/pull/151) (`mergedAt: null`) |
| HARDWARE_BOUND = WebAuthn, kein TEE | GELESEN | `IdentityKeyGuardian.ts:43-48` + [`10_KEY_PROTECTION_REALITY.md`](../_core/10_KEY_PROTECTION_REALITY.md) |
| Issue #140 = Dependabot PR | GELESEN | [PR #140](https://github.com/Late-bloomer420/miTch/pull/140) |
| EUDI AV offen | GELESEN | [Issue #97](https://github.com/Late-bloomer420/miTch/issues/97) |
| Lokale Predicates = nicht issuer-authentifiziert | GELESEN | [Issue #97](https://github.com/Late-bloomer420/miTch/issues/97) |
| EV-05 = advisory, nicht gating | GELESEN | [`REPO_EVIDENCE_STATUS_2026-10-14.md`](REPO_EVIDENCE_STATUS_2026-10-14.md) |

---

## 📝 Changelog

| **Version** | **Datum** | **Änderungen** |
|-------------|-----------|----------------|
| 1.0 | 2026-10-19 | Initiale Version (basierend auf Issue #170, PR #174, Code-Analyse) |
| 1.1 | 2026-10-24 | Statischer Current-master-/PR-/Drive-Abgleich; Scope-/Merge-/Empfehlungskorrekturen, keine neue Runtime-Evidenz oder Gate-Schließung |
