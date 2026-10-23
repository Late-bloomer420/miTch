# Security- und Privacy-Review: miTch

**Baseline:** `624cf9a` (nach PR #174, 2026-10-15)
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
| **Impact** | **Keine wallet-seitige Policy-Prüfung** – Verifier prüft nur Signaturen |

**Beleg:**
- Issue #170: "`src/packages/connect` is absent at the checked baseline"
- Verzeichnisliste: Paket nicht vorhanden

**Fix:**
- `src/packages/connect` implementieren (per [`ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](../tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md))
- **Wallet-seitige Enforcement** (nicht nur Verifier-Signaturcheck)

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
- **BE/BS-Flags** (Browser-Enforcement/Attestation) werden **nicht geprüft** → NOT PROVEN

---

### P1-2: Lokale Predicates vs. issuer-signierte `age_over_NN` (mdoc, Issue #97)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | OPEN |
| **Datei:Zeile** | `evaluate.ts:20-40` (`CommonPredicates.ageAtLeast(18)`) |
| **Lücke** | Wallet berechnet `age >= 18` **lokal** aus `dateOfBirth` |
| **Impact** | **Keine issuer-authentifizierte ZKP** – nicht EUDI AV-compliant |

**Beleg:**
- Issue #97: "Local predicate evaluation plus a wallet signature is **not** an evidenced issuer-authenticated ZK derivation"
- Issue #97: "Current real ADOPT SD-JWT path selectively discloses **numeric age**"
- EUDI AV Profile (`eu.europa.ec.av.1`) erfordert **`age_over_NN` (boolean)**, nicht numerisches `age`

**Fix:**
- EUDI AV Profile (`eu.europa.ec.av.1`) implementieren
- `age_over_NN` (boolean) statt numerischem `age`
- mdoc statt SD-JWT VC für AV-Profil

---

### P1-3: `decisionId` unsicher (PR #151 nicht gemergt)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | REAL |
| **Datei:Zeile** | `evaluate.ts:375` |
| **Lücke** | `Math.random()` statt `crypto.randomUUID()` |
| **Impact** | Predictable IDs ermöglichen **Tracking/Korrelation** (keine direkte Sicherheitslücke) |

**Code-Beleg (`evaluate.ts:375`):**
```typescript
const decisionId = `decision_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
```

**PR-Status:**
- PR #151: `mergedAt: null`, `state: "OPEN"` (nicht gemergt)

**Fix:**
- PR #151 mergen **oder**
- `decisionId` auf `globalThis.crypto.randomUUID()` ändern

---

## ⚪ P2: Offene Punkte

### P2-1: EV-05 (Security-Audits nicht gating)

| **Aspekt** | **Details** |
|-----------|-------------|
| **Status** | NOT PROVEN |
| **Beleg** | `REPO_EVIDENCE_STATUS_2026-10-14.md`: "Audit steps are **advisory**" |

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
| **Beleg** | Keine direkte Evidenz im gelesenen Code (Wallet nutzt `globalThis.crypto.subtle` in-memory) |

---

## 📊 Zusammenfassung pro Punkt

| **ID** | **Priorität** | **Status** | **Kurzfassung** | **Fix** |
|--------|--------------|------------|----------------|---------|
| P0-1 | **P0** | REAL | Request-Binding-Lücke in `/oid4vp-present` | Session-Speicherung + 4 Regressionstests |
| P0-2 | **P0** | NOT PROVEN | Keine Enforcement-Grenze (`connect` fehlt) | `src/packages/connect` implementieren |
| P1-1 | **P1** | PARTIAL | HARDWARE_BOUND = nur WebAuthn (kein TEE) | Label/Doku korrigieren |
| P1-2 | **P1** | OPEN | Lokale Predicates ≠ EUDI AV Compliance | `age_over_NN` (mdoc) implementieren |
| P1-3 | **P1** | REAL | `decisionId` unsicher (`Math.random()`) | PR #151 mergen |
| P2-1 | **P2** | NOT PROVEN | EV-05 = advisory, keine Findings | Zahlen entfernen |
| P2-2 | **P2** | NOT PROVEN | Keine SBOM/Signaturen | – |
| P2-3 | **P2** | NOT PROVEN | XSS/IndexedDB nicht bestätigt | – |

---

## 🎯 Empfehlung (priorisiert)

1. **#170 sofort schließen (P0)**
   - Session-Speicherung in `/oid4vp-present` implementieren
   - Request-Binding (nonce, state, audience) serverseitig validieren
   - **4 Regressionstests** hinzufügen

2. **PR #151 mergen (P1)**
   - `decisionId` auf `crypto.randomUUID()` ändern

3. **HARDWARE_BOUND klären (P1)**
   - Label in **`WEBAUTHN_BOUND`** umbenennen
   - Dokumentation in [`10_KEY_PROTECTION_REALITY.md`](../_core/10_KEY_PROTECTION_REALITY.md) aktualisieren

4. **EUDI AV Profile umsetzen (P1)**
   - `age_over_NN` (boolean) statt numerischem `age`
   - mdoc statt SD-JWT VC für AV-Profil

5. **Enforcement-Grenze definieren (P0)**
   - `src/packages/connect` implementieren (per [`ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](../tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md))
   - **Wallet-seitige Policy-Prüfung** (nicht nur Verifier-Signaturcheck)

---

## 🔗 Quellenverzeichnis (alle Aussagen belegbar)

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
