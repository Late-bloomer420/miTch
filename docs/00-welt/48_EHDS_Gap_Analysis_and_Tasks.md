# EHDS Compliance Gap Analysis & Task List
## Was wir gelernt haben — und was noch fehlt

**Quelle:** [ehds-jurist.nl — The existing free flow of health data](https://ehds-jurist.nl/the-existing-free-flow-of-health-data/)
**Datum:** 2026-03-04
**Status:** Aktiv — wird laufend aktualisiert

---

## 🧠 Was wir heute gelernt haben

### Erkenntnis 1 — Der EHDS schafft nichts Neues, er macht Bestehendes sichtbar

**GDPR Art. 1** verbietet bereits heute die Einschränkung des freien Datenflusses
innerhalb der EU. Der EHDS *unterstützt* diesen Fluss — er ist nicht die Grundlage dafür.

**Konsequenz für miTch:**
- Unsere EU-weiten Verifier-Patterns (`hospital-*-er-*`) sind *heute schon* rechtlich valide
- Das Argument gegenüber Stakeholdern ist stärker als gedacht:
  miTch implementiert geltendes Recht, nicht zukünftige Regulierung
- Cross-Border-Szenarien (NL → ES Krankenhaus) sind kein Edge Case, sondern Grundrecht

---

### Erkenntnis 2 — Primary Use vs. Secondary Use ist eine harte rechtliche Grenze

Die entscheidende Unterscheidung die miTch bisher **nicht modelliert**:

| Begriff | Definition | Beispiel | Consent-Logik |
|---------|-----------|---------|---------------|
| **Primary Use** | Direkte Patientenversorgung | Notaufnahme, Rezept, Arztbesuch | Biometrie + Consent (implementiert ✅) |
| **Secondary Use** | Wiederverwendung für andere Zwecke | Wissenschaft, Statistik, Politikbewertung | User-Widerspruch im Kontrollregister (fehlt ❌) |

**Konsequenz für miTch:**
Das nationale Kontrollregister (per EHDS) muss in miTchs PolicyManifest modellierbar sein.
Ein User muss sagen können: *"Notfallzugriff ja — Forschungszugriff nein."*
Das sind zwei verschiedene Regeln für dieselben Daten.

---

### Erkenntnis 3 — HDAB-Permit ist ein neuer Verifier-Typ

Forscher brauchen eine **HDAB-Genehmigung** (Health Data Access Body) bevor sie
auf Sekundärdaten zugreifen dürfen. Dieses Permit ist ein Credential — und miTch
kennt diesen Verifier-Typ noch nicht.

**Konsequenz für miTch:**
Ein Verifier der Forschungsdaten anfragt muss sein HDAB-Permit beweisen können,
bevor die Policy Engine überhaupt den Consent-Flow startet.

---

### Erkenntnis 4 — Geographischer Scope ist nicht optional

- **EU-intern:** Freier Datenfluss — kein Widerspruchsrecht des Users
- **Drittländer mit Adequacy Decision** (Japan, etc.): User-Opt-in erforderlich
- **Drittländer ohne Adequacy:** DENY by default

Dieses Konzept existiert in miTchs PolicyRule aktuell **nicht**.

---

### Erkenntnis 5 — Break-Glass ist rechtlich definiert, nicht nur technisch

Notfallzugriff ohne Consent ist rechtlich möglich — aber nur mit:
1. Sofortigem Audit-Alert an den Patienten
2. Nachträglicher Benachrichtigung
3. Begründungspflicht des Verifiers

Das EHDS_SPEC.md erwähnt "Break-Glass Event" — aber es ist **nicht implementiert**.

---

## 📋 Task Liste

> **Legende:**
> 🔴 Architektur-kritisch — ohne das ist EHDS-Compliance strukturell unvollständig
> 🟡 Compliance-wichtig — rechtlich relevant, technisch umsetzbar
> 🟢 Demo-Qualität — für Stakeholder-Präsentation wichtig
> ⬜ Nice-to-have — sinnvoll aber nicht blocking

---

### BLOCK A — Typ-System erweitern
*Alle Änderungen in `src/packages/shared-types/src/policy.ts`*

#### 🔴 T-A1 — `usagePurpose` zu `PolicyRule` hinzufügen

```typescript
export type UsagePurpose =
  | 'primaryCare'        // Direkte Behandlung — höchste Priorität
  | 'researchSecondary'  // Wissenschaft — User kann global widersprechen
  | 'policyAssessment'   // Behördliche Auswertung (Effektivitätsmessung)
  | 'statistics';        // Aggregiert, de-identifiziert

export interface PolicyRule {
  // ... bestehendes ...
  usagePurpose?: UsagePurpose;  // NEU
}
```

**Warum:** Ohne dieses Feld kann die Engine nicht zwischen Notfallzugriff
und Forschungsanfrage unterscheiden — obwohl beide dieselben Datenpunkte anfragen.

**Aufwand:** ~2h (Typ + Engine-Check + Test)
**Abhängig von:** nichts
**Blockt:** T-A2, T-C1

---

#### 🔴 T-A2 — Secondary-Use Widerspruch im PolicyManifest

Neue `globalSettings`-Option:

```typescript
export interface GlobalPolicySettings {
  // ... bestehendes ...
  denySecondaryUse?: boolean;        // NEU: globaler Widerspruch gegen Forschung
  denySecondaryUseCountries?: string[]; // NEU: ["JP", "US"] — Drittländer-Opt-out
}
```

Und in der DemoPolicy:

```typescript
globalSettings: {
  blockUnknownVerifiers: true,
  denySecondaryUse: false,           // User-Entscheidung (default: erlaubt)
  denySecondaryUseCountries: ['US'], // Beispiel: kein US-Datentransfer
}
```

**Engine-Logik:** Wenn `rule.usagePurpose === 'researchSecondary'`
und `globalSettings.denySecondaryUse === true` → sofortiges DENY,
unabhängig von Verifier-Match.

**Aufwand:** ~3h (Typ + Engine + PolicyEditor UI + Test)
**Abhängig von:** T-A1
**Blockt:** T-C1

---

#### 🔴 T-A3 — HDAB-Permit als `TrustedIssuer`-Typ

```typescript
export interface TrustedIssuer {
  did: string;
  name: string;
  credentialTypes: string[];
  validUntil?: string;
  issuerRole?: 'standard' | 'hdab' | 'emergency'; // NEU
}
```

Neue PolicyRule-Option:

```typescript
export interface PolicyRule {
  // ... bestehendes ...
  requiresHdabPermit?: boolean; // NEU: Verifier muss HDAB-Credential vorweisen
}
```

**Engine-Logik:** Wenn `requiresHdabPermit: true`, prüft die Engine ob der
Verifier ein gültiges HDAB-Issued Credential in seiner Presentation mitschickt.
Ohne Permit → DENY mit ReasonCode `HDAB_PERMIT_REQUIRED`.

**Aufwand:** ~4h (Typ + Engine + ReasonCode + Issuer-Mock HDAB-Endpoint + Test)
**Abhängig von:** T-A1
**Blockt:** T-C1

---

#### 🟡 T-A4 — `geoScope` in `PolicyRule`

```typescript
export type GeoScope =
  | 'eu-only'              // Nur EU-Verifier (default für Layer 2)
  | 'eu-plus-adequacy'     // EU + Adequacy-Länder (JP, KR, etc.)
  | 'global';              // Keine geo-Einschränkung

export interface PolicyRule {
  // ... bestehendes ...
  geoScope?: GeoScope;
}
```

**Engine-Logik:** Verifier-DID enthält Länder-Prefix (`did:jp:...`).
Engine prüft gegen `geoScope` — Nicht-EU-Verifier bei `eu-only` → DENY.

**Aufwand:** ~3h (Typ + DID-Parsing + Engine + Test)
**Abhängig von:** nichts
**Blockt:** nichts direkt, aber wichtig für Drittland-Demo

---

### BLOCK B — Engine & Compliance-Logik
*Änderungen in `src/packages/policy-engine/src/engine.ts`*

#### 🔴 T-B1 — Break-Glass Audit Alert implementieren

Das EHDS_SPEC.md definiert: Wenn `verifier_type === 'EMERGENCY_ER'`,
Zugriff *ohne* sofortigen Consent erlaubt — aber **mit** sofortigem Audit-Alert.

Aktueller Stand: `requiresPresence: true` blockiert ohne Consent. Korrekt für
Standard-Notaufnahme, aber falsch für echten Notfall (bewusstloser Patient).

Neue Engine-Logik:

```typescript
// Wenn Verifier als EMERGENCY markiert UND User nicht erreichbar:
if (rule.allowBreakGlass && !userIsAvailable) {
  verdict = 'ALLOW';
  reasonCodes.push(ReasonCode.BREAK_GLASS_ACTIVATED);
  // Audit-Alert sofort generieren
  await auditLog.recordBreakGlass({
    verifier: request.verifierId,
    claims: authorizedClaims,
    timestamp: Date.now(),
    notifyUser: true,  // Push-Notification an User
  });
}
```

**Aufwand:** ~5h (Engine + AuditLog-Erweiterung + Notification-Stub + Test)
**Abhängig von:** T-A1
**Risiko:** Muss sehr sorgfältig getestet werden — Break-Glass darf nicht als
Bypass missbraucht werden

---

#### 🟡 T-B2 — ePrescription Single-Use (Nullifier)

Laut EHDS_SPEC.md müssen Rezepte nach Einlösung "geburned" werden.
Aktuell: kein Double-Spend-Schutz.

Lösung ohne Blockchain:
- Verifier-Backend führt Nonce-Liste eingelöster Rezepte
- Wallet markiert Credential nach Presentation als `status: 'dispensed'`
- Engine prüft Credential-Status vor Freigabe

**Aufwand:** ~4h (Credential-Status-Feld + Engine-Check + Verifier-Backend-Endpoint)
**Abhängig von:** nichts
**Blockt:** nichts, aber wichtig für Pharmacy-Demo

---

#### 🟡 T-B3 — `HDAB_PERMIT_REQUIRED` ReasonCode

```typescript
// In engine.ts ReasonCode enum:
HDAB_PERMIT_REQUIRED = 'HDAB_PERMIT_REQUIRED',
SECONDARY_USE_DENIED = 'SECONDARY_USE_DENIED',
GEO_SCOPE_VIOLATION  = 'GEO_SCOPE_VIOLATION',
BREAK_GLASS_ACTIVATED = 'BREAK_GLASS_ACTIVATED',
```

Und im DenialResolver: menschenlesbare Erklärungen für alle 4 neuen Codes.

**Aufwand:** ~1h
**Abhängig von:** T-A1, T-A3, T-A4, T-B1

---

### BLOCK C — Demo-Szenarien
*Änderungen in `src/apps/wallet-pwa/src/`*

#### 🟢 T-C1 — Forschungsanfrage-Szenario in Demo

Neuer Button: **"Forschungsinstitut: Patientendaten"**

```typescript
const researchRequest: VerifierRequest = {
  verifierId: 'did:eu:research-institute-fhi',
  usagePurpose: 'researchSecondary',  // T-A1
  requirements: [{
    credentialType: 'PatientSummary',
    requestedClaims: ['bloodGroup', 'allergies'],
  }]
};
// → DENY wenn denySecondaryUse: true im Manifest
// → PROMPT + HDAB-Check wenn denySecondaryUse: false
```

**Demo-Aussage:** "Dieselben Daten, andere Nutzungsabsicht — miTch unterscheidet."

**Aufwand:** ~2h (Button + Request + Demo-Policy anpassen)
**Abhängig von:** T-A1, T-A2, T-A3

---

#### 🟢 T-C2 — Kontrollregister-UI im PolicyEditor

User kann im PolicyEditor einstellen:
- [ ] Forschungszugriff generell erlauben/sperren
- [ ] Nur EU-Forscher erlauben
- [ ] Drittland-Transfer (JP, US, etc.) erlauben/sperren

**Aufwand:** ~4h (PolicyEditor-Erweiterung + globalSettings-Bindings)
**Abhängig von:** T-A1, T-A2, T-A4

---

#### 🟢 T-C3 — Sprachlocale für Medizinbegriffe (EHDS_SPEC.md §3.3)

EHDS_SPEC.md Punkt 3.3 ist noch komplett offen:
> "The Wallet UI must render medical terms in the local language of the Verifier"

Einfachste Lösung für Demo: i18n-Map für die häufigsten Begriffe
(Penicillin-Allergie, Blutgruppe, etc.) mit DE/EN/ES/NL.

**Aufwand:** ~3h (i18n-Map + ConsentModal-Locale-Rendering)
**Abhängig von:** nichts

---

#### 🟢 T-C4 — Cross-Border-Szenario in Demo

Neuer Verifier: `did:es:hospital-barcelona-er-1`
→ matcht `hospital-*-er-*` Pattern
→ zeigt UI mit Hinweis "Spanisches Krankenhaus — EU-Datenfluss aktiv"

**Demo-Aussage:** "Cross-Border funktioniert heute schon — GDPR Art. 1."

**Aufwand:** ~1h (Verifier-Config + UI-Label)
**Abhängig von:** T-A4

---

### BLOCK D — Dokumentation
*Änderungen in `docs/`*

#### ⬜ T-D1 — EHDS Compliance Map

Dokument das zeigt: Welche EHDS-Anforderung ist durch welchen miTch-Mechanismus
erfüllt. Für Stakeholder und spätere Zertifizierung.

| EHDS Anforderung | Artikel | miTch-Mechanismus | Status |
|-----------------|---------|-------------------|--------|
| Patient Summary Austausch | Art. 5 | PatientSummary VC + SD-JWT | ✅ Implementiert |
| Primärnutzungs-Consent | Art. 8 | ConsentModal + WebAuthn | ✅ Implementiert |
| Sekundärnutzungs-Widerspruch | Art. 11 | PolicyManifest globalSettings | ❌ T-A2 |
| HDAB-Permit-Pflicht | Art. 46 | TrustedIssuer hdab-Rolle | ❌ T-A3 |
| Cross-Border-Freizügigkeit | GDPR Art. 1 | Verifier-Pattern EU-Wildcard | ✅ Implementiert |
| Notfallzugriff (Break-Glass) | Art. 8(5) | Engine Break-Glass-Logik | ❌ T-B1 |
| Geo-Scope Drittländer | GDPR Art. 46 | geoScope in PolicyRule | ❌ T-A4 |
| ePrescription Single-Use | Art. 14 | Nullifier / Status-Check | ❌ T-B2 |

**Aufwand:** ~2h (Dokument schreiben)
**Abhängig von:** nichts — jetzt schreibbar

---

## 🗓 Empfohlene Reihenfolge

```
Woche 1 (Typ-Fundament):
  T-A1 → T-A2 → T-A3  (usagePurpose + Secondary + HDAB)

Woche 2 (Engine + Demo):
  T-B1 → T-B3 → T-C1  (Break-Glass + ReasonCodes + Forschungs-Demo)

Woche 3 (UI + Polish):
  T-C2 → T-C3 → T-C4  (Kontrollregister + Locale + Cross-Border)

Parallel (immer):
  T-D1  (EHDS Compliance Map — wächst mit)
  T-A4  (geoScope — kann unabhängig eingefügt werden)
  T-B2  (ePrescription — isoliertes Feature)
```

---

## 🚦 Aktueller Status

| Task | Status | Prio |
|------|--------|------|
| T-A1 usagePurpose | ✅ `cc344a4` | 🔴 Kritisch |
| T-A2 Secondary-Use Widerspruch | ✅ `45691a1` | 🔴 Kritisch |
| T-A3 HDAB-Permit | ✅ `f69b11c` | 🔴 Kritisch |
| T-A4 geoScope | ✅ `e7b7ecb` | 🟡 Wichtig |
| T-B1 Break-Glass Alert | ❌ Offen | 🔴 Kritisch |
| T-B2 ePrescription Nullifier | ❌ Offen | 🟡 Wichtig |
| T-B3 ReasonCodes | ✅ `cc344a4` | 🟡 Wichtig |
| T-C1 Forschungs-Demo | ❌ Offen | 🟢 Demo |
| T-C2 Kontrollregister-UI | ❌ Offen | 🟢 Demo |
| T-C3 Sprachlocale | ❌ Offen | 🟢 Demo |
| T-C4 Cross-Border-Szenario | ❌ Offen | 🟢 Demo |
| T-D1 EHDS Compliance Map | ❌ Offen | ⬜ Nice-to-have |

---

## 💡 Der zentrale Gedanke hinter diesem Dokument

Der EHDS-Jurist-Artikel macht einen entscheidenden Punkt explizit:
**Primär- und Sekundärnutzung sind strukturell verschiedene Rechtsverhältnisse** —
nicht nur semantisch.

miTch kann beides in einem PolicyManifest abbilden, ohne eine zentrale Datenbank
zu brauchen. Der User definiert seine Grenze lokal. Das ist der Unterschied zu
jedem zentralen Kontrollregister.

Das ist das Argument für miTch — nicht die Kryptographie. Die ist Mittel zum Zweck.

---

*Letzte Aktualisierung: 2026-03-04 | Nächste Review: nach T-A1 Implementierung*
