# Spec 112 — Komponenten-Isolations-Modell

**Status:** STABLE
**Stand:** 2026-03-06
**Scope:** S-04 Security Hardening — Internal Privilege Escalation Defense
**Referenz:** BACKLOG S-04, docs/ARCHITECTURE_ZERO_TRUST.md

---

## Problem

Interne Angreifer (kompromittiertes NPM-Modul, modifizierter Bundle-Code) könnten versuchen, über Komponenten-Grenzen hinweg Daten abzugreifen oder Policy-Entscheidungen zu manipulieren — ohne dass der Nutzer davon erfährt.

**Angriffsvektor:** Internal Privilege Escalation
- Policy Engine gibt mehr frei als Policy erlaubt → Consent Store wird umgangen
- Audit Logger wird deaktiviert → kein Audit-Trail für Zugriffe
- Credential Store gibt Rohdaten raus → Policy-Entscheidung wird nie evaluiert

---

## Architektur-Prinzip: Strikte Komponentengrenzen

Jede Komponente hat eine **definierte API-Grenze**. Kein direkter Speicherzugriff, keine globalen Variablen, keine Bypass-Mechanismen.

```
┌─────────────────────────────────────────────────────────┐
│                     Wallet PWA (Shell)                  │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐  ┌─────────────┐ │
│  │ Policy Engine│ ─→ │Consent Store │  │ Audit Logger│ │
│  │              │    │              │  │             │ │
│  │ evaluate()   │    │ grant()      │  │ log()       │ │
│  │ ─────────────│    │ revoke()     │  │ export()    │ │
│  │ Returns only │    │ query()      │  │             │ │
│  │ Verdict +    │    │              │  │ Write-only  │ │
│  │ Capsule      │    │ No raw creds │  │ from Engine │ │
│  └──────────────┘    └──────────────┘  └─────────────┘ │
│          ↑                  ↑                  ↑        │
│          │                  │                  │        │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Secure Credential Store              │  │
│  │  (AES-256-GCM + Crypto-Shredding, IndexedDB)     │  │
│  │  Policy Engine reads METADATA only (no raw VC)   │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Komponentengrenzen

### 1. Policy Engine (`@mitch/policy-engine`)

**Input:**
- `VerifierRequest` — validiert durch Input Validation Schema (S-03) vor Übergabe
- `EvaluationContext` — Timestamp, UserDID, Interaction-Metadata
- `StoredCredentialMetadata[]` — NUR Metadaten (Typ, Issuer, Claims-Liste), KEINE Rohdaten
- `PolicyManifest` — validiert durch `validatePolicy()` (inkl. S-02 version check)

**Output:**
- `PolicyEvaluationResult` — Verdict (ALLOW/DENY/PROMPT) + ReasonCodes + DecisionCapsule
- **KEINE** Rohdaten aus Credentials
- **KEINE** direkten Schreibzugriffe auf Consent Store oder Audit Logger

**Isolation-Regeln:**
- Engine hat KEINEN Zugriff auf den Consent Store
- Engine hat KEINEN Zugriff auf den Raw-Credential-Store
- Engine schreibt KEINE Audit-Logs direkt — das ist Aufgabe der Shell
- Entscheidung ist deterministisch: gleicher Input → gleicher Output (G-03)
- DecisionCapsule ist kryptografisch signiert (wallet_attestation) — nicht tamperbar

**Trust Level:** LOW — Engine sieht nur Policy + Metadata, nie Rohdaten

---

### 2. Consent Store (`@mitch/secure-storage`)

**Input:**
- Explizite Nutzer-Aktionen (UI-Buttons) — keine programmatischen Freigaben
- `grant(verifierId, claimSet, expiresAt)` — immer zeitlich begrenzt
- `revoke(consentId)` — sofortige Wirkung, kein "Soft Delete"

**Output:**
- `ConsentRecord` — welche Claims für welchen Verifier bis wann freigegeben sind
- Wird von Shell abgefragt, NICHT von Policy Engine direkt

**Isolation-Regeln:**
- Consent Store hat KEINEN Zugriff auf Policy Engine
- Consent Store speichert KEINE Credential-Rohdaten
- Jede Änderung erzeugt einen Audit-Event (Schreib-Event an Audit Logger)
- Crypto-Shredding: Widerruf löscht den Consent-Schlüssel → Daten werden vergessen

**Trust Level:** MEDIUM — hält Nutzer-Entscheidungen, kein Policy-Wissen

---

### 3. Audit Logger (`@mitch/audit-log`)

**Input:**
- Write-only API: `log(event: AuditEvent)` — keine Löschfunktion
- Aufgerufen NUR durch Shell, NICHT direkt von Engine oder Consent Store

**Output:**
- Lokaler Audit Trail (IndexedDB) — nie zentral übertragen
- Export nur auf explizite Nutzeranfrage (Art. 15 DSGVO)

**Isolation-Regeln:**
- Audit Logger ist **append-only** — keine Lösch- oder Änderungs-API
- Logger hat KEINEN Zugriff auf Policy Engine oder Consent Store
- Logger kennt keine Credential-Inhalte — nur Metadaten (VerifierId, Verdict, Timestamp)
- Separate Verschlüsselung vom Credential Store (eigener Schlüssel)

**Trust Level:** HIGH — passiver Empfänger, minimale Angriffsfläche

---

### 4. Secure Credential Store (`@mitch/secure-storage`, Credential-Partition)

**Input:**
- `store(encryptedVC, metadata)` — vom Issuer-Flow (OID4VCI)
- `retrieve(credentialId)` — NUR von Shell nach expliziter Policy-Entscheidung (ALLOW)

**Output:**
- **An Policy Engine:** NUR `StoredCredentialMetadata[]` (keine Rohdaten!)
- **An Presentation Layer:** Rohdaten NUR nach ALLOW-Verdict + Consent (entschlüsselt)

**Isolation-Regeln:**
- Policy Engine bekommt NIEMALS Rohdaten
- Entschlüsselung passiert NACH Policy-Entscheidung, nicht vorher
- Crypto-Shredding: Key deletion = Data deletion (kein GDPR "Vergessen"-Problem)
- JWE-Verschlüsselung at rest (AES-256-GCM, G-08)

**Trust Level:** CRITICAL — enthält PII, strengste Isolation

---

## Datenfluss-Invarianten

Diese Invarianten MÜSSEN zu jedem Zeitpunkt gelten:

| # | Invariante |
|---|---|
| I-1 | Rohdaten fließen NIEMALS zur Policy Engine |
| I-2 | Policy Engine schreibt NIEMALS direkt in Consent Store oder Audit Logger |
| I-3 | Audit Logger ist append-only — keine Delete-API |
| I-4 | Consent Store hat KEINE Policy-Logik — er speichert nur Entscheidungen |
| I-5 | Jede ALLOW-Entscheidung produziert einen signierten DecisionCapsule |
| I-6 | Jede Datenfreigabe erscheint im Audit Trail (lokal) |
| I-7 | Kein Modul kann seine eigene Ausgabe als Input für sich selbst verwenden |

---

## Sicherheitskonsequenzen

### Privilege Escalation Prevention
- Engine kann DENY nicht zu ALLOW umschreiben (Capsule ist signiert)
- Capsule enthält Nonce + Expiry (5 Minuten) — kein Replay möglich
- Pairwise DID in Capsule — kein Nutzer-Fingerprint aus Capsule ableitbar (U-05)

### Verifier Fingerprint Check (S-01)
- Engine prüft Fingerprint VOR Policy-Evaluation
- Mismatch → PROMPT (niemals auto-ALLOW) — User muss aktiv bestätigen

### Manifest Rollback Protection (S-02)
- Shell prüft `manifest_version` vor Übergabe an Engine
- Älteres Manifest → Rejection (kein Silent Downgrade)

### Input Validation (S-03)
- Alle Claim-Namen werden normalisiert + whitelist-validiert VOR Übergabe an Engine
- Injection via Claim-Namen ist nicht möglich

---

## Grenzdefinitionen im Code

| Grenze | Durchgesetzt durch |
|---|---|
| Engine liest nur Metadaten | `StoredCredentialMetadata[]` Interface (kein `rawVC` Feld) |
| Engine schreibt kein Audit | Shell-Orchestration — Engine gibt Result zurück, Shell loggt |
| Consent Store hat keine Policy | Separate Packages: `secure-storage` vs `policy-engine` |
| Capsule ist tamper-evident | `CapsuleSigner` + `wallet_attestation` |
| Input normalisiert vor Eval | `sanitizeRequestedClaims()` in Shell VOR `engine.evaluate()` |

---

## Empfohlene Implementierung in der Shell

```typescript
// Korrekte Reihenfolge in WalletService.processVerifierRequest():

// 1. Input-Validierung (S-03)
const claims = sanitizeRequestedClaims(request.requestedClaims);
const validatedRequest = { ...request, requestedClaims: claims };

// 2. Manifest-Rollback-Schutz (S-02)
const rollback = checkManifestRollback(manifest, store.getTrustedManifestVersion());
if (!rollback.ok) throw new Error(rollback.reason);

// 3. Policy Engine: NUR Metadaten übergeben
const metadata = await credentialStore.getMetadataOnly(); // kein rawVC!
const result = await policyEngine.evaluate(validatedRequest, ctx, metadata, manifest);

// 4. Audit (immer, auch bei DENY)
auditLogger.log({ verdict: result.verdict, verifierId: request.verifierId, ... });

// 5. Rohdaten NUR bei ALLOW + Consent
if (result.verdict === 'ALLOW') {
  const raw = await credentialStore.retrieve(result.selectedCredentials);
  return buildPresentation(raw, result.decisionCapsule);
}
```

---

## Verwandte Spezifikationen

- Spec 111: Pairwise-Ephemeral DIDs (U-01–U-05)
- docs/ARCHITECTURE_ZERO_TRUST.md (S-05)
- docs/specs/05_Threat_Model.md
- docs/specs/04_Data_Flows_and_PII_Boundaries.md
