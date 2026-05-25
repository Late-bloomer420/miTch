# miTch Gesamtanalyse-Prozess v2 - 2026-05-24

Status: Arbeitsstandard fuer Architekturpruefungen
Scope: Repo-Zustand, Dokumentation, ADRs, Code-Architektur, Privacy-Firewall-Axiome, offene Entscheidungen
Wichtig: Dieses Dokument ist kein ADR. Es beschreibt, wie die Architektur ab jetzt geprueft und zusammengefasst wird.

## 1. Zweck

Dieser Prozess verhindert, dass miTch erneut in parallele Wahrheiten auseinanderlaeuft. Jede Analyse muss drei Dinge sauber trennen:

1. Was ist dokumentiert?
2. Was ist im Code wirklich vorhanden?
3. Was ist nach den Privacy-Firewall-Axiomen akzeptabel, unklar oder falsch?

Die Leitregel ist:

```text
UNKNOWN => FAIL
```

Wenn eine Aussage nicht durch Code, Tests, Specs oder ADRs belegbar ist, wird sie nicht als "wahrscheinlich richtig" behandelt. Sie wird als offene Pruefung markiert.

## 2. Aktuell verifizierter Repo-Zustand

Stand der Pruefung: 2026-05-24.

### Git-Zustand

- Aktiver Branch: `master`
- Lokaler Branch ist 2 Commits vor `origin/master`
- Lokaler HEAD: `eb6d212 fix(wallet-pwa): avoid Vite config-bundle ENOENT on Windows`
- `origin/master`: `ae91f48 feat(wallet): paginate consent receipts`
- Working Tree ist nicht sauber.

Aktuell uncommitted geaendert:

- `CLAUDE.md`
- `docs/03-architecture/decisions/DECISION_004_Consent_UX.md`
- `src/apps/wallet-pwa/src/App.test.tsx`
- `src/apps/wallet-pwa/src/App.tsx`
- `src/apps/wallet-pwa/src/components/ConsentManagerPanel.tsx`
- `src/apps/wallet-pwa/src/consent-manager/__tests__/receipt-store.test.ts`
- `src/apps/wallet-pwa/src/consent-manager/model.ts`
- `src/apps/wallet-pwa/src/consent-manager/receipt-store.ts`
- `src/packages/oid4vp/src/__tests__/e2e-flow.test.ts`
- `src/packages/oid4vp/src/demo-flow.ts`
- `src/packages/oid4vp/tsconfig.json`
- `src/packages/oid4vp/vitest.config.ts`

Aktuell untracked:

- `TASKS.md`
- `dashboard.html`
- `docs/compliance/CONSENT_RECEIPT_EXPORT.md`
- `memory/`
- `src/apps/wallet-pwa/src/components/__tests__/`
- `src/apps/wallet-pwa/src/consent-manager/types.ts`
- `src/packages/oid4vp/src/shared-crypto.d.ts`

Bewertung:

- Das ist kein sicherer Ausgangspunkt fuer Architekturentscheidungen.
- Vor einem ADR oder Refactoring muessen diese Aenderungen in logische Changesets getrennt werden.
- Jede Analyse muss den Dirty-Tree-Zustand explizit nennen.

### Workspace-Zustand

`pnpm -r list --depth -1` und package.json-Scan zeigen:

- 27 Package-Workspaces unter `src/packages/`
- 5 App-bezogene Workspaces unter `src/apps/`
- Fachlich weiterhin 3 Apps:
  - `wallet-pwa`
  - `issuer-mock`
  - `verifier-demo`
- `verifier-demo` besteht workspace-technisch aus root, backend und frontend.

Das erklaert die Zahlenabweichung in der Doku:

- Manche Dokus sagen 26 Packages.
- Der aktuelle Code hat 27 Package-Workspaces, weil `@mitch/data-flow` vorhanden ist.
- Manche Dokus sagen 3 Apps, was fachlich stimmt, aber workspace-technisch unvollstaendig ist.

## 3. Aktuell relevante Wahrheitsquellen

### Dokumenten-Canon

Primaere Doku-Navigation:

- `docs/DOCS_CANON.md`
- `docs/README.md`
- `STATE.md`
- `docs/BACKLOG.md`
- `docs/specs/SPECS_STATUS_INDEX.md`

Wichtige operative Quellen:

- `docs/ops/EVIDENCE_PACK_P0.md`
- `docs/pilot/PILOT_DRY_RUN_01.md`
- `docs/pilot/PILOT_DRY_RUN_01_FINDINGS.md`
- `docs/pilot/FINDINGS_BACKLOG.md`
- `docs/protocol/CAP_NEGOTIATION_V1.md`
- `docs/ops/METADATA_BUDGET_V1.md`
- `docs/ops/RUNBOOKS_V1.md`

Wichtige Architekturquellen:

- `docs/REFACTORING_ROADMAP.md`
- `REFACTORING_ROADMAP.md`
- `docs/ARCHITECTURE_ZERO_TRUST.md`
- `docs/specs/112_Component_Isolation_Model.md`
- `docs/specs/02_Principles_and_NonNegotiables.md`
- `src/packages/shared-types/specs/decision_capsule.md`

### ADR-Sammlungen

Es gibt drei Sammlungen:

| Ort                               | Zweck                             | Zustand                                      |
| --------------------------------- | --------------------------------- | -------------------------------------------- |
| `docs/03-architecture/decisions/` | Fruehe Phase-0 Decision Notes     | Accepted, aber historisch                    |
| `docs/03-architecture/mvp/`       | Formale Architekturstrategie-ADRs | ADR-001 bis ADR-003 Accepted, viele Proposed |
| `docs/compliance/ADR/`            | Compliance-/Implementierungs-ADRs | Accepted, eigene Nummerierung                |

Problem:

- ADR-001 bis ADR-009 existieren mehrfach mit unterschiedlichen Themen.
- Die Kollision ist dokumentiert, aber operativ riskant.
- Neue Entscheidungen duerfen nicht mehr nur in `DECISION_*.md` landen.

Regel ab diesem Prozess:

- `DECISION_*.md` ist historische Quelle, nicht mehr Ziel fuer neue bindende Entscheidungen.
- Neue bindende Architekturentscheidungen gehoeren in eine formale ADR.
- Wenn alte Nummern weiter genutzt werden, muss der Scope im Titel eindeutig sein.
- Besser: neue Prefixes einfuehren:
  - `ARCH-ADR-XXX`
  - `COMP-ADR-XXX`

## 4. Privacy-Firewall-Axiome als Pruefmatrix

Die extern gelesenen Skill-Dokumente liefern die haertesten Pruefkriterien.

### Axiome

| Axiom            | Architekturregel                                                                                     |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| Non-Existence    | Daten, die nicht existieren, koennen nicht leaken. Wenn ZKP moeglich ist, muss ZKP bevorzugt werden. |
| User Sovereignty | Private Keys bleiben auf dem User-Geraet. Keine zentralen Profile.                                   |
| Fail-Closed      | UNKNOWN stoppt den Flow. Implizites Allow ist verboten.                                              |
| Explicit Intent  | Keine breiten Scopes. "Bessere UX" ist keine Rechtsgrundlage fuer Datensammlung.                     |

### Reason Codes fuer Architekturpruefungen

| Code                        | Wann anwenden                                                   |
| --------------------------- | --------------------------------------------------------------- |
| `FAIL_LOG_RAW_PII`          | Raw PII wird geloggt oder in Audit/Receipt unsauber persistiert |
| `FAIL_STORE_RAW_PII`        | Raw PII wird ohne klare Verschluesselung/Retention gespeichert  |
| `FAIL_NON_EPHEMERAL`        | Daten/Keys leben laenger als fachlich noetig                    |
| `FAIL_LINKABILITY_REUSE`    | Stable Identifier werden ueber Kontexte wiederverwendet         |
| `FAIL_LINKABILITY_NO_NONCE` | Proof/Request ohne Nonce oder Anti-Replay-Kontext               |
| `FAIL_SEC_IMPLICIT_ALLOW`   | Ein Flow erlaubt Zugriff ohne explizite Policy-/Capsule-Evidenz |
| `FAIL_SEC_UNHANDLED_ERROR`  | Fehlerpfad kann zu unklarem Zustand oder Allow fuehren          |
| `FAIL_POLICY_MISMATCH`      | Code und Policy/ADR widersprechen sich                          |
| `FAIL_AUTHORITY_UNKNOWN`    | Issuer/Verifier/Policy-Quelle ist nicht belegbar                |
| `FAIL_INPUT_MISSING`        | Pflichtdaten fuer sichere Bewertung fehlen                      |
| `FAIL_SPEC_AMBIGUOUS`       | Spec/ADR ist mehrdeutig oder nicht entscheidungsfaehig          |

Analyse-Regel:

- `PASS`: durch Code/Test/Doku belegt.
- `FAIL`: Verletzung belegt.
- `UNKNOWN`: nicht belegbar oder widerspruechlich. Wird wie FAIL behandelt, bis geklaert.

## 5. Was bereits dokumentiert ist

### Architekturprinzipien

Dokumentiert in `docs/specs/02_Principles_and_NonNegotiables.md`:

- Edge-first decisions
- Ephemerality by default
- Data minimization by construction
- User as root of trust
- Fail-closed logic
- Keine zentralisierte Identitaetsspeicherung
- Keine Verhaltensprofile oder Cross-Service-Korrelation
- Proofs und Decisions loggen, keine Identity Records

Bewertung: Aktiv und bindend.

### Komponenten-Isolation

Dokumentiert in `docs/specs/112_Component_Isolation_Model.md`:

- Policy Engine bekommt nur `StoredCredentialMetadata[]`, keine Rohdaten.
- Policy Engine schreibt nicht direkt in Consent Store oder Audit Logger.
- Audit Logger ist append-only.
- Consent Store hat keine Policy-Logik.
- Jede ALLOW-Entscheidung produziert einen signierten DecisionCapsule.
- Jede Datenfreigabe erscheint im lokalen Audit Trail.

Bewertung: Gute Zielarchitektur. Gegen den aktuellen `WalletService` muss geprueft werden, ob die Grenzen real getrennt sind oder nur in einer Shell-Datei orchestriert werden.

### DecisionCapsule

Dokumentiert in `src/packages/shared-types/specs/decision_capsule.md`:

- DecisionCapsule ist der autoritative Output der Policy Engine.
- Muss `request_hash` enthalten.
- Muss `policy_hash` enthalten.
- `policy_hash` soll SHA-256 des aktiven `PolicyManifest` sein.
- Capsule darf keine Roh-PII-Werte enthalten.
- VP-Generation darf nur Claims enthalten, die in der Capsule erlaubt sind.

Bewertung: Normative DRAFT, aber inhaltlich zentral.

Aktueller Codebefund:

- `src/packages/shared-types/src/policy.ts` sagt ebenfalls: `policy_hash` ist SHA-256 des PolicyManifest.
- `src/packages/policy-engine/src/engine.ts` berechnet `policyHash` aktuell aus `canonicalStringify(matchedRule)`.
- Das ist mindestens `FAIL_POLICY_MISMATCH` oder `UNKNOWN => FAIL`, bis entschieden ist, ob es `policy_hash` oder `rule_hash` sein soll.

### Refactoring

Dokumentiert in:

- `docs/REFACTORING_ROADMAP.md`
- `REFACTORING_ROADMAP.md`

Bereits dokumentierte Baustellen:

- WalletService Decomposition
- SecureStorage Adapter + Crypto Boundary
- Claim-Level Encryption
- Key Rotation
- Verifier Binding Phase 2 via DNS-DID / `.well-known`
- TEE / Non-extractable key migration

Bewertung:

- Die Roadmaps sind inhaltlich richtig, aber Zahlen sind veraltet.
- Root `REFACTORING_ROADMAP.md` nennt `WalletService.ts` mit 1081 LOC.
- Aktueller Codebefund: `WalletService.ts` hat 1395 Zeilen.
- `docs/REFACTORING_ROADMAP.md` spricht sogar noch von ca. 700 LOC.

### Consent Manager / Consent Receipts

Dokumentiert oder vorhanden in:

- `docs/03-architecture/decisions/DECISION_004_Consent_UX.md`
- `docs/03-architecture/mvp/ADR-004_Consent_UX_Strategy.md`
- `docs/tasks/SPRINT_02_CONSENT_MANAGER_DATA_VISUALIZATION.md`
- `docs/compliance/CONSENT_RECEIPT_EXPORT.md` (untracked)
- `src/apps/wallet-pwa/src/consent-manager/types.ts` (untracked)
- `src/apps/wallet-pwa/src/consent-manager/receipt-store.ts`
- `src/packages/oid4vp/src/demo-flow.ts`

Aktueller Codebefund:

- Es gibt `ConsentReceipt` in Wallet-PWA.
- Es gibt `ConsentReceipt` auch in OID4VP Demo Flow.
- Receipt Export hat `receiptSetHash` und `exportHash`.
- Export ist laut Doku metadata-only.
- Export ist noch nicht signiert.
- Scope ist aktuell OID4VP W-05.

Bewertung:

- Das Feature ist real vorhanden.
- Das kanonische Modell ist noch nicht sauber entschieden.
- `ConsentReceiptV1` sollte nach `shared-types` oder in ein klares Domain-Package.
- Solange das nicht entschieden ist: `FAIL_SPEC_AMBIGUOUS`.

## 6. Was im Code wirklich vorhanden ist

### Kernpakete

Vorhanden:

- `@mitch/shared-types`
- `@mitch/shared-crypto`
- `@mitch/policy-engine`
- `@mitch/predicates`
- `@mitch/secure-storage`
- `@mitch/secure-memory`
- `@mitch/audit-log`
- `@mitch/revocation-statuslist`
- `@mitch/webauthn-verifier`
- `@mitch/mdoc`
- `@mitch/oid4vp`
- `@mitch/oid4vci`
- `@mitch/oid4vp-verifier`
- `@mitch/verifier-sdk`
- `@mitch/verifier-browser`
- `@mitch/data-flow`
- weitere Demo-/Integration-/Security-Pakete

### Wichtige aktuelle Groessen

| Datei                                                      | Zeilen |
| ---------------------------------------------------------- | -----: |
| `src/apps/wallet-pwa/src/services/WalletService.ts`        |   1395 |
| `src/packages/policy-engine/src/engine.ts`                 |    760 |
| `src/packages/secure-storage/src/index.ts`                 |    305 |
| `src/packages/shared-types/src/policy.ts`                  |    372 |
| `src/apps/wallet-pwa/src/consent-manager/receipt-store.ts` |    158 |
| `src/packages/oid4vp/src/demo-flow.ts`                     |    447 |

### Policy Engine

Vorhanden:

- `PolicyEngine.evaluate()`
- Fail-closed Pfade fuer unknown verifier / no matching rule
- Rate limiting / risk prompt
- Fingerprint mismatch -> PROMPT, nicht auto-ALLOW
- DecisionCapsule-Erzeugung
- `allow-assertion.ts`
- `conflict-resolver.ts`
- Deny reason codes

Risiken:

- `policy_hash` Semantik widerspricht Spec.
- Pairwise DID Fehler wird geloggt und Flow laeuft weiter.
- Ephemeral Response Key Export passiert in der Policy Engine.
- Das ist fuer reine Policy-Schicht zu viel Transport-/Presentation-Verantwortung.

### WalletService

Vorhanden:

- Master-Key Ableitung
- SecureStorage Init
- AuditLog Init
- Identity Key Generation
- PolicyEngine Init
- Demo Credential Seeding
- Policy Persistence/Merge
- Request Evaluation
- Presentation Generation
- mdoc Path
- Predicate Proof Path
- VP Signing
- Transport Encryption
- Audit Events
- Identity-Firewall Events
- Recovery Actions

Bewertung:

- Funktional stark fuer Pilot/Demo.
- Architektonisch groesster Knoten.
- Gegen Spec 112 ist zu pruefen, ob Komponenten wirklich getrennt sind oder nur methodisch in einer Datei leben.

### SecureStorage

Vorhanden:

- IndexedDB Storage
- AES-GCM via `@mitch/shared-crypto`
- Plaintext IndexTags
- `save`, `load`, `loadSelectiveClaims`, `delete`, metadata functions

Risiken:

- `loadSelectiveClaims()` decryptet den vollen Blob und filtert danach.
- Echte Per-Claim Encryption ist nicht vorhanden.
- Storage, Serialization und Crypto sind gekoppelt.
- Adapter Boundary ist geplant, aber nicht implementiert.

### Consent Receipt Export

Vorhanden:

- `ConsentReceipt` mit `schemaVersion`, `id`, `verifier`, `purpose`, `claimsShared`, `timestamp`, `outcome`, `decisionId`
- `buildConsentReceiptExport()`
- `receiptSetHash`
- `exportHash`
- Tests in neuem untracked Testordner

Risiken:

- Untracked/dirty Zustand.
- Nicht signiert.
- Modell dupliziert zwischen Wallet-PWA und OID4VP Demo Flow.
- Retention-Entscheidung ist noch nicht als formale ADR accepted.

### Protocol-Typen

Vorhanden:

- `src/packages/oid4vp/src/shared-crypto.d.ts` als untracked Module Augmentation fuer `@mitch/shared-crypto`

Bewertung:

- Das ist ein Hinweis auf fehlende kanonische Exports in `shared-crypto` oder `shared-types`.
- Dauerhaft sollte OID4VP nicht eigene Typen fuer ein anderes Workspace-Package nachdeklarieren.

## 7. Gesamtbefund

miTch ist nicht architektonisch verloren. Es gibt eine starke, konsistente Zielarchitektur:

- Edge-first
- Fail-closed
- Proofs statt Values
- User-only custody
- DecisionCapsule als Policy-Artefakt
- Secure local storage
- Auditability without exposure
- Pairwise DID / Unlinkability
- OID4VP/OID4VCI/mdoc-Kompatibilitaet

Das Problem ist Drift:

1. Dokumentationsdrift: Zahlen, Status und ADR-Orte widersprechen sich.
2. Entscheidungsdrift: DECISION, ADR, Backlog, Sprint-Doku und untracked Dateien enthalten parallele Aussagen.
3. Code-Kopplung: WalletService traegt zu viele Verantwortlichkeiten.
4. Contract-Drift: `policy_hash` meint laut Spec Manifest, laut Code aber matched Rule.
5. Consent-Drift: ConsentReceipt existiert in mehreren Schichten ohne kanonisches Modell.
6. Boundary-Drift: Protocol-Package deklariert fehlende Shared-Crypto-Typen lokal nach.

Nach Privacy-Firewall-Regeln ist das nicht "okay, weil Demo funktioniert", sondern:

- `FAIL_SPEC_AMBIGUOUS` fuer ADR-/Consent-Unklarheit
- `FAIL_POLICY_MISMATCH` fuer `policy_hash`
- `FAIL_SEC_IMPLICIT_ALLOW` als Pruefrisiko bei jeder ALLOW-/PROMPT-Capsule
- `FAIL_LINKABILITY_REUSE` als Pruefrisiko, wenn Pairwise DID optional bleibt
- `FAIL_STORE_RAW_PII` als Pruefrisiko fuer Receipt/Audit/Storage Retention

## 8. Neuer Gesamtanalyse-Prozess

Jede zukuenftige Architekturpruefung laeuft in dieser Reihenfolge.

### Schritt 0: Arbeitsbaum einfrieren

Kommandos:

```bash
git status --short --branch
git branch --all --verbose --no-abbrev
git diff --stat
```

Ergebnis dokumentieren:

- Branch
- ahead/behind
- modified files
- untracked files
- ob die Analyse auf dirty tree basiert

Regel:

- Keine Architekturentscheidung ohne Hinweis auf den Git-Zustand.
- Dirty tree bedeutet: Ergebnisse sind Arbeitsbefund, nicht Release-Befund.

### Schritt 1: Canon laden

Immer lesen:

- `docs/DOCS_CANON.md`
- `docs/README.md`
- `STATE.md`
- `docs/BACKLOG.md`
- `docs/specs/SPECS_STATUS_INDEX.md`

Ziel:

- Welche Dokumente behaupten Autoritaet?
- Welche Zahlen/Statusangaben sind veraltet?
- Welche Quellen widersprechen sich?

Output:

- "Dokumentiert" Tabelle
- "Verifiziert" Tabelle
- "Widerspruch" Tabelle

### Schritt 2: ADR-Lage klaeren

Immer lesen:

- `docs/03-architecture/decisions/README.md`
- `docs/03-architecture/mvp/README.md`
- `docs/compliance/ADR/README.md`

Pruefen:

- Ist die Entscheidung historisch, proposed oder accepted?
- Gibt es Nummernkollision?
- Gibt es Supersedes/Conflict?
- Ist der Codepfad genannt?

Regel:

- DECISION-Dateien sind historische Inputs.
- Neue bindende Entscheidungen brauchen ADR.
- Wenn ADR-Status Proposed ist, darf Implementation nicht als "architektonisch abgeschlossen" gelten.

### Schritt 3: Repo-Wirklichkeit verifizieren

Kommandos:

```bash
pnpm -r list --depth -1
rg --files -g "package.json" -g "pnpm-workspace.yaml" -g "turbo.json" -g "tsconfig*.json" -g "!node_modules"
rg -n "@mitch/" src/packages src/apps -g "*.ts" -g "*.tsx" -g "*.json" -g "!node_modules" -g "!dist"
```

Ziel:

- Workspaces zaehlen
- Package-Abhaengigkeiten sehen
- Apps vs Workspace-Projekte unterscheiden
- lokale Type-Workarounds finden

Output:

- Package-Liste
- App-Liste
- auffaellige Cross-Layer-Abhaengigkeiten

### Schritt 4: Kerninvarianten pruefen

Immer gegen diese Quellen halten:

- `docs/specs/02_Principles_and_NonNegotiables.md`
- `docs/specs/112_Component_Isolation_Model.md`
- `src/packages/shared-types/specs/decision_capsule.md`
- Skill-Axiome:
  - Non-Existence
  - User Sovereignty
  - Fail-Closed
  - Explicit Intent

Fragen:

- Sieht die Policy Engine Rohdaten?
- Gibt es eine ALLOW-Entscheidung ohne Rule/Evidenz/Hash?
- Gibt es Nonce, Expiry und Audience Binding?
- Werden Raw PII Werte geloggt oder exportiert?
- Gibt es stabile Identifier ueber Kontexte?
- Gibt es implizite Sessions/Cookies fuer Identity Assertions?
- Gibt es Zod/Validation fuer externe Inputs?

Output:

- Invariant Matrix mit `PASS`, `FAIL`, `UNKNOWN`.
- Jeder `UNKNOWN` bekommt Reason Code.

### Schritt 5: Code Hotspots pruefen

Immer pruefen:

- `src/packages/policy-engine/src/engine.ts`
- `src/packages/policy-engine/src/allow-assertion.ts`
- `src/packages/policy-engine/src/conflict-resolver.ts`
- `src/packages/shared-types/src/policy.ts`
- `src/packages/shared-types/specs/decision_capsule.md`
- `src/apps/wallet-pwa/src/services/WalletService.ts`
- `src/packages/secure-storage/src/index.ts`
- `src/packages/shared-crypto/src/index.ts`
- Consent-relevante Dateien, falls betroffen

Pruefpunkte:

- LOC und Verantwortlichkeiten
- Hash-Semantik
- Error Handling
- Fail-closed Verhalten
- Rohdaten-Grenzen
- Crypto-Key-Lebensdauer
- Audit/Receipt-Inhalte
- Presentation subset rule

### Schritt 6: Doku gegen Code mappen

Fuer jede Behauptung:

```text
Claim -> Dokument -> Codepfad -> Test/Evidence -> Status
```

Beispiel:

```text
Claim: policy_hash ist Hash des aktiven PolicyManifest
Dokument: shared-types/specs/decision_capsule.md
Codepfad: policy-engine/src/engine.ts
Evidence: Code hasht matchedRule
Status: FAIL_POLICY_MISMATCH
```

Regel:

- "Im Backlog als done" reicht nicht.
- "Im Code vorhanden" reicht nicht, wenn Doku etwas anderes fordert.
- "Test gruen" reicht nicht, wenn die falsche Semantik getestet wird.

### Schritt 7: Findings mit Severity und Reason Code schreiben

Format:

```text
ID:
Severity:
ReasonCode:
Claim:
Evidence:
Risk:
Required decision/fix:
Owner area:
```

Severity:

- P0: kann Privacy/Security-Invariante brechen oder ADR-Entscheidungen blockieren
- P1: Architekturdrift oder Produktionsreife-Blocker
- P2: Refactoring/Qualitaet/Portability

### Schritt 8: Sanierungsplan ableiten

Immer in diesen Ebenen:

1. Working tree / Branch Hygiene
2. ADR / Canon Governance
3. Contract Fixes
4. Code Boundary Refactoring
5. Tests / Evidence
6. Doku Cleanup

Regel:

- Erst Wahrheit stabilisieren, dann refactoren.
- Erst Contracts fixieren, dann Code verschieben.
- Keine grossen Refactors in dirty feature work mischen.

## 9. Konkrete offene Findings aus dieser Analyse

### Remediation Notes nach Handoff

- 2026-05-25: `F-ARCH-003` im Working Tree behoben. `policy-engine/src/engine.ts`
  berechnet `policy_hash` nun aus dem vollstaendigen `PolicyManifest`; der gematchte
  `PolicyRule` wird zusaetzlich als optionaler `rule_hash` gebunden.
- 2026-05-25: `F-ARCH-005` fuer die aktuelle Wallet/OID4VP-Receipt-Schicht teilweise
  behoben. `ConsentReceiptV1` und `ConsentReceiptExportV1` sind in
  `shared-types/src/consent.ts` kanonisch definiert; historische/v0-Receipt-Modelle
  muessen separat bewertet werden.
- 2026-05-25: `F-ARCH-008` im Working Tree behoben. Pairwise-DID-Erzeugungsfehler
  fuehren fuer ALLOW/PROMPT-Proof-Flows jetzt zu `DENY` mit
  `PAIRWISE_DID_FAILED`.

### F-ARCH-001: Dirty Tree als Architektur-Risiko

Severity: P0
ReasonCode: `FAIL_SPEC_AMBIGUOUS`
Evidence: `git status` zeigt mehrere modified und untracked Dateien.
Risk: Architekturentscheidungen koennen auf unstabilen Arbeitsdateien beruhen.
Required fix: Aenderungen in Changesets trennen.

### F-ARCH-002: ADR-Nummerkollision und Decision Drift

Severity: P0
ReasonCode: `FAIL_SPEC_AMBIGUOUS`
Evidence: Drei Sammlungen mit ADR-001 bis ADR-009; DECISION_004 wird weiter geaendert.
Risk: Entscheidungen sind nicht eindeutig referenzierbar.
Required fix: Neue ADR-Prefix-Regel oder klare Supersedes-Metadaten.

### F-ARCH-003: `policy_hash` Semantik widerspricht Spec

Severity: P0
ReasonCode: `FAIL_POLICY_MISMATCH`
Evidence: Spec fordert PolicyManifest-Hash; Code hasht `matchedRule`.
Risk: DecisionCapsule kann nicht eindeutig an aktives Manifest gebunden werden.
Required fix: `policy_hash` als Manifest-Hash implementieren und optional `rule_hash` einfuehren.

### F-ARCH-004: WalletService ist Produktionsreife-Blocker

Severity: P1
ReasonCode: `FAIL_SPEC_AMBIGUOUS`
Evidence: 1395 Zeilen, viele Verantwortlichkeiten; Roadmaps nennen Decomposition.
Risk: Komponenten-Isolation aus Spec 112 bleibt schwer beweisbar.
Required fix: Facade-Schnitt beibehalten, Services extrahieren.

### F-ARCH-005: ConsentReceipt ist nicht kanonisch

Severity: P1
ReasonCode: `FAIL_SPEC_AMBIGUOUS`
Evidence: Typen in Wallet-PWA und OID4VP Demo Flow; Export-Doku untracked.
Risk: Consent/Audit/Protocol-Semantik driftet.
Required fix: `ConsentReceiptV1` und `ConsentReceiptExportV1` kanonisch definieren.

### F-ARCH-006: ConsentReceipt Export ist nicht signiert

Severity: P1
ReasonCode: `FAIL_SEC_IMPLICIT_ALLOW`
Evidence: Doku sagt "not signed yet"; nur Hash-Anker vorhanden.
Risk: Export ist pruefbar, aber nicht nichtabstreitbar.
Required fix: Signing-Plan und ADR-Entscheidung.

### F-ARCH-007: Selective Claims sind noch keine Claim-Level Encryption

Severity: P1
ReasonCode: `FAIL_STORE_RAW_PII`
Evidence: `loadSelectiveClaims()` decryptet vollen Blob und filtert danach.
Risk: Structural Non-Existence ist intern nicht voll erreicht.
Required fix: Per-Claim Ciphertext Layout oder klare PoC-Markierung.

### F-ARCH-008: Pairwise DID Fehler ist soft

Severity: P1
ReasonCode: `FAIL_LINKABILITY_REUSE`
Evidence: Fehler bei Pairwise DID wird geloggt, Flow laeuft weiter.
Risk: Unlinkability kann optional werden, obwohl sie als Invariante verstanden wird.
Required fix: Entscheiden, ob Pairwise DID verpflichtend fuer ALLOW/PROMPT ist.

### F-ARCH-009: OID4VP Type Augmentation Workaround

Severity: P2
ReasonCode: `FAIL_SPEC_AMBIGUOUS`
Evidence: untracked `src/packages/oid4vp/src/shared-crypto.d.ts`.
Risk: Protocol Package kompensiert fehlende shared Exports lokal.
Required fix: Typen in `shared-crypto` oder `shared-types` kanonisch exportieren.

### F-ARCH-010: Dokumentierte Zahlen sind veraltet

Severity: P2
ReasonCode: `FAIL_SPEC_AMBIGUOUS`
Evidence: Doku nennt 26 Packages/700 oder 1081 LOC; Code zeigt 27 Packages/1395 LOC.
Risk: Reviews verlieren Vertrauen in Doku.
Required fix: Zahlen als "last verified" markieren oder automatisiert generieren.

## 10. Nichts-vergessen-Checkliste

Vor Abschluss jeder Architekturpruefung abhaken:

- [ ] Git-Zustand dokumentiert
- [ ] Dirty tree bewertet
- [ ] Package/App-Zahlen verifiziert
- [ ] DOCS_CANON gelesen
- [ ] STATE und BACKLOG gegeneinander geprueft
- [ ] ADR-Sammlungen geprueft
- [ ] Proposed vs Accepted getrennt
- [ ] Specs mit Codepfaden gemappt
- [ ] DecisionCapsule Semantik geprueft
- [ ] PolicyEngine fail-closed Pfade geprueft
- [ ] WalletService Verantwortlichkeiten gezaehlt
- [ ] SecureStorage Claim-Level-Realitaet geprueft
- [ ] ConsentReceipt Modell und Retention geprueft
- [ ] Audit/Receipt auf Raw PII geprueft
- [ ] Pairwise DID / Nonce / Expiry geprueft
- [ ] Protocol Type Boundaries geprueft
- [ ] Findings mit Reason Codes versehen
- [ ] Sanierungsplan nach P0/P1/P2 geschrieben
- [ ] Keine "wahrscheinlich okay" Aussagen im Ergebnis

## 11. Empfohlene naechste Arbeit

Reihenfolge:

1. Working tree sortieren und Changesets trennen.
2. `docs/DOCS_CANON.md` um diese Analyse-Regeln ergaenzen oder auf dieses Dokument verlinken.
3. Neue ADR fuer ConsentReceipt Retention/Export schreiben.
4. `policy_hash` vs `rule_hash` entscheiden und fixen.
5. `ConsentReceiptV1` kanonisieren.
6. `shared-crypto.d.ts` Workaround entfernen durch echte Exports.
7. WalletService mit niedrigem Risiko entlasten:
   - DemoSeedService
   - ConsentReceiptService
   - PresentationBuilder
   - CredentialRepository Port
8. SecureStorage Adapter Boundary vorbereiten.
9. Claim-Level Encryption als echte Production-Aufgabe separat planen.

## 12. Kurzfassung fuer Reviews

miTch hat eine tragfaehige Zielarchitektur, aber der aktuelle Stand muss als Drift-Zustand behandelt werden. Die wichtigsten harten Punkte sind:

- Dirty tree zuerst stabilisieren.
- ADR-/Decision-Governance reparieren.
- DecisionCapsule `policy_hash` Semantik korrigieren.
- ConsentReceipt kanonisieren.
- WalletService dekomponieren.
- SecureStorage ehrlich zwischen PoC-Minimierung und echter Claim-Level Encryption unterscheiden.

Nach Privacy-Firewall-Regeln gilt: Was nicht belegbar ist, ist nicht bestanden. Dieser Prozess ist deshalb bewusst streng.
