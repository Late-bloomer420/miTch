# Sprint 1: Identity Firewall MVP

Stand: 2026-05-20
Backlog-Bezug: U-20, U-21
Status: Complete — Abschlussreview bestanden 2026-06-07 (alle Merge-blockierenden Kriterien erfüllt, MVP auf `master`)

## Sprint-Ziel

miTch soll im Wallet-/Verifier-Kontext sichtbar machen, wenn Identifier-, Tracker-, Cookie- oder aehnliche Wiedererkennungszugriffe stattfinden. Der MVP soll solche Zugriffe erkennen, auditierbar loggen und in der Wallet/DataFlow-Oberflaeche verstaendlich anzeigen.

## Rollen

### 1. Product/Policy

Verantwortung:

- Definiert, welche Zugriffstypen im MVP als Identity-Firewall-Ereignis gelten.
- Legt fest, welche Informationen dem Nutzer angezeigt werden duerfen.
- Entscheidet, welche Ereignisse nur geloggt und welche zusaetzlich sichtbar hervorgehoben werden.

Liefergegenstaende:

- MVP-Scope fuer erkannte Zugriffstypen.
- Kurze Event-Klassifikation: Identifier, Cookie, Tracker, Storage, Fingerprinting-Hinweis.
- Akzeptanzkriterien fuer Nutzerverstaendlichkeit.

### 2. Engineer

Verantwortung:

- Entwirft das minimale Event-Modell fuer Identity-Firewall-Ereignisse.
- Bindet die Events an bestehende Audit-/DataFlow-Strukturen an.
- Implementiert Wallet-/UI-Anzeige fuer erkannte Ereignisse.
- Schreibt fokussierte Tests fuer Detection, Audit und Anzeige.

Liefergegenstaende:

- Implementierungsplan nach Review 2.
- Codeaenderungen in klar begrenzten Modulen.
- Unit-/Integrationstests.
- Kurze technische Notiz, wie Events erzeugt und konsumiert werden.

### 3. Reviewer/Security

Verantwortung:

- Prueft, ob die Detection keine Rohdaten oder unnoetige Identifier speichert.
- Prueft Fail-closed- und Datenschutzverhalten.
- Prueft, ob UI-Texte keine falschen Sicherheitsversprechen machen.
- Prueft Tests gegen Linkability- und Logging-Risiken.

Liefergegenstaende:

- Review 1: Scope-/Policy-Freigabe.
- Review 2: Implementierungsplan-Freigabe.
- Abschlussreview vor Merge.

## Struktur-Fund vom 2026-05-20

### Audit-Event-Modell

Gefundene Quellen:

- `src/packages/shared-types/src/audit.ts`
- `src/packages/audit-log/src/index.ts`
- `src/apps/wallet-pwa/src/services/WalletService.ts`

Aktueller Stand:

- `AuditEventType` ist ein enger Union-Type mit bestehenden Actions wie `KEY_CREATED`, `KEY_USED`, `KEY_DESTROYED`, `VP_GENERATED`, `VP_SENT`, `POLICY_EVALUATED`, `POLICY_BLOCKED`, `USER_CONSENT_GRANTED`, `USER_CONSENT_DENIED`, `VC_IMPORTED`, `VC_DELETED`.
- `AuditLogEntry` enthaelt `id`, `timestamp`, `action`, optional `subjectId`, optional `verifierId`, Hash-Chain-Felder, Signaturfelder und `metadata?: Record<string, unknown>`.
- `AuditLog.append(action, subjectId, metadata)` erzeugt Hash, optionale Signatur und fuegt das Event in die lokale Audit-Chain ein.
- Wallet-PWA nutzt `WalletService.auditLog.append(...)` bereits fuer Key-, Presentation-, Policy- und mdoc-Ereignisse.
- UI bekommt Auditdaten ueber `WalletService.getRecentAuditLogs(limit)` und reicht sie an `DataFlowPanel`.

Konsequenz fuer Sprint 1:

- Identity-Firewall braucht eine neue Audit-Action, statt Tracker-Events als generische `POLICY_EVALUATED`-Events zu verstecken.
- Alle Identity-Firewall-Events muessen `metadata.decision_id` tragen, sonst werden sie vom bestehenden DataFlow-Service ignoriert.
- Keine Roh-Identifier, keine vollstaendigen URLs, keine IPs, keine Cookie-Werte und keine User-Agent-Strings im Audit speichern.

### DataFlow-Transaction-Modell

Gefundene Quellen:

- `src/packages/data-flow/src/types.ts`
- `src/packages/data-flow/src/service.ts`
- `src/packages/data-flow/src/labels.ts`
- `src/apps/wallet-pwa/src/components/DataFlowPanel.tsx`

Aktueller Stand:

- `DataFlowService.buildTransactions(entries)` gruppiert Audit-Entries ausschliesslich nach `metadata.decision_id`.
- `DataFlowTransaction` enthaelt Transaktionszeit, Verifier, geteilte Claims, angefragte Claims, zurueckgehaltene Claims, bewiesene Claims, Credential-Typen, ZKP-Flag, Key-Lifecycle und Timeline-Events.
- `DataFlowEvent.category` ist aktuell begrenzt auf `key`, `credential`, `presentation`, `policy`, `consent`.
- `eventLabel()` mappt jede `AuditEventType` auf ein deutsches Timeline-Label plus Kategorie.
- `DataFlowPanel` zeigt pro Transaktion Verifier, Status, Claim-Tags, Summary und beim Aufklappen die Timeline.

Konsequenz fuer Sprint 1:

- DataFlow braucht eine neue Kategorie fuer Identity-Firewall-Events, empfohlen: `identity`.
- `DataFlowTransaction` sollte Identity-Firewall-Events explizit ausweisen, empfohlen: `identityAccesses: IdentityFirewallAccess[]` plus `identityAccessCount`.
- `DataFlowPanel` kann die Events im bestehenden Timeline-Bereich anzeigen und zusaetzlich einen kompakten Warn-/Info-Badge auf der Transaction Card rendern.

### Vorhandener Privacy-Audit-Hook

Gefundene Quellen:

- `src/apps/wallet-pwa/src/services/PrivacyAuditService.ts`
- `src/apps/wallet-pwa/src/components/PrivacyAuditModal.tsx`
- `src/apps/wallet-pwa/src/App.tsx`

Aktueller Stand:

- `PrivacyAuditService.auditTransaction(verifierName)` erzeugt aktuell mock-/heuristikbasierte `TrackingPoint[]` fuer OS, Browser und Netzwerk.
- `PrivacyAuditModal` zeigt diese Tracker vor Proof-Ausfuehrung an.
- `App.handlePrivacyAuditAccept(context)` speichert derzeit nur lokalen Consent-State, schreibt aber keine strukturierten Tracker-/Identity-Firewall-Events in die Audit-Chain.
- An dieser Stelle existiert mit `evaluationResult.decisionCapsule` bereits der noetige Kontext fuer `decision_id` und Verifier.

Konsequenz fuer Sprint 1:

- Der erste MVP kann den bestehenden Privacy-Audit-Hook nutzen, statt eine Browser-weite Extension oder einen Netzwerk-Proxy zu bauen.
- `handlePrivacyAuditAccept()` ist der beste Einstiegspunkt fuer Review 2, weil dort Tracker-Befunde, User-Acknowledgement und DecisionCapsule-Kontext zusammenlaufen.

## Review 1: Scope, Event-Modell, UI-Verhalten

Ziel: Vor der technischen Detailplanung entscheiden, was der MVP genau erkennen und anzeigen soll.

Zu klaeren:

- Welche Zugriffstypen gehoeren in den MVP?
- Welche Felder darf ein Identity-Firewall-Event enthalten?
- Wo wird das Ereignis im UI sichtbar?
- Was ist ausdruecklich nicht Teil des MVP?

Empfohlener MVP-Scope:

- Loggen von Zugriffen auf bekannte Identifier-Oberflaechen im Wallet-Kontext.
- Keine Speicherung von Roh-Identifiern.
- Anzeige im bestehenden DataFlow-/Wallet-Kontext.
- Keine Browser-weite Extension, kein Netzwerk-Proxy, kein vollstaendiges Anti-Fingerprinting.

Review-1-Ergebnis:

- Product/Policy bestaetigt Scope.
- Reviewer/Security bestaetigt, dass keine offensichtliche Datenschutzverletzung im Event-Modell steckt.
- Engineer darf den konkreten Implementierungsplan ausarbeiten.

## Review 1 Draft: Entscheidungen

### Empfohlener In-Scope-MVP

- Wallet-PWA only: Identity-Firewall-Ereignisse werden im bestehenden Wallet-/Proof-Flow sichtbar.
- Detection-Quelle fuer Sprint 1: vorhandene `PrivacyAuditService`-Befunde und explizite Wallet-observable Surfaces.
- Persistenz: nur PII-minimierte Audit-Events in der bestehenden Audit-Chain.
- Anzeige: bestehendes `DataFlowPanel`, plus Timeline-Event und kompakter Badge pro Transaktion.
- Verhalten: informieren und auditieren, nicht blockieren. Blocking bleibt spaeterer Sprint.

### Empfohlenes Audit-Event

Neue Action:

```typescript
IDENTITY_ACCESS_DETECTED
```

Empfohlene Metadata-Felder:

```typescript
{
  decision_id: string;
  verifier_did?: string;
  access_type: 'cookie' | 'storage' | 'browser_api' | 'network_metadata' | 'tracker_domain' | 'fingerprinting_signal';
  surface: 'document.cookie' | 'localStorage' | 'sessionStorage' | 'navigator.userAgent' | 'network' | 'unknown';
  actor_label: string;
  field_class: 'identifier' | 'tracking' | 'fingerprint' | 'metadata';
  persistence: 'session' | 'device' | 'cloud' | 'unknown';
  linkability: 'none' | 'session' | 'cross_session' | 'cross_context';
  severity: 'info' | 'warning' | 'critical';
  blocked: false;
  source: 'privacy_audit_service' | 'wallet_runtime';
}
```

PII-Regeln:

- `actor_label` darf nur menschenlesbare Kategorien/Namen enthalten, keine vollstaendigen URLs mit Pfad oder Query.
- Kein Cookie-Wert, keine IP-Adresse, kein raw User-Agent, keine Device-ID, kein Credential-ID-Rohwert.
- Falls spaeter Werte korreliert werden muessen, nur salted Hash mit expliziter Metadata-Budget-Freigabe.

### Empfohlenes DataFlow-Mapping

- `eventLabel('IDENTITY_ACCESS_DETECTED')` zeigt: `Identifier-Zugriff erkannt`.
- Neue `DataFlowEvent.category`: `identity`.
- Neue Transaction-Felder:
  - `identityAccesses: IdentityFirewallAccess[]`
  - `identityAccessCount: number`
- `summarizeTransaction()` darf nur faktenbasierte Aussagen erzeugen, z. B. `2 Identifier-Zugriffe sichtbar gemacht`.
- `DataFlowPanel` rendert Identity-Firewall-Ereignisse als Timeline-Zeilen und Card-Badge, nicht als Risiko-Score.

### Rollenentscheidung fuer Review 1

Product/Policy entscheidet:

- Sind die sechs vorgeschlagenen `access_type`-Werte ausreichend fuer den MVP?
- Soll `blocked` im MVP immer `false` sein?
- Sind Badge und Timeline als erste UI ausreichend?

Engineer prueft fuer Review 2:

- Exakte Typ-Erweiterungen in `shared-types` und `data-flow`.
- Mapping von `TrackingPoint` aus `PrivacyAuditService` auf `IDENTITY_ACCESS_DETECTED`.
- Methode in `WalletService`, um Identity-Firewall-Events auditierbar anzulegen.
- Tests in `data-flow`, `wallet-pwa` und `shared-types`.

Reviewer/Security prueft:

- Keine Roh-PII in Event-Metadata.
- Keine stabilen Cross-RP-Korrelatoren.
- Keine falsche Behauptung, dass Tracker blockiert wurden.
- Keine Erweiterung des MVP zu Browser-Extension, Proxy oder Risk-Scoring.

## Review 1 Entscheidung vom 2026-05-20

Review 1 wird mit folgenden Defaults als Sprint-Grundlage geschlossen. Diese Entscheidungen gelten fuer Review 2 und die spaetere Implementierung, bis sie ausdruecklich geaendert werden.

### Product/Policy

Entscheidungen:

- Die sechs `access_type`-Werte sind fuer den MVP ausreichend: `cookie`, `storage`, `browser_api`, `network_metadata`, `tracker_domain`, `fingerprinting_signal`.
- Der MVP ist informierend und auditierend. `blocked` ist in Sprint 1 immer `false`.
- Nutzeranzeige erfolgt ueber DataFlow Card-Badge plus Timeline-Eintrag.
- Es gibt keinen Risiko-Score und keine automatische rechtliche Bewertung.
- UI-Text darf nur sagen, dass ein Zugriff oder Signal sichtbar gemacht wurde, nicht dass es blockiert wurde.

Akzeptanzkriterien:

- Nutzer koennen in einer Transaktion erkennen, dass Identifier-/Tracking-Zugriffe sichtbar gemacht wurden.
- Die Anzeige bleibt knapp und ueberlaedt den bestehenden DataFlow nicht.
- Kein UI-Element behauptet, miTch blockiere OS-, Browser-, ISP- oder Verifier-Tracking im MVP.

### Engineer

Entscheidungen:

- Neue Audit-Action: `IDENTITY_ACCESS_DETECTED`.
- Neue DataFlow-Kategorie: `identity`.
- Neue DataFlow-Transaction-Felder: `identityAccesses` und `identityAccessCount`.
- Bestehender Einstiegspunkt fuer MVP-Events: `App.handlePrivacyAuditAccept(context)` ruft eine neue WalletService-Methode auf.
- Die WalletService-Methode schreibt pro relevantem `TrackingPoint` ein `IDENTITY_ACCESS_DETECTED`-Audit-Event mit `decision_id`.

Akzeptanzkriterien:

- Events ohne `decision_id` werden nicht erzeugt.
- Events koennen von `DataFlowService.buildTransactions()` in die richtige Transaktion gruppiert werden.
- Bestehende Key-/VP-/Consent-/Policy-Events bleiben unveraendert kompatibel.
- Implementierung bleibt auf Wallet-PWA, shared-types und data-flow begrenzt, sofern Review 2 keine zusaetzliche Notwendigkeit findet.

### Reviewer/Security

Entscheidungen:

- Rohwerte sind verboten: keine Cookie-Werte, IP-Adressen, raw User-Agent-Strings, Device-IDs, Credential-IDs, vollstaendigen URLs mit Pfad oder Query.
- `actor_label` ist nur ein grobes Label, z. B. `Unknown ISP`, `Google Chrome`, `Microsoft`, `Verifier Domain`.
- `verifier_did` darf als vorhandener Transaktionskontext mitgefuehrt werden, aber es duerfen keine zusaetzlichen stabilen Cross-RP-Korrelatoren entstehen.
- Spaetere Hashes fuer Identifier-Werte brauchen eine eigene Metadata-Budget-Entscheidung und sind nicht Teil dieses MVP.

Akzeptanzkriterien:

- Tests zeigen, dass Identity-Firewall-Metadata keine offensichtlichen Roh-Identifier enthaelt.
- Timeline und Summary sprechen von Sichtbarmachung/Auditierung, nicht Blocking.
- Der MVP kann fehlschlagen, ohne Proof-Erzeugung zu blockieren; Fail-closed gilt fuer Datenoffenlegung, nicht fuer die rein informative Tracker-Anzeige.

## Review 2: Implementierungsplan, Tests, Akzeptanzkriterien

Ziel: Der Engineer bekommt einen entscheidungskompletten Bauplan.

Zu klaeren:

- Welche bestehenden Audit-/DataFlow-Typen werden erweitert oder wiederverwendet?
- Wo werden Events erzeugt?
- Welche UI-Komponente zeigt die Events?
- Welche Tests sind Merge-blockierend?

Akzeptanzkriterien:

- Identity-Firewall-Events werden deterministisch erzeugt.
- Events enthalten keine Roh-PII und keine unnoetigen stabilen Identifier.
- Events erscheinen im Wallet-/DataFlow-Kontext.
- Tests decken mindestens Detection, Audit-Event und UI-Anzeige ab.
- Bestehende Tests bleiben gruen.

## Review 2 Draft: Technischer Bauplan

Dieser Bauplan ist die Vorlage fuer den zweiten Review. Nach Freigabe kann der Engineer bauen.

### 1. Shared Types

Ziel:

- Identity-Firewall-Events werden als eigener Audit-Event-Typ typisiert.
- Metadata-Struktur ist eng genug, um PII-Regeln testbar zu machen.

Geplante Aenderungen:

- In `src/packages/shared-types/src/audit.ts` `AuditEventType` um `IDENTITY_ACCESS_DETECTED` erweitern.
- In derselben Datei neue Typen ergaenzen:
  - `IdentityAccessType`
  - `IdentityAccessSurface`
  - `IdentityFieldClass`
  - `IdentityPersistence`
  - `IdentityLinkability`
  - `IdentitySeverity`
  - `IdentityFirewallMetadata`
- `IdentityFirewallMetadata.blocked` bleibt fuer Sprint 1 literal `false`.

Verbindliche Feldwerte:

```typescript
export type IdentityAccessType =
  | 'cookie'
  | 'storage'
  | 'browser_api'
  | 'network_metadata'
  | 'tracker_domain'
  | 'fingerprinting_signal';

export type IdentityAccessSurface =
  | 'document.cookie'
  | 'localStorage'
  | 'sessionStorage'
  | 'navigator.userAgent'
  | 'network'
  | 'unknown';

export interface IdentityFirewallMetadata {
  decision_id: string;
  verifier_did?: string;
  access_type: IdentityAccessType;
  surface: IdentityAccessSurface;
  actor_label: string;
  field_class: 'identifier' | 'tracking' | 'fingerprint' | 'metadata';
  persistence: 'session' | 'device' | 'cloud' | 'unknown';
  linkability: 'none' | 'session' | 'cross_session' | 'cross_context';
  severity: 'info' | 'warning' | 'critical';
  blocked: false;
  source: 'privacy_audit_service' | 'wallet_runtime';
}
```

### 2. Wallet Event-Erzeugung

Ziel:

- Der bestehende Privacy-Audit-Flow schreibt nach Nutzer-Acknowledgement strukturierte Audit-Events.

Geplante Aenderungen:

- In `WalletService` eine Methode ergaenzen:
  - `recordIdentityFirewallEvents(decisionId: string, verifierDid: string | undefined, trackers: TrackingPoint[]): Promise<void>`
- Die Methode mappt jeden relevanten `TrackingPoint` auf ein `IDENTITY_ACCESS_DETECTED`-Event.
- `App.handlePrivacyAuditAccept(context)` ruft diese Methode vor `proceedWithProof(...)` auf.
- Falls Event-Erzeugung fehlschlaegt, wird ein UI-Log mit Warning erzeugt; Proof-Erzeugung wird dadurch nicht blockiert.

Mapping-Regeln fuer `TrackingPoint`:

- `layer: 'BROWSER'` -> `access_type: 'browser_api'`, `surface: 'navigator.userAgent'`, `field_class: 'fingerprint'`
- `layer: 'NETWORK'` -> `access_type: 'network_metadata'`, `surface: 'network'`, `field_class: 'metadata'`
- `layer: 'OS'` -> `access_type: 'fingerprinting_signal'`, `surface: 'unknown'`, `field_class: 'fingerprint'`
- `layer: 'SDK' | 'SERVER'` -> `access_type: 'tracker_domain'`, `surface: 'unknown'`, `field_class: 'tracking'`
- `riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'` -> `severity: 'info' | 'warning' | 'critical'`
- `actor_label` wird aus `TrackingPoint.actor` uebernommen, aber vor dem Schreiben sanitisiert.

Sanitizing-Regeln:

- Maximal 80 Zeichen.
- Querystrings, URL-Pfade und Fragmente entfernen.
- Wenn ein Label wie eine URL aussieht, nur Hostname oder grobes Label speichern.
- Leere Labels werden zu `Unknown actor`.

### 3. DataFlow-Erweiterung

Ziel:

- Identity-Firewall-Events erscheinen in derselben Transaktion wie der Proof.

Geplante Aenderungen:

- In `src/packages/data-flow/src/types.ts` `DataFlowEvent.category` um `identity` erweitern.
- Neue `IdentityFirewallAccess`-Struktur in `data-flow` einfuehren oder aus `shared-types` ableiten.
- `DataFlowTransaction` um `identityAccesses` und `identityAccessCount` erweitern.
- `DataFlowService.buildTransactions()` sammelt `IDENTITY_ACCESS_DETECTED`-Events aus der jeweiligen `decision_id`-Gruppe.
- `eventLabel()` mappt `IDENTITY_ACCESS_DETECTED` auf `Identifier-Zugriff erkannt` mit Kategorie `identity`.
- `summarizeTransaction()` ergaenzt bei `identityAccessCount > 0`: `N Identifier-Zugriffe sichtbar gemacht`.

### 4. Wallet UI

Ziel:

- Nutzer sehen Identity-Firewall-Ereignisse ohne neues Haupt-Feature oder Modal.

Geplante Aenderungen:

- `DataFlowPanel` rendert bei `identityAccessCount > 0` einen kompakten Badge in der Transaction Card.
- Im aufgeklappten Timeline-Bereich erscheinen die Identity-Firewall-Events als normale Timeline-Events mit Kategorie `identity`.
- CSS ergaenzt `dataflow-card__tag--identity` und `dataflow-event__dot--identity`.
- Text bleibt faktisch: `Identifier sichtbar gemacht` oder `Identifier-Zugriff erkannt`.

Nicht umsetzen:

- Keine neue Score-Anzeige.
- Keine neue Blockieren-Schaltflaeche.
- Keine VPN-/Provider-Empfehlung in DataFlow.

### 5. Merge-blockierende Tests

Shared Types:

- `AuditEventType` enthaelt `IDENTITY_ACCESS_DETECTED`.
- `IdentityFirewallMetadata` akzeptiert `blocked: false` und lehnt keinen MVP-Fall typseitig ab.

DataFlow:

- `DataFlowService` gruppiert `IDENTITY_ACCESS_DETECTED` ueber `decision_id`.
- `identityAccessCount` ist korrekt.
- `eventLabel('IDENTITY_ACCESS_DETECTED')` liefert Kategorie `identity`.
- `summarizeTransaction()` meldet nur die Anzahl sichtbarer Identifier-Zugriffe.

Wallet-PWA:

- `DataFlowPanel` zeigt den Identity-Badge bei Identity-Firewall-Events.
- Timeline zeigt `Identifier-Zugriff erkannt`.
- `WalletService.recordIdentityFirewallEvents()` erzeugt Events ohne Rohwerte.
- `App.handlePrivacyAuditAccept()` ruft die WalletService-Methode vor `proceedWithProof(...)` auf.

Regression:

- Bestehende `data-flow` Tests bleiben gruen.
- Bestehende `wallet-pwa` Tests bleiben gruen.
- Bestehende Audit-Chain-Verifikation bleibt unveraendert.

### 6. Review-2-Freigabekriterien

Product/Policy gibt frei, wenn:

- UI-Texte korrekt zwischen Sichtbarmachung und Blocking unterscheiden.
- Der MVP klar auf Wallet-PWA-Transparenz begrenzt bleibt.

Engineer gibt frei, wenn:

- Alle betroffenen Dateien und Tests identifiziert sind.
- Keine offene Interface-Entscheidung uebrig bleibt.

Reviewer/Security gibt frei, wenn:

- Metadata-Felder PII-minimal sind.
- Es keine neuen stabilen Cross-RP-Korrelatoren gibt.
- Failure der Identity-Firewall-Anzeige keinen Proof-Flow blockiert und keine Rohdaten offenlegt.

## Implementation v1 vom 2026-05-20

Umgesetzt:

- `IDENTITY_ACCESS_DETECTED` als eigener Audit-Event-Typ.
- PII-minimale `IdentityFirewallMetadata`-Typen in `shared-types`.
- `DataFlowTransaction.identityAccesses` und `identityAccessCount`.
- DataFlow-Label und Summary fuer Identity-Firewall-Ereignisse.
- WalletService-Methode `recordIdentityFirewallEvents(...)`.
- Anbindung in `App.handlePrivacyAuditAccept(...)` vor Proof-Erzeugung.
- DataFlowPanel-Badge, Tag und Timeline-Dot fuer Identity-Firewall-Ereignisse.
- Tests fuer shared-types, data-flow, WalletService und DataFlowPanel.

Validierung:

- `@askmi/shared-types` TypeScript-Lint gruen.
- `shared-types/test/runtime-validation.test.ts`: 63 Tests gruen ueber direkte Vitest-Binary.
- `data-flow` Source-Typecheck gruen ueber temporaere Source-Alias-tsconfig.
- `data-flow` Tests: 48 Tests gruen ueber direkte Vitest-Binary mit temporaerer Alias-Config.
- Wallet-PWA geaenderte Dateien transpilieren per esbuild.

Offene lokale Tooling-Einschraenkung:

- `pnpm install --frozen-lockfile` scheitert lokal mit `ENOENT` auf `_tmp_*`.
- `data-flow` und `wallet-pwa` Package-Filter-Tests koennen deshalb nicht ueber ihre normalen Package-Scripts laufen, weil lokale `node_modules`-Links fuer Vitest/jsdom fehlen.

## Nicht im MVP

- Keine vollstaendige Browser-Extension.
- Kein globaler Cookie-/Tracker-Blocker.
- Kein Netzwerk-Traffic-Proxy.
- Kein Risk Scoring.
- Keine automatisierte rechtliche Bewertung.
- Keine Speicherung vollstaendiger Identifier-Werte.

## Naechster Schritt

Abschlussreview vorbereiten:

1. Code-Diff gegen Review-1- und Review-2-Kriterien pruefen.
2. Normale Package-Tests ausfuehren, sobald pnpm-Workspace-Linking lokal repariert ist.
3. Product/Policy bestaetigt UI-Text: Sichtbarmachung, kein Blocking-Versprechen.
4. Reviewer/Security prueft Metadata auf Roh-Identifier und Cross-RP-Korrelatoren.
5. Danach U-20/U-21 im Backlog je nach Review-Ergebnis als MVP-complete markieren.

## Abschlussreview 2026-06-07

Durchgefuehrt auf aktuellem `master` (`6ed357a`), nach Rebrand und Branch-Konsolidierung.
Die Implementation v1 hat beide Umbauten ueberlebt und liegt vollstaendig `@askmi`-namespaced
auf `master`.

### 1. Code-Diff gegen Review-1/Review-2-Kriterien — ✅

Verifizierte Symbole auf `master`:

- `IDENTITY_ACCESS_DETECTED` als eigener `AuditEventType` (`shared-types/src/audit.ts`).
- `IdentityFirewallMetadata` mit literal `blocked: false` (PII-eng typisiert).
- `WalletService.recordIdentityFirewallEvents(...)` + Mapping `mapTrackingPointToIdentityMetadata`.
- `DataFlowTransaction.identityAccesses` / `identityAccessCount`, Kategorie `identity`,
  `eventLabel('IDENTITY_ACCESS_DETECTED')`, `summarizeTransaction()`.
- `DataFlowPanel` Badge/Tag/Timeline-Dot fuer Identity-Ereignisse.

### 2. Package-Tests (frueher lokaler Blocker, jetzt geloest) — ✅

pnpm-Workspace-Linking funktioniert wieder; Tests ueber die normalen Package-Scripts:

- `@askmi/shared-types`: **69/69** gruen.
- `@askmi/data-flow`: **56/56** gruen.
- `@askmi/wallet-pwa`: **105/105** gruen.
- Summe der MVP-relevanten Suiten: **230** Tests gruen.

### 3. Product/Policy — UI-Text — ✅

`eventLabel` liefert `Identifier-Zugriff erkannt`, `summarizeTransaction()` meldet
`N Identifier-Zugriffe sichtbar gemacht`. Kein UI-Text behauptet Blocking; kein Risk-Score.

### 4. Reviewer/Security — Metadata-Pruefung — ✅

- `sanitizeIdentityActorLabel()` reduziert URLs auf Hostname, entfernt Query/Fragment/Pfad,
  kappt auf 80 Zeichen, Fallback `Unknown actor` — keine Roh-URLs/Pfade.
- Keine Cookie-Werte, IPs, raw User-Agent-Strings, Device-IDs oder Credential-Rohwerte im Event.
- `verifier_did` nur als bereits vorhandener Transaktionskontext, kein neuer stabiler
  Cross-RP-Korrelator.
- `blocked: false as const` schliesst falsche Blocking-Behauptung typseitig aus.
- `if (!decisionId) return []` verhindert Events ohne `decision_id`.
- Fail-closed gilt fuer Datenoffenlegung, nicht fuer die rein informative Anzeige —
  Event-Erzeugung kann fehlschlagen, ohne den Proof-Flow zu blockieren.

### 5. Backlog-Status

Die historischen IDs U-20/U-21 existieren in der aktuellen Backlog-Struktur nicht mehr
(Umstellung auf Video-Gap-Epics + Sprint-02). Der MVP wird hier als **complete** gefuehrt;
`STATE.md` weist die Identity-Firewall-Transparenz als ausgelieferte Capability aus.

### Ergebnis

Abschlussreview **bestanden**. Identity Firewall MVP (informieren + auditieren, nicht
blockieren) ist auf `master`, getestet und PII-minimal. Blocking/Enforcement bleibt
explizit einem spaeteren Sprint vorbehalten (siehe "Nicht im MVP").
