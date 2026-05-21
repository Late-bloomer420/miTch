# Sprint 2: Consent Manager Data Visualization

Stand: 2026-05-21

## Ziel

miTch soll den Consent- und Disclosure-Flow so visualisieren, dass Nutzer, Product und Security auf einen Blick sehen:

- was angefragt wurde
- was erlaubt wurde
- was zurückgehalten wurde
- welche Entscheidung der Policy Engine zugrunde lag
- welche Evidence im Audit vorhanden ist

## Begriffsklarheit

Im Repo und in der UI wird **Consent** verwendet, nicht `Consens`.

`Consent Manager` ist hier die Bezeichnung fuer die neue Visualisierungs- und Kontrolloberflaeche rund um:

- ConsentModal
- DataFlowPanel
- ConsentReceipt
- DecisionCapsule
- Audit Evidence

## Warum der Schritt jetzt kommt

Die Basis ist bereits vorhanden:

- `ConsentModal` startet die Zustimmung im Wallet.
- `PrivacyAuditService` zeigt Sichtbarkeits-/Tracker-Kontext.
- `WalletService` schreibt Identity-Firewall-Events.
- `DataFlowPanel` zeigt bereits Transaktions- und Claim-Sicht.
- `consentReceipt.ts` und `audit.ts` liefern Evidence-Objekte.

Was fehlt, ist eine gemeinsame, verständliche Visualisierungsschicht fuer diese Daten.

## Sprint-Frage

Wie machen wir die Consent- und Disclosure-Entscheidung so sichtbar, dass sie wie ein echtes Steuerungsobjekt wirkt und nicht wie mehrere lose UI-Teile?

## Rollen

### 1. Product / Policy

Verantwortung:

- Definiert die sichtbaren Zustände des Consent Managers.
- Legt fest, welche Daten sicher angezeigt werden duerfen.
- Entscheidet, welche Aussagen im UI erlaubt sind und welche nicht.

Liefergegenstaende:

- Soll-Zustaende fuer Consent Manager.
- Freigegebene Begriffe fuer UI und Labels.
- Akzeptanzkriterien fuer Nutzerverstaendlichkeit.

### 2. Engineer

Verantwortung:

- Fasst bestehende Consent- und Audit-Daten in einer visualisierten Struktur zusammen.
- Nutzt vorhandene Datenmodelle statt neue Parallelmodelle.
- Implementiert die erste, schlanke Manager-Ansicht.

Liefergegenstaende:

- Datenmodell fuer Consent Manager View.
- UI-Zusammenfuehrung von ConsentModal, DataFlowPanel und ConsentReceipt.
- Tests fuer Datenfluss und Darstellung.

### 3. Reviewer / Security

Verantwortung:

- Prueft, dass keine Roh-PII in die Visualisierung rutscht.
- Prueft, dass Consent nicht als harter Auto-Allow missverstanden wird.
- Prueft, dass die Visualisierung keine falsche Sicherheit suggeriert.

Liefergegenstaende:

- Freigabe der sichtbaren Felder.
- Freigabe der Bezeichnungen.
- Freigabe der No-Go-Felder.

## Nächster konkreter Schritt

### Schritt 1: Visual State Model festziehen

Wir definieren die minimalen Zustandsbausteine, die der Consent Manager anzeigen muss:

- `requested`
- `allowed`
- `withheld`
- `decision`
- `receipt`
- `identity_signals`

Diese Zustände sollen direkt aus bestehenden Quellen ableitbar sein:

- `DecisionCapsule`
- `AuditLogEntry`
- `DataFlowTransaction`
- `ConsentReceipt`
- `PrivacyContext`

## Erste Umsetzungsrichtung

### Anzeigeebenen

1. **Request Layer**
   - was der Verifier angefragt hat

2. **Decision Layer**
   - was die Policy erlaubt oder ablehnt

3. **Disclosure Layer**
   - was tatsaechlich geteilt wurde

4. **Evidence Layer**
   - DecisionCapsule, ConsentReceipt, Audit-Events

5. **Identity Visibility Layer**
   - Identifier-, Tracker- und Surface-Hinweise

### UI-Regeln

- Eine Entscheidung pro Karte.
- Ein Vergleich von `requested` vs. `allowed` vs. `withheld`.
- Ein sichtbarer Evidence-Hinweis pro Transaktion.
- Keine generische Privacy-Dekoration ohne Datenbezug.

## Erfolgskriterien

- Nutzer erkennen die Consent-Entscheidung ohne in den Audit-Details zu versinken.
- Product kann die Datenfreigabe ohne technische Begriffe erklaeren.
- Security kann pruefen, dass keine Rohdaten angezeigt werden.
- Engineer kann die Ansicht direkt aus bestehenden Modulen ableiten.

## Empfehlung fuer den naechsten Bau-Schritt

Als naechstes bauen wir zuerst das **Consent Manager View Model** als gemeinsame Struktur zwischen:

- `ConsentModal`
- `DataFlowPanel`
- `AuditReportPanel`
- `PrivacyAuditModal`

Danach folgt die eigentliche UI-Integration.

