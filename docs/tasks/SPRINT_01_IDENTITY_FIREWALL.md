# Sprint 1: Identity Firewall MVP

Stand: 2026-05-20
Backlog-Bezug: U-20, U-21
Status: Planning

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

## Nicht im MVP

- Keine vollstaendige Browser-Extension.
- Kein globaler Cookie-/Tracker-Blocker.
- Kein Netzwerk-Traffic-Proxy.
- Kein Risk Scoring.
- Keine automatisierte rechtliche Bewertung.
- Keine Speicherung vollstaendiger Identifier-Werte.

## Naechster Schritt

Review 1 vorbereiten:

1. Bestehende Audit-, DataFlow- und Wallet-Strukturen inspizieren.
2. Konkretes minimales Event-Modell vorschlagen.
3. UI-Platzierung im bestehenden Wallet/DataFlow-Kontext festlegen.
4. Scope mit Product/Policy und Reviewer/Security freigeben.
