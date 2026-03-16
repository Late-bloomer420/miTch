# IDEAS.md — Claudes Antworten

> Meine Perspektive auf die offenen Fragen. Zum Vergleichen mit Jonas' Antworten.
> Nicht als Wahrheit gemeint — als Sparring-Partner.

---

## Positionierung: Was ist miTch fuer den Nutzer?

**Meine Antwort: Option C — aber mit klarem Einstieg ueber Sichtbarkeit.**

Begruendung: Ein "Privacy Wallet" allein hat ein Kaltstart-Problem. Der Nutzer muss erstmal einen Verifier finden der miTch unterstuetzt, einen Credential bekommen, eine Transaktion machen — alles bevor er Wert sieht. Das dauert zu lang.

Der Data Import loest das Kaltstart-Problem: Der Nutzer laedt seinen Google Takeout hoch, und innerhalb von 30 Sekunden sieht er etwas das ihn ueberrascht. DAS ist der Moment. Das Wallet kommt danach natuerlich — "Jetzt wo du siehst was gesammelt wird, hier ist wie du es kontrollierst."

**Ein-Satz-Versuch:** "miTch zeigt dir was die Welt ueber dich weiss — und gibt dir die Kontrolle zurueck."

Nicht: "miTch ist ein Privacy-Wallet." Nicht: "miTch schuetzt deine Credentials." Sondern: Sichtbarkeit zuerst, Kontrolle als Konsequenz.

---

## Wer ist der erste Nutzer?

**Meine Antwort: Privacy-Enthusiasten / noyb-Umfeld — gefolgt von Studenten in Innsbruck.**

Begruendung:

**Warum nicht Studenten zuerst:** Der Student-Discount Use Case braucht einen kooperierenden Verifier (MCI, Uni, Geschaeft). Das ist ein Henne-Ei-Problem. Bis der erste Verifier live ist, hat der Student keinen Grund miTch zu installieren.

**Warum Privacy-Enthusiasten zuerst:** Diese Gruppe braucht keinen Verifier. Sie braucht nur den Data Import. Sie laedt ihren Google Takeout runter, sieht das Roentgenbild, und ist hooked. Diese Leute sind auf Mastodon, Hacker News, noyb-Newsletter, CCC-Umfeld. Sie teilen sowas. Sie sind die Evangelisten die den Netzwerkeffekt starten.

**Dann Studenten:** Wenn miTch 500-1000 aktive Nutzer hat (Privacy-Enthusiasten), hast du Verhandlungsmasse fuer den ersten Verifier-Piloten. "500 Leute nutzen das schon, wollt ihr der erste Verifier sein?" Das ist ein anderes Gespraech als "ich hab ein Wallet gebaut, will wer mitmachen?"

**Reihenfolge:**
1. Privacy-Enthusiasten → Data Import → Roentgenbild → Evangelismus
2. Studenten Innsbruck → Student-Discount Pilot → erster Verifier
3. Breiter Markt → Gemeinde-Pilot → PaaS API

---

## Offene Fragen zu #1: Personal Privacy Profile

### Aha-Moment
**Meine Antwort: Der Data Import IST der Aha-Moment.**

Erster Screen nach Onboarding: "Lade deine Daten herunter. Wir zeigen dir was drin steckt."
Drei Buttons: Apple | Google | Facebook
Der Nutzer waehlt einen, laedt die ZIP hoch, wartet 10 Sekunden.
Dann: ein einfaches Dashboard — "X Apps haben deinen Standort getrackt. Y Tracker haben deine Daten bekommen. Z Mal wurde dein Profil geteilt."

Kein Wallet, kein Credential, keine Crypto-Erklaerung. Nur: "Hier ist was du nicht wusstest." Der Rest kommt spaeter.

### Granularitaet
**Meine Antwort: Pro-Feld — aber mit Credential-Gruppierung.**

Der Nutzer denkt nicht in Credentials ("mein SD-JWT VC"). Er denkt in Feldern ("mein Geburtsdatum", "meine Adresse"). Also zeig Felder. Aber gruppiere sie visuell nach Credential-Herkunft, damit klar ist woher die Daten kommen.

### Notifications
**Meine Antwort: In-App first, Push spaeter.**

Push-Notifications haben ein Vertrauensproblem — eine neue App die sofort Push will, wird abgelehnt. Besser: In-App Badge (rote Zahl wie bei E-Mail). Push kommt spaeter wenn der Nutzer die App schon vertraut und es selbst aktiviert.

Ausnahme: Wirklich kritische Events (Breach-Detection, Credential-Missbrauch) sollten Push koennen — aber nur wenn der Nutzer das explizit erlaubt hat.

### Overreaching-Threshold
**Meine Antwort: Relativ, nicht absolut.**

Nicht "ein Verifier der mehr als 3 Felder will ist overreaching". Sondern: "Ein Liquor Store der deine Adresse will, ist overreaching — ein Krankenhaus das deine Adresse will, ist es nicht." Der Threshold muss kontextabhaengig sein.

Technisch: Der Policy Engine kennt schon Use-Case-Profile (config-profiles.ts). Ein Verifier der mehr verlangt als sein Profil erwarten laesst, wird gelb. Wer deutlich mehr verlangt, wird rot.

Wer definiert das? Initialer Vorschlag: miTch-Team kuratiert Basis-Profile (Einzelhandel, Gesundheit, oeffentliche Hand, Bildung). Community kann spaeter Profile vorschlagen. Aber die Defaults muessen stimmen — sonst ist alles gelb und gelb bedeutet nichts.

### MVP-Definition
**Meine Antwort: Nur Data Import. Kein Daily Review im MVP.**

Die kleinste wertvolle Einheit: Du laedt Google Takeout hoch, miTch zeigt dir 5 Insights in Plain Language. Fertig. Kein Wallet, kein Consent-Dialog, keine Transaktion. Nur das Roentgenbild.

Warum: Das ist in Wochen baubar (Parser + einfache UI). Der Daily Review braucht eine funktionierende Wallet + Transaktionen + Verifier — das sind Monate. Der Data Import beweist den Wert sofort.

**MVP-Scope:**
- Google Takeout Parser (JSON, gut dokumentiert, groesste Nutzerbasis)
- 5 Insight-Kategorien: Standort-Zugriffe, Tracking-Netzwerke, App-Aktivitaet, Suchhistorie-Umfang, Datenmenge gesamt
- Einfache Web-UI (kann in wallet-pwa leben)
- Alles lokal, kein Upload

### Plattformen
**Meine Antwort: Google Takeout zuerst.**

Google Takeout ist am besten dokumentiert, hat die groesste Nutzerbasis (Android > iOS weltweit), und die Daten sind am reichhaltigsten (Suche, Standort, YouTube, Gmail-Metadaten, App-Nutzung). Apple Privacy Report ist kleiner und weniger ueberraschend (Apple sammelt weniger). Facebook hat die emotionalste Wirkung aber schmaelere Nutzerbasis (2026, viele junge Nutzer sind nicht mehr auf Facebook).

Reihenfolge: Google → Apple → Instagram/WhatsApp → Facebook

### Wartung Export-Formate
**Meine Antwort: Moderat, aber beherrschbar.**

Google Takeout Format aendert sich selten (JSON-Struktur ist seit Jahren stabil). Groesstes Risiko: neue Datentypen die der Parser nicht kennt. Loesung: Parser der unbekannte Felder nicht ignoriert sondern als "Unbekannt — X Eintraege" anzeigt. So ist der Output nie falsch, nur manchmal unvollstaendig.

Wartungsaufwand: Realistisch 1-2 Tage pro Quartal um neue Felder einzupflegen. Kein Blocker.

### Automatisierung
**Meine Antwort: Bewusst manuell. Fuer jetzt.**

Automatisierung (Apple Shortcuts, Google API) klingt besser, hat aber zwei Probleme:
1. Google/Apple koennen die API jederzeit einschraenken → Abhaengigkeit
2. Der manuelle Download ist ein bewusster Akt — der Nutzer WILL seine Daten sehen. Das ist ein Feature, kein Bug.

Spaeter vielleicht ein "Erinnere mich alle 3 Monate" Reminder. Aber kein Auto-Sync.

### Re-Identifikations-Score
**Meine Antwort: Ja, es gibt nutzbare Forschung.**

Latanya Sweeney (Harvard, 2000): 87% der US-Bevoelkerung sind mit PLZ + Geburtsdatum + Geschlecht eindeutig identifizierbar. Das ist der Klassiker.

k-Anonymity (Samarati & Sweeney): Ein Datensatz ist k-anonym wenn jede Kombination von Quasi-Identifiern mindestens k Personen matcht. Je kleiner k, desto hoeher das Risiko.

l-Diversity (Machanavajjhala et al., 2007): Erweiterung — auch wenn k gross ist, kann ein sensitives Attribut trotzdem eindeutig sein.

Praktisch fuer miTch: Ein einfaches Scoring-Modell das pro Transaktion berechnet welche Quasi-Identifier-Kombination geteilt wurde und das geschaetzte k anzeigt. "Mit diesen Daten bist du in einer Gruppe von ~50 Personen" vs. "~3 Personen" vs. "eindeutig identifizierbar". Kein perfektes k — eine Schaetzung reicht fuer den Nutzer.

### Differenzierung Apple/Google
**Meine Antwort: Drei Dinge die kein Konkurrent hat.**

1. **Cross-Platform:** Apple zeigt Apple-Daten. Google zeigt Google-Daten. miTch zeigt ALLES zusammen — und berechnet was die Kombination ueber dich verraet. Das Ganze ist mehr als die Summe.

2. **Handlungsempfehlungen + Escalation:** Apple zeigt dir "App X hat 47x auf deinen Standort zugegriffen" — und dann? Nichts. miTch sagt: "Das ist unueblich. Hier kannst du die Berechtigung entziehen. Wenn du willst, melde es der Datenschutzbehoerde."

3. **Ehrlichkeit ueber Grenzen:** SHADOW_PROFILES.md ist das ehrlichste Dokument im ganzen Repo. miTch sagt dem Nutzer was es NICHT zeigen kann. Das baut Vertrauen das kein "Privacy Dashboard" von Apple oder Google je haben wird — weil die ein Interesse haben die Grenzen zu verschweigen.

---

## Offene Fragen zu #2: Collective Signal

### Sybil-Protection
**Meine Antwort: Nullifier-basiert, aber einfach.**

Jeder Nutzer hat einen deterministischen Nullifier pro Verifier (HKDF aus Wallet-Seed + Verifier-ID). Das Flag "overreaching" wird mit dem Nullifier signiert. Zwei Flags vom selben Nullifier = eins. Kein zentraler Server kennt den Nutzer — nur dass ein einzigartiger Nullifier einmal geflagt hat.

Das ist nicht perfekt (wer zwei Wallets hat, kann doppelt flaggen) — aber fuer ein Scoring-System reicht es. Es ist kein Wahlsystem, es ist ein Signal.

### Rechtliche Implikationen
**Meine Antwort: Niedrig, wenn die Methodik transparent ist.**

Oeffentliche Scores von Restaurants (TripAdvisor), Hotels (Booking), Arbeitgebern (Glassdoor) sind legal — solange die Methodik offenliegt und keine falschen Tatsachenbehauptungen gemacht werden. "X% der Nutzer bewerten diesen Verifier als ueberfordernd" ist eine Meinungsaeusserung, keine Tatsachenbehauptung.

Risiko: Verifier koennten versuchen den Score gerichtlich anzugreifen. Schutz: Der Score basiert auf anonymen Aggregaten, miTch kennt die einzelnen Nutzer nicht, die Methodik ist Open Source.

Trotzdem: vor Launch juristisch pruefen lassen. Datenschutzrecht ist eine Sache, Wettbewerbsrecht eine andere.

---

## Gesamtbild: Mein vorgeschlagener Pfad

```
Phase 1 (kurzfristig): Google Takeout Parser + einfache Insights-UI
  → Zielgruppe: Privacy-Enthusiasten
  → Ziel: 500 aktive Nutzer, Feedback, Evangelismus
  → Kein Wallet noetig

Phase 2 (mittelfristig): Daily Review UI + Wallet-Transaktionen
  → Zielgruppe: erweitert auf Studenten/Innsbruck
  → Ziel: erster Verifier-Pilot (Student-Discount)
  → Wallet wird relevant

Phase 3 (laengerfristig): Collective Signal + PaaS API + Badge
  → Zielgruppe: breiterer Markt
  → Ziel: Monetarisierung, Netzwerkeffekt
  → Verifier zahlen, Nutzer profitieren
```

Die Crypto-Infrastruktur (26 Packages, 1411 Tests) ist die Grundlage — aber der Nutzer sieht sie nie direkt. Was er sieht ist das Roentgenbild. Das ist das Produkt.

---

*Geschrieben: 2026-03-16, Claude Opus 4.6*
