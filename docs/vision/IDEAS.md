# miTch — Ideas Hub

> Zukunftsdenken. Nicht implementierungsreif. Sammlung von Ideen die miTch weiterentwickeln.

---

## Die offene Frage: Was ist miTch fuer den Nutzer?

Bevor irgendwas gebaut wird, muss diese Positionierung klar sein:

**Option A — "Privacy Wallet"**
miTch ist ein Werkzeug das Credentials schuetzt. Der Nutzer kommt weil er etwas beweisen muss (Alter, Wohnsitz, Student) und dabei keine PII preisgeben will. Einstieg: erste Transaktion.

**Option B — "Digitales Roentgenbild"**
miTch zeigt dem Nutzer was die Welt ueber ihn weiss — und gibt ihm Werkzeuge das zu aendern. Der Nutzer kommt weil er neugierig ist. Einstieg: Data Import (Apple/Google Export analysieren). Das Wallet kommt danach als Konsequenz.

**Option C — Beides, aber Reihenfolge matters**
Einstieg ueber Sichtbarkeit (Roentgenbild), Retention ueber Kontrolle (Wallet). "Erst sehen, dann handeln."

**TODO Jonas:** Welche Option? Das bestimmt was zuerst gebaut wird und wie miTch kommuniziert wird. Meine Vermutung: Option C — aber der erste Satz auf der Website muss trotzdem EINER sein.

---

## Wer ist der erste Nutzer?

Alle Ideen reden ueber "den Nutzer" — aber wer ist das konkret? Der erste Nutzer bestimmt welche Idee zuerst gebaut wird.

| Kandidat | Warum der? | Einstieg ueber |
|---|---|---|
| **Studenten in Innsbruck** | Tech-affin, Privacy-bewusst, lokaler Zugang, Student-Discount Use Case | Wallet (Student-Proof) |
| **Privacy-Enthusiasten / noyb-Umfeld** | Hohe Motivation, fruehe Evangelisten, brauchen kein Marketing | Data Import (Roentgenbild) |
| **Schufa-/KSV-Geschaedigte** | Konkreter Schmerz, emotionaler Trigger, AI Act Relevanz | Shadow Profile + Escalation |
| **GDPR-bewusste Unternehmer** | Compliance-Druck, wollen Badge/Trust Seal | Verifier-Seite (Badge) |
| **Eltern** | Sorge um Kinder-Daten, Delegation Use Case | Data Import + Delegated Proofs |

**TODO Jonas:** Wer ist Nutzer #1? Kann auch eine Kombination sein — aber einer muss der ERSTE sein.

---

## Cluster-Uebersicht

Die Ideen bilden drei Cluster mit klaren Abhaengigkeiten:

```
Cluster A: Nutzer-Sichtbarkeit (muss zuerst)
  → #1 Personal Privacy Profile (Dashboard + Data Import)
  → #2 Collective Signal / Anti-Surveillance Scorecard

Cluster B: Verifier-Seite (braucht Nutzer-Basis aus A)
  → #3 Privacy-as-a-Service API
  → #7 Compliance Badge / Trust Seal
  → #8 Gemeinde-Wallet Pilot Innsbruck

Cluster C: Protokoll-Erweiterungen (unabhaengig, technisch)
  → #4 Offline-First Verification
  → #5 Delegated Proofs
  → #6 Composable Predicates
```

**Logik:** Cluster B funktioniert nicht ohne Cluster A — kein Verifier zahlt fuer eine API die niemand nutzt. Cluster C ist technisch wertvoll aber kein Wachstumstreiber. A baut die Nutzerbasis, B monetarisiert sie, C erweitert die Faehigkeiten.

---

## Competitive Landscape

miTch ist nicht allein im Raum. Was gibt es, und warum ist miTch anders?

| Projekt | Was es tut | Wo miTch anders ist |
|---|---|---|
| **HestiaLabs** (Schweiz) | Data Literacy — hilft Nutzern ihre Datenexporte zu verstehen | miTch geht weiter: nicht nur verstehen, sondern kontrollieren (Wallet + Policy Engine) |
| **Solid / Inrupt** (Tim Berners-Lee) | Data Pods — Nutzer speichert Daten in eigenem Pod, Apps fragen an | miTch speichert keine Daten zentral — es vermittelt Proofs. Kein Pod, kein Server, kein Single Point of Failure |
| **MyData** (Finnland) | Daten-Portabilitaet — Standard fuer Daten-Austausch zwischen Diensten | miTch tauscht keine Daten aus — es beweist Eigenschaften ohne Daten preiszugeben |
| **Apple Privacy Report** | Zeigt welche Apps auf Sensoren/Netzwerk zugreifen | Nur Apple-Oekosystem, keine Verifier-Sicht, kein Escalation-Path, keine Cross-Platform-Analyse |
| **Google My Activity** | Zeigt gespeicherte Aktivitaeten (Suche, Standort, YouTube) | Nur Google-Daten, kein Aggregat, keine Handlungsempfehlungen, Fuchs bewacht Huehnerstall |

**miTch's Differenzierung in einem Satz:** Die anderen zeigen dir WAS gesammelt wurde. miTch zeigt dir was daraus ERRECHNET werden kann — und gibt dir Werkzeuge dagegen vorzugehen.

---

# Cluster A — Nutzer-Sichtbarkeit

> Muss zuerst gebaut werden. Ohne Sichtbarkeit kein Vertrauen, ohne Vertrauen keine Nutzerbasis.

---

## 1. Personal Privacy Profile (Dashboard + Data Import)

**Kern-These:** Zwei Datenquellen, ein Bild.

### Datenquelle 1: Platform-Import (was schon gesammelt wurde)
Der Nutzer laedt seine Plattform-Daten manuell in miTch — miTch analysiert und uebersetzt.

**Das Problem:**
- Apple, Google, Facebook etc. erlauben per GDPR Art. 20 den Download der eigenen Daten
- Diese Exports sind riesige JSON/CSV-Dumps (oft Hunderte MB)
- Kein normaler Mensch oeffnet, versteht oder analysiert diese Dateien
- Die Daten existieren — aber ohne Uebersetzer sind sie wertlos

**Was miTch daraus macht:**
- **Sensor-Daten:** "Dein iPhone hat in den letzten 30 Tagen 847x deinen Standort erfasst. 12 Apps hatten Zugriff."
- **Analyse-Daten:** "Diese 5 Apps haben Nutzungsdaten an Tracking-Netzwerke gesendet. Hier ist was sie wissen."
- **Cross-Platform:** "Google kennt deine Suchhistorie, Apple kennt deine App-Nutzung — zusammen ergibt das dieses Bild von dir."
- **Zeitverlauf:** "Deine Datenexposition ist in den letzten 6 Monaten um 34% gestiegen — hauptsaechlich durch diese 2 Apps."
- **Re-Identifikation:** "Mit den Daten die du geteilt hast bist du zu X% re-identifizierbar" (basierend auf k-Anonymity / Quasi-Identifier-Forschung)

### Datenquelle 2: miTch-Transaktionen (was du aktiv kontrollierst)
Das Daily Review aus UX_DAILY_REVIEW.md — aber jetzt eingebettet in das groessere Bild.

- **Pro Transaktion:** Welche Claims geteilt, welche zurueckgehalten, an wen, wann
- **Pro Verifier:** Wie oft fragt der an? Was will er? Vergleich zu aehnlichen Verifiern
- **Longitudinal:** Monats-Zusammenfassung — "12 Verifier haben dich kontaktiert, 3 wollten mehr als noetig"
- **Danger Levels:** Ampel-System (gruen/gelb/rot) basierend auf Over-Requesting-Patterns

### Die Verbindung — warum das EINE Idee ist:
Der Platform-Import ist der **Onboarding-Moment** ("Hier ist was die Welt ueber dich weiss").
Die miTch-Transaktionen sind der **Retention-Moment** ("Und hier ist wie miTch das aendert").
Zusammen: ein Personal Privacy Profile das waechst — erst passiv (Import), dann aktiv (Transaktionen).

### Was schon da ist:
- Backend: audit-log (`exportReport()`), KPIEngine, transparencyReport.ts
- Design: UX_DAILY_REVIEW.md (detailliert), WHY_USERS_CARE.md (Evidenz), SHADOW_PROFILES.md (Grenzen)
- Fehlend: gesamte UI-Schicht, Platform-Parser, Notification-System, Monthly Summaries

### Technisch (Data Import):
- Alles lokal — Import-Dateien werden nie hochgeladen
- Parser fuer gaengige Export-Formate: Apple Privacy Report (JSON), Google Takeout (JSON/mbox), Facebook Download (JSON/HTML)
- Analyse laeuft im Browser oder lokal auf dem Device
- Ergebnisse im audit-log gespeichert (gleiche Infrastruktur wie Transaktions-Log)

### Offene Fragen (TODO Jonas):
- **Aha-Moment:** Ist der Data Import der erste Screen? Oder braucht es vorher noch etwas?
- **Granularitaet:** Pro-Feld oder pro-Credential bei Transaktions-View?
- **Notifications:** Push-Notifications oder nur In-App?
- **Overreaching-Threshold:** Ab wann wird ein Verifier als "overreaching" markiert? Wer definiert das?
- **MVP-Definition:** Was ist die kleinste Version die schon Wert liefert? (z.B. nur Data Import ohne Daily Review? Oder nur Daily Review ohne Import?)
- **Plattformen:** Welche zuerst? Apple + Google? Facebook/Instagram/WhatsApp spaeter?
- **Wartung:** Export-Formate aendern sich — wie viel Aufwand ist das?
- **Automatisierung:** Spaeter moeglich (Apple Shortcuts, Google API)? Oder bewusst manuell?
- **Re-Identifikations-Score:** Gibt es nutzbare Forschung? (k-Anonymity, l-Diversity, Quasi-Identifier?)
- **Differenzierung:** Apple/Google haben eigene Privacy Reports — was macht miTch fundamental anders? (Vermutung: feldgranular + Escalation + verifieruebergreifend + Cross-Platform + re-identification + Handlungsempfehlungen)

---

## 2. Collective Signal / Anti-Surveillance Scorecard

**Idee:** Nutzer flaggen Verifier die zu viel verlangen — aggregiert, anonym, ohne individuelle Attribution.

### Mechanik:
- One-Tap "Dieser Verifier verlangt zu viel" nach jeder Transaktion
- Aggregation lokal oder via Privacy-preserving Protocol (kein zentraler Server sieht wer flaggt)
- Ab Schwellenwert (z.B. 500 Flags): Verifier bekommt oeffentlichen Score
- Veroeffentlichung als aggregierte Stats — Transparenz-Druck auf Datensammler

### Verbindung zu #1:
- Dashboard zeigt den Collective Score pro Verifier
- "Andere Nutzer bewerten diesen Verifier als overreaching" als Info im Consent-Dialog
- Platform-Import-Daten koennten Collective Signal anreichern (z.B. "Diese App hat bei 80% der Nutzer Standort-Zugriff obwohl sie ihn nicht braucht")

### Offene Fragen:
- Sybil-Protection ohne zentrale Identity? (Nullifier-basiert?)
- Rechtliche Implikationen von oeffentlichen Verifier-Scores?
- Wer kuratiert die Schwellenwerte?

---

# Cluster B — Verifier-Seite

> Braucht Nutzer-Basis aus Cluster A. Kein Verifier zahlt fuer eine API die niemand nutzt.

---

## 3. Privacy-as-a-Service API

**Idee:** Verifier zahlt pro Proof-Request statt pro PII-Datensatz.

### Umkehrung des Geschaeftsmodells:
- Heute: Verifier kauft PII-Datensaetze (Schufa, KYC-Provider)
- miTch: Verifier kauft kryptographische Proofs — guenstiger, compliant, kein Daten-Risiko
- Pricing: Pro Verification, gestaffelt nach Komplexitaet (einfaches isOver18 vs. Multi-Predicate)

### Revenue fuer miTch:
- Freemium: X Verifications/Monat gratis, danach Pay-per-Use
- Enterprise: SLA, Support, Custom Policy Profiles
- Marketplace: Drittanbieter-Module (z.B. branchenspezifische Predicates)

### Offene Fragen:
- Wer zahlt? Verifier oder Nutzer oder beide?
- Wie verhindert man dass Payment-Metadata Privacy untergraebt?
- Open-Source-Core + Commercial API — Governance-Modell?

---

## 7. Compliance Badge / Trust Seal

**Idee:** Verifier die miTch nutzen kriegen ein verifizierbares "Zero-PII Verified" Badge.

### Mechanik:
- Badge ist selbst ein Verifiable Credential (dogfooding!)
- Audit-Trail beweist dass Verifier tatsaechlich nur Proofs empfaengt
- Badge wird regelmaessig re-evaluiert (kein einmaliges Zertifikat)

### Marketing-Wert:
- Sichtbar auf Verifier-Website → Vertrauenssignal fuer Endnutzer
- Netzwerkeffekt: je mehr Verifier das Badge haben, desto wertvoller wird es
- GDPR-Differenzierung gegenueber Konkurrenz

---

## 8. Gemeinde-Wallet Pilot (Innsbruck)

**Idee:** Innsbruck als erste Stadt die miTch fuer Buerger-Services nutzt.

### Use Cases:
- Parkausweis: Wohnsitz-Proof statt Meldezettel-Kopie
- Bibliotheksausweis: Alters-Proof + Wohnsitz, kein KYC
- Muellgebuehren-Ermaessigung: Einkommens-Proof ohne Steuerbescheid
- Oeffentlicher Nahverkehr: Studenten/Senioren-Tarif via Predicate

### Warum Innsbruck:
- Ueberschaubare Groesse (130k Einwohner)
- Universitaetsstadt → tech-affine Early Adopter
- ID Austria Rollout laeuft → eIDAS 2.0 Infrastruktur kommt
- Lokale Kontakte vorhanden

### Offene Fragen:
- Welche Abteilung ist Ansprechpartner? (IT? Buergerdienste?)
- Regulatorische Huerden fuer kommunale Proof-Akzeptanz?
- Integration mit bestehenden Gemeinde-IT-Systemen?

---

# Cluster C — Protokoll-Erweiterungen

> Technisch wertvoll, unabhaengig von Nutzerbasis. Erweitern was miTch kann, nicht wer es nutzt.

---

## 4. Offline-First Verification

**Idee:** QR-basierter Proof-Austausch ohne Internet.

### Use Cases:
- Bergbahn-Ticket: Alter-Proof am Lift-Scanner ohne Mobilfunk
- Festival-Eingang: Tausende Proofs ohne Backend-Last
- Katastrophenfall: Identity-Verification wenn Infrastruktur ausfaellt

### Mechanik:
- Policy Engine laeuft lokal auf dem Device
- Proof wird als signiertes QR generiert (compact SD-JWT)
- Verifier scannt offline, validiert Signatur lokal
- Merkle-Proof wird spaeter geanchored wenn wieder online

### Offene Fragen:
- Revocation-Check ohne Internet? (Cached StatusList mit TTL?)
- QR-Kapazitaet fuer komplexe Proofs? (max ~4KB)
- Replay-Protection offline? (Zeitfenster-basiert?)

---

## 5. Delegated Proofs

**Idee:** Proofs im Namen anderer erstellen ohne deren Identity preiszugeben.

### Use Cases:
- Eltern beweisen Alter des Kindes (Kino, Schwimmbad)
- Firma beweist Mitarbeiter-Eigenschaft fuer Firmenticket
- Betreuer beweist Patientenrecht fuer Medikamentenabholung

### Mechanik:
- Delegation-Chain: Issuer → Credential-Holder → Delegate → Verifier
- Delegate bekommt eingeschraenktes Proof-Recht (zeitlich, scopebegrenzt)
- Verifier sieht: "gueltig, delegiert" — nicht wer der eigentliche Holder ist

### Offene Fragen:
- Wie wird Delegation widerrufen?
- Ketten-Laenge begrenzen? (max 1 Delegation?)
- Rechtliche Basis fuer delegierte Proofs? (Vollmacht vs. Vertretung)

---

## 6. Composable Predicates

**Idee:** Mehrere Bedingungen als ein einziger Proof statt separate Anfragen.

### Beispiel:
`isStudent AND isOver18 AND livesIn(Tirol)` → ein Proof, eine Consent-Anfrage

### Warum:
- Reduziert Proof-Fatigue massiv (ProofFatigueTracker existiert schon)
- Weniger Consent-Dialoge = bessere UX
- Verifier bekommt genau was er braucht, nicht mehr

### Offene Fragen:
- Wie wird Consent fuer zusammengesetzte Proofs dargestellt?
- Performance bei vielen Predicates? (ZK-Circuit-Groesse)
- Standard-Kompatibilitaet? (OID4VP unterstuetzt das?)

---

*Letzte Aktualisierung: 2026-03-15*
