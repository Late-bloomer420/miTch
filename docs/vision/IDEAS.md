# miTch — Ideas Hub

> Zukunftsdenken. Nicht implementierungsreif. Sammlung von Ideen die miTch weiterentwickeln.

---

## 1. Data Transparency Dashboard (Priority: HIGH)

**Die Killer-Feature-These:** Nutzer kommen nicht wegen Crypto — sie kommen weil sie *sehen* was mit ihren Daten passiert.

### Was der Nutzer sieht:
- **Pro Transaktion:** Welche Claims geteilt, welche zurückgehalten, an wen, wann
- **Pro Verifier:** Wie oft fragt der an? Was will er? Vergleich zu ähnlichen Verifiern
- **Longitudinal:** Monats-Zusammenfassung — "12 Verifier haben dich kontaktiert, 3 wollten mehr als nötig"
- **Danger Levels:** Ampel-System (grun/gelb/rot) basierend auf Over-Requesting-Patterns
- **Was daraus errechnet werden kann:** Ehrliche Darstellung — "Mit Geburtsdatum + PLZ kann ein Verifier dein Profil zu 87% re-identifizieren" (siehe SHADOW_PROFILES.md)

### Warum das der erste Schritt ist:
- Nutzer die sehen was passiert, vertrauen dem System
- Nutzer die vertrauen, empfehlen weiter
- Nutzer die empfehlen, bringen Verifier dazu miTch zu integrieren
- **Netzwerkeffekt startet bei Transparenz, nicht bei Crypto**

### Was schon da ist:
- Backend: audit-log (`exportReport()`), KPIEngine, transparencyReport.ts
- Design: UX_DAILY_REVIEW.md (detailliert), WHY_USERS_CARE.md (Evidenz)
- Fehlend: gesamte UI-Schicht, Notification-System, Monthly Summaries

### Offene Fragen:
- Wie granular? Pro-Feld oder pro-Credential?
- Push-Notifications oder nur In-App?
- Ab wann wird ein Verifier als "overreaching" markiert? (Threshold-Definition)

---

## 2. Collective Signal / Anti-Surveillance Scorecard

**Idee:** Nutzer flaggen Verifier die zu viel verlangen — aggregiert, anonym, ohne individuelle Attribution.

### Mechanik:
- One-Tap "Dieser Verifier verlangt zu viel" nach jeder Transaktion
- Aggregation lokal oder via Privacy-preserving Protocol (kein zentraler Server sieht wer flaggt)
- Ab Schwellenwert (z.B. 500 Flags): Verifier bekommt oeffentlichen Score
- Veröffentlichung als aggregierte Stats — Transparenz-Druck auf Datensammler

### Verbindung zu Feature 1:
- Dashboard zeigt den Collective Score pro Verifier
- "Andere Nutzer bewerten diesen Verifier als overreaching" als Info im Consent-Dialog

### Offene Fragen:
- Sybil-Protection ohne zentrale Identity? (Nullifier-basiert?)
- Rechtliche Implikationen von oeffentlichen Verifier-Scores?
- Wer kuratiert die Schwellenwerte?

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
- oeffentlicher Nahverkehr: Studenten/Senioren-Tarif via Predicate

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

*Letzte Aktualisierung: 2026-03-15*
