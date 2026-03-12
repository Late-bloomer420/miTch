# miTch — Anwendungsbereiche
**Stand:** 2026-03-06  
**Kriterium:** Nur Bereiche wo Selective Disclosure + Unlinkability + Policy Enforcement reale Probleme löst.  
**Ehrlichkeits-Check:** Jeder Bereich enthält eine Bewertung von Machbarkeit und Marktreife.

---

## Tier 1 — Natürlicher Fit (miTch löst das Kernproblem)

### 1. Altersverifikation (aktueller Beachhead)
**Problem:** Online-Dienste (Alkohol, Tabak, Glücksspiel, Pornografie) brauchen Altersnachweise. Aktuell: Ausweiskopie hochladen oder VideoIdent = massiver Daten-Overkill.  
**miTch:** "Ist über 18" als Ja/Nein-Proof. Kein Name, kein Geburtsdatum, keine Adresse.  
**Regulierung:** EU Verordnung zur Altersverifikation kommt. UK Online Safety Act. Deutschland: JuSchG.  
**Machbarkeit:** ⭐⭐⭐⭐⭐ — Bereits implementiert.  
**Markt:** Milliarden-Markt. Yoti, Veriff, IDnow sind die Incumbents — alle sammeln zu viele Daten.

### 2. Gesundheitswesen / EHDS
**Problem:** Patienten haben keine Kontrolle über ihre Gesundheitsdaten. Arzt A weiß was Arzt B verschrieben hat. Forschung braucht Daten, aber Patienten wollen nicht gläsern sein.  
**miTch:** Selektive Freigabe einzelner Gesundheitsdaten. Break-Glass für Notfälle. Forschung nur mit HDAB-Permit.  
**Regulierung:** EHDS (2025), DSGVO Art. 9 (Gesundheitsdaten = besondere Kategorie).  
**Machbarkeit:** ⭐⭐⭐⭐ — EHDS-Features bereits implementiert (12 Tasks done).  
**Markt:** EU-weit verpflichtend ab ~2028. Jedes Krankenhaus, jede Praxis, jede Apotheke.

### 3. Digitaler Führerschein / Fahrzeugverifikation
**Problem:** Mietwagen-Firma will wissen: "Darf diese Person Auto fahren?" Aktuell: Führerschein-Kopie mit Adresse, Geburtsdatum, Augenfarbe, etc.  
**miTch:** Proof: "Hat Klasse B Führerschein, gültig" — sonst nichts.  
**Regulierung:** ISO 18013-5 (mDL) ist genau dafür. EUDI-Wallet wird das nativ unterstützen.  
**Machbarkeit:** ⭐⭐⭐⭐ — Braucht ISO 18013-5 / mdoc Support (E-11 im Backlog).  
**Markt:** Jeder EU-Bürger mit Führerschein. Car-Sharing, Mietwagen, Versicherungen.

### 4. Bildungsnachweise / Micro-Credentials
**Problem:** Arbeitgeber will wissen: "Hat diese Person einen Master in Informatik?" Aktuell: Zeugniskopie mit allen Noten, Geburtsdatum, Matrikelnummer.  
**miTch:** Proof: "Hat Abschluss X von Uni Y" — ohne Notenspiegel, ohne persönliche Details.  
**Regulierung:** EU Digital Credentials for Learning (2024). Europass Digital Credentials.  
**Machbarkeit:** ⭐⭐⭐⭐ — SD-JWT passt perfekt. Issuer = Uni, Verifier = Arbeitgeber.  
**Markt:** 20M+ Studierende in der EU. LinkedIn drängt in den Bereich, aber zentralisiert.

### 5. Finanzwesen / KYC (Know Your Customer)
**Problem:** Bankkonto eröffnen = kompletter Identitätsnachweis. Jede Bank speichert eine vollständige Kopie deiner Daten. Datenlecks = Identitätsdiebstahl.  
**miTch:** Stufenweise Verifikation. Stufe 1: "Ist EU-Bürger, über 18". Stufe 2: "Name + Adresse" (nur wenn regulatorisch nötig). Stufe 3: Vollständig (nur bei Verdacht).  
**Regulierung:** Anti-Geldwäsche-Richtlinie (AMLD6), PSD3, eIDAS 2.0.  
**Machbarkeit:** ⭐⭐⭐ — KYC hat strikte regulatorische Anforderungen die Minimierung erschweren.  
**Markt:** Jede Bank, jeder Finanzdienstleister, jede Kryptobörse.

### 6. Behördengänge / E-Government
**Problem:** Jeder Behördengang = komplette Identifikation, oft redundant. Meldeamt weiß alles, Finanzamt weiß alles, KFZ-Stelle weiß alles — und die Daten sind nicht verknüpft (gut) aber der Bürger muss sie immer wieder neu vorlegen (schlecht).  
**miTch:** Selektive Nachweise pro Behörde, pro Zweck. Standesamt braucht andere Daten als KFZ-Zulassung.  
**Regulierung:** OZG 2.0 (Online-Zugangs-Gesetz), EUDI-Wallet, SDG (Single Digital Gateway).  
**Machbarkeit:** ⭐⭐⭐ — Braucht OID4VP + staatliche Issuer-Integration.  
**Markt:** 450M EU-Bürger. Jede Behörde.

---

## Tier 2 — Starker Use Case (braucht Erweiterung)

### 7. Arbeitsmarkt / Berechtigungsnachweise
**Problem:** Handwerker muss Meisterbrief zeigen. Arzt muss Approbation nachweisen. Security-Personal braucht Unbedenklichkeitsbescheinigung. Aktuell: Papierkopien, leicht fälschbar.  
**miTch:** Kryptografisch verifizierbare Berufsnachweise. "Ist approbierter Arzt, gültig bis 2028."  
**Machbarkeit:** ⭐⭐⭐⭐ — Direkte Erweiterung der Bildungsnachweise.  
**Markt:** Jede regulierte Berufsgruppe. Handwerk, Medizin, Recht, Sicherheit.

### 8. Supply Chain / Lieferkettengesetz
**Problem:** EU-Lieferkettengesetz (CSDDD) verlangt Nachweise über Arbeitsbedingungen, Umweltstandards in der gesamten Kette. Lieferanten wollen aber nicht ihre kompletten Geschäftsdaten offenlegen.  
**miTch:** Selektive Compliance-Nachweise. "Dieser Lieferant erfüllt ILO-Standard X" — ohne interne Kalkulationen preiszugeben.  
**Regulierung:** CSDDD (2024), EU-Entwaldungsverordnung, Konfliktmineralien-Verordnung.  
**Machbarkeit:** ⭐⭐⭐ — Braucht B2B-Credential-Format, nicht nur Personen-Credentials.  
**Markt:** Jedes Unternehmen mit EU-Lieferkette.

### 9. IoT / Smart Home / Connected Devices
**Problem:** Dein Smart TV, dein Auto, dein Kühlschrank — alle senden Daten an Hersteller. Firmware-Updates verlangen Geräte-Identifikation. Hersteller wissen wann du fernsiehst.  
**miTch:** Device Credentials mit Selective Disclosure. "Dieses Gerät ist berechtigt für Update X" — ohne User-Profiling.  
**Machbarkeit:** ⭐⭐ — Braucht Device-level Credential Management, anderes Threat Model.  
**Markt:** 30+ Milliarden IoT-Geräte weltweit bis 2030.

### 10. Wahlen / E-Voting / Abstimmungen
**Problem:** Online-Abstimmungen (Vereinsversammlungen, Aktionärsmeetings, Bürgerbegehren) brauchen: Berechtigung prüfen + Anonymität garantieren.  
**miTch:** "Ist stimmberechtigtes Mitglied" als Proof — ohne zu wissen WER gestimmt hat. Unlinkability ist hier CORE.  
**Machbarkeit:** ⭐⭐⭐ — Technisch machbar, politisch hochsensibel. Nicht für Bundestagswahlen, aber für Vereins-/Unternehmensabstimmungen realistisch.  
**Markt:** Jeder Verein, jede AG, jede Genossenschaft. Pilotprojekte in Estland, Schweiz.

### 11. Versicherungen
**Problem:** Versicherungsantrag = komplette Gesundheitsakte offenlegen. Versicherung weiß mehr über dich als dein Arzt.  
**miTch:** "Hat keine Vorerkrankung in Kategorie X" — ohne die komplette Akte.  
**Machbarkeit:** ⭐⭐⭐ — Versicherungen werden Widerstand leisten (weniger Daten = schlechtere Risikomodelle).  
**Markt:** Hunderte Milliarden €. Aber: Adoption braucht regulatorischen Druck.

### 12. Reisen / Grenzkontrollen
**Problem:** Flughafen-Kontrolle = Pass scannen = komplette Identität + Reisehistorie. Airlines speichern PNR-Daten 5+ Jahre.  
**miTch:** "Ist EU-Bürger, kein Einreiseverbot" — ohne Name und Geburtsdatum an die Airline.  
**Regulierung:** EUDI-Wallet soll auch für Reisen nutzbar sein. ICAO DTC (Digital Travel Credential).  
**Machbarkeit:** ⭐⭐ — Hohe regulatorische Hürden, Sicherheitsbehörden wollen MEHR Daten, nicht weniger.  
**Markt:** Milliarden Reisende/Jahr.

### 13. Digitale Signaturen / Verträge
**Problem:** Qualified Electronic Signatures (QES) brauchen volle Identifikation. Für viele Verträge reicht aber "ist geschäftsfähig und bevollmächtigt".  
**miTch:** Abgestufte Signaturen. Einfache Signatur: Pseudonym + Nachweis der Geschäftsfähigkeit. QES nur wenn rechtlich nötig.  
**Regulierung:** eIDAS 2.0 Artikel 3 (elektronische Signaturen).  
**Machbarkeit:** ⭐⭐⭐ — Trust Service Provider Integration nötig.  
**Markt:** DocuSign, Adobe Sign — aber alle zentralisiert.

---

## Tier 3 — Zukunftsmusik (realistisch, aber braucht Ökosystem)

### 14. Social Media / Plattform-Zugang
**Problem:** Plattformen fordern zunehmend Identitätsnachweis (EU Digital Services Act). Aktuell: Ausweiskopie an Meta schicken. Dystopie.  
**miTch:** "Ist reale Person, über 16, EU-Bürger" — ohne Name, ohne Gesicht, ohne Adresse.  
**Regulierung:** DSA (2024), EU AI Act (für Deepfake-Kennzeichnung).  
**Machbarkeit:** ⭐⭐ — Plattformen müssten miTch-kompatibel werden. Braucht kritische Masse.  
**Markt:** 4+ Milliarden Social-Media-Nutzer.

### 14b. Phone Number Verification (mi.call)
**Problem:** Telefonnummern sind das universelle Login-Token (WhatsApp, Signal, 2FA). Jeder Service speichert die Nummer, Cross-Service Tracking ist trivial. Telcos sehen wer sich wo anmeldet.  
**miTch:** Privacy Layer vor bestehenden Telco-APIs (GSMA Mobile Connect, CAMARA Number Verify, A1/Magenta Silent Auth). Service bekommt: `has_verified_phone: true` + pairwise pseudonymous ID. Nicht die Nummer.  
**Partner:** GSMA Open Gateway, A1 Digital Identity, Magenta/CAMARA, ID Austria (Handy-Signatur als Credential-Basis).  
**Regulierung:** GDPR Art. 25, ePrivacy Directive, EECC (European Electronic Communications Code).  
**Machbarkeit:** ⭐⭐⭐ — Telco-APIs existieren schon. miTch muss sich nur davor setzen. Braucht einen Telco-Partner.  
**Markt:** 8+ Milliarden Mobilfunkverträge weltweit. Jede 2FA-Implementierung ist ein potenzieller Kunde.  
**Notiz:** Tier 3 — erst nach funktionierendem Pilot und echten Partner-Gesprächen. Siehe Social Login Use Case als Vorbild für die Architektur.

### 15. Dezentrale Marktplätze / Sharing Economy
**Problem:** Airbnb, eBay, Vinted — Vertrauen zwischen Fremden braucht Identifikation. Aber Airbnb weiß alles über Host UND Gast.  
**miTch:** Host verifiziert: "Gast ist volljährig + hat positive Bewertungshistorie" — ohne echten Namen.  
**Machbarkeit:** ⭐⭐ — Reputation-System + Selective Disclosure ist ein offenes Forschungsfeld.  
**Markt:** Sharing Economy = $500B+ bis 2030.

### 16. Journalismus / Whistleblowing
**Problem:** Quellenschutz ist existenziell. Aber Journalisten müssen die Glaubwürdigkeit von Quellen verifizieren.  
**miTch:** "Diese Person arbeitet bei Unternehmen X auf Ebene Y" — ohne Name, ohne Abteilung.  
**Machbarkeit:** ⭐⭐⭐ — Technisch direkt machbar. Adoption: Journalisten sind keine Early Adopters.  
**Markt:** Klein aber gesellschaftlich hochrelevant. Pressefreiheit.

### 17. Gaming / Metaverse / Digitale Identität
**Problem:** Spieler müssen für Altersfreigabe, In-Game-Käufe und Anti-Cheat ihre Identität nachweisen. Publisher bauen massive Profile.  
**miTch:** "Spieler ist über 18 + hat bezahlt" — ohne echte Identität. Jeder Spieler sieht gleich aus für den Publisher.  
**Machbarkeit:** ⭐⭐ — Gaming-Industrie hat wenig Anreiz, Daten aufzugeben.  
**Markt:** $200B+ Industrie.

### 18. Humanitäre Hilfe / Flüchtlinge
**Problem:** Menschen ohne Papiere brauchen Zugang zu Hilfe, Gesundheitsversorgung, Bildung. Traditionelle ID-Systeme schließen sie aus.  
**miTch:** Verifiable Credentials die nicht an einen Staat gebunden sind. "Diese Person hat Anspruch auf medizinische Versorgung" — ausgestellt von UNHCR/Rotes Kreuz.  
**Machbarkeit:** ⭐⭐ — Infrastruktur fehlt in Krisengebieten. Kein Smartphone = kein Wallet.  
**Markt:** 100M+ Vertriebene weltweit. Gesellschaftlich extrem relevant.

### 19. Forschungsdaten / Open Science
**Problem:** Forscher brauchen Zugang zu sensiblen Datensätzen (Gesundheit, Soziales, Kriminalität). Aktuell: langwierige Ethik-Anträge, dann Vollzugriff oder gar nichts.  
**miTch:** Granulare Datenfreigabe. Forscher bekommt nur die Felder die er für seine Hypothese braucht. Audit-Trail zeigt was analysiert wurde.  
**Machbarkeit:** ⭐⭐⭐ — Passt perfekt zu Controlled Insight (Phase 4).  
**Markt:** Jede Universität, jedes Forschungsinstitut, Pharma-Industrie.

### 20. Telekommunikation / SIM-Registrierung
**Problem:** EU-weit SIM-Karten-Registrierungspflicht. Aktuell: Ausweiskopie an Vodafone. Datenlecks = SIM-Swap-Angriffe.  
**miTch:** "Ist identifizierte Person" — ohne den Ausweis zu kopieren. Bei SIM-Swap: Verifier-Fingerprint erkennt Anomalie.  
**Regulierung:** Nationale Telekom-Gesetze, eIDAS 2.0.  
**Machbarkeit:** ⭐⭐⭐ — Telcos sind reguliert und technisch fähig.  
**Markt:** Jeder Mobilfunkvertrag in der EU.

---

---

## Tier 4 — Unterschätzt aber real

### 21. Wohnungsmarkt / Mietbewerbung
**Problem:** Vermieter verlangen: Schufa, Gehaltsnachweis, Arbeitgeberbescheinigung, Personalausweis. Komplette finanzielle Entblößung für eine Wohnungsbesichtigung.  
**miTch:** "Einkommen > 3x Kaltmiete, keine negativen Schufa-Einträge, unbefristetes Arbeitsverhältnis" — ohne Kontoauszüge, ohne Gehaltszahl, ohne Arbeitgeber-Name.  
**Machbarkeit:** ⭐⭐⭐⭐ — Schufa/Creditreform müssten als Issuer fungieren.  
**Markt:** Jede Mietbewerbung in Deutschland. Millionen/Jahr.

### 22. Anti-Diskriminierung bei Bewerbungen
**Problem:** Anonymisierte Bewerbungen scheitern in der Praxis. Arbeitgeber sehen Foto, Name, Alter, Geschlecht — und diskriminieren (bewusst oder unbewusst).  
**miTch:** "Hat Qualifikation X, Y Jahre Erfahrung in Bereich Z" — ohne Name, Alter, Geschlecht, Herkunft, Foto. Erst nach Einladung zum Gespräch wird mehr geteilt.  
**Machbarkeit:** ⭐⭐⭐ — Technisch trivial, kulturell schwer.  
**Markt:** Jedes Unternehmen das AGG-konform sein will.

### 23. Dating / Social Matching
**Problem:** Dating-Apps wissen alles: Standort, Präferenzen, Chatverläufe, Gesundheitsstatus. Profile sind oft gefälscht.  
**miTch:** Verifiziert: "Ist reale Person, Altersbereich 25-35, keine Vorstrafen" — ohne echten Namen bis zum Match.  
**Machbarkeit:** ⭐⭐ — Dating-Apps verdienen an Daten, wenig Anreiz.  
**Markt:** $6B+ global. Tinder, Bumble, Hinge.

### 24. Klinische Studien / Pharma
**Problem:** Patienten für Studien rekrutieren erfordert medizinische Vorab-Screening mit sensiblen Daten. Viele melden sich nicht aus Angst vor Datenmissbrauch.  
**miTch:** "Patient hat Diagnose X, Altersgruppe Y, keine Kontraindikation Z" — Pharmafirma sieht genug für Einschluss, aber nicht die Identität.  
**Machbarkeit:** ⭐⭐⭐ — Passt perfekt zu EHDS Secondary Use.  
**Markt:** Pharma-Industrie: $1.5T global. Klinische Studien: $80B+.

### 25. Parkausweise / Behindertenausweis / Sozialleistungen
**Problem:** Behindertenausweis zeigt: Name, Foto, Art der Behinderung, Grad. Beim Parken auf Behindertenparkplatz sieht jeder Passant alles.  
**miTch:** "Hat Berechtigung für Behindertenparkplatz" — ohne Art oder Grad der Behinderung.  
**Machbarkeit:** ⭐⭐⭐⭐ — Einfacher Use Case, hoher gesellschaftlicher Wert.  
**Markt:** 7.8M Schwerbehinderte allein in Deutschland.

### 26. Energie / Smart Grid / Einspeisevergütung
**Problem:** Solaranlagen-Besitzer müssen sich gegenüber Netzbetreiber komplett identifizieren für Einspeisevergütung. Smart Meter senden Verbrauchsprofile.  
**miTch:** "Anlage X produziert Y kWh" — ohne Haushalts-Verbrauchsprofil offenzulegen.  
**Machbarkeit:** ⭐⭐ — IoT-Credential + Energieregulierung.  
**Markt:** Jeder Prosumer in der EU. Millionen Solaranlagen.

### 27. Kinderschutz / Elterliche Zustimmung
**Problem:** DSGVO Art. 8: Unter-16-Jährige brauchen Elternzustimmung für Online-Dienste. Aktuell: "Klick hier dass du 16 bist" — wirkungslos.  
**miTch:** Proof: "Elternteil hat Zustimmung für Kind erteilt für Dienst X" — ohne Identität des Kindes an den Dienst.  
**Machbarkeit:** ⭐⭐⭐ — Delegation-Credential (Eltern→Kind).  
**Markt:** Jedes Kind mit Smartphone in der EU.

### 28. Treueprogramme ohne Tracking
**Problem:** Payback, Miles & More, etc. = totale Verhaltensüberwachung im Tausch gegen Punkte.  
**miTch:** "Dieser Nutzer hat 10 Käufe getätigt" — Punkte ohne Verhaltensprofil. Unlinkable Loyalty.  
**Machbarkeit:** ⭐⭐ — Loyalty-Programme SIND das Tracking. Business Model Conflict.  
**Markt:** $200B+ Loyalty-Industrie.

### 29. Physischer Zugang / Gebäude / Events
**Problem:** Konzert-Ticket = Name + oft Ausweis am Eingang. Fitnessstudio = Foto + Adresse + Bankverbindung.  
**miTch:** "Hat gültiges Ticket für Event X" oder "Hat aktive Mitgliedschaft" — ohne Identität.  
**Machbarkeit:** ⭐⭐⭐ — NFC/QR + Selective Disclosure.  
**Markt:** Jedes Konzert, jedes Stadion, jedes Fitnessstudio.

### 30. Digitaler Nachlass / Erbschaft
**Problem:** Wenn jemand stirbt: Wer hat Zugang zu den digitalen Konten? Erben müssen Sterbeurkunde + Erbschein + Vollmacht an jeden einzelnen Dienst schicken.  
**miTch:** "Person X ist berechtigter Erbe für Konto Y" — ausgestellt vom Nachlassgericht, verifizierbar ohne den ganzen Erbschein.  
**Machbarkeit:** ⭐⭐ — Juristisch komplex, aber technisch direkt machbar.  
**Markt:** Wächst mit der Digitalisierung. Jeder Todesfall betrifft dutzende Online-Konten.

---

## Zusammenfassung

| Tier | Bereiche | Gemeinsamer Nenner |
|---|---|---|
| 1 (Now) | Alter, Gesundheit, Führerschein, Bildung, KYC, E-Gov | Person → Verifier: "Ich beweise X ohne Y zu zeigen" |
| 2 (Next) | Arbeit, Supply Chain, IoT, Voting, Versicherung, Reisen, Signaturen | Erweitertes Trust-Modell: B2B, Devices, Gruppen |
| 3 (Future) | Social Media, Sharing, Journalismus, Gaming, Humanitär, Forschung, Telco | Ökosystem-Adoption nötig, gesellschaftlicher Impact |
| 4 (Unterschätzt) | Wohnung, Anti-Diskriminierung, Dating, Pharma, Behindertenausweis, Energie, Kinderschutz, Loyalty, Events, Nachlass | Alltagsprobleme wo Overidentification Standard ist |

**Das Muster:** Überall wo heute jemand sagt "Zeig mir deinen Ausweis" kann miTch sagen "Ich beweise dir was du brauchst — aber du erfährst nicht wer ich bin."

---

> *"Alle sind miTch" ist nicht nur ein Privacy-Statement. Es ist ein neues Paradigma für digitale Interaktion.*
