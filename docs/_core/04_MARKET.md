# miTch Marktlage — Wettbewerb & Lücken

**Stand: 02.05.2026 | Alle Aussagen belegt**

---

## Was bereits beauftragt / deployed ist

### EU Age Verification Blueprint (LIVE)
- **Wer:** T-Scy Consortium (Scytales AB + T-Systems International), EC-Vertrag seit Q1 2025
- **Was:** Open-Source Mini-Wallet, zkSNARK-basiert (Frigo & Shelat, 2024), ~30 Single-Use Attestationen lokal
- **Scope:** `age_over_18 / 15 / 13` für Online-Plattformen (DSA Art. 28)
- **Rollout:** Feature-ready 15. April 2026; FR, DK, GR, IT, ES, CY, IE als Pilot; alle 27 Staaten bis Jan 2027
- **Preis:** Kostenlos für Nutzer und Plattformen (steuerfinanziert)

### Digital Euro Offline-Lösung (IN DEVELOPMENT)
- **Wer:** G+D + Nexi + Capgemini, ECB Framework Agreement seit Oktober 2025
- **Was:** P2P-Offline-Zahlung, "cash-like privacy" (keine Aufzeichnung durch Bank/PSP/ECB)
- **Timeline:** Gesetzgebung 2026 notwendig → Pilot frühestens 2027 → Issuance frühestens **2029**
- **Kritik:** Online-Variante nutzt pseudonymisierte Zentraldatenbank (CNIL: unzureichend)

### EUDIW Large Scale Pilots (LAUFEND)
- **Umfang:** 550 Organisationen, 26 Mitgliedsstaaten + NO, IS, UA
- **Konsortien:** WE BUILD (197 Teilnehmer), DC4EU, POTENTIAL, NOBID, EUDI4ALL, FIDES
- **Use Cases:** Bankkonto eröffnen, SIM-Karte registrieren, mobiler Führerschein (mDL)
- **Deadline:** September 2026 für alle Mitgliedsstaaten

---

## Was NICHT beauftragt / NICHT gelöst ist

| Lücke | Warum relevant |
|---|---|
| **Verifier-Side Compliance Layer** | EU-App prüft Alter — aber wer stellt sicher, dass Verifier danach DSGVO-konform handeln? |
| **Policy Enforcement gegen Verifier-Overreach** | Kein Mechanismus im EUDIW-Ökosystem |
| **Cross-Predicate Proofs** | Sportwetten braucht: `age_over_18` + `residency_DE` + `self_exclusion_check` — kein Standard |
| **User Audit Trail** | Nutzer weiß nicht, wer wann was abgefragt hat |
| **B2B Compliance-Nachweis** | Wie weist eine Plattform gegenüber DPA nach, dass sie DSGVO-konform verarbeitet? |
| **Business Model für Ökosystem** | EUDIW "needs a sustainable business model" (Biometric Update, Okt 2025) — explizit offen |
| **Regulated Markets** | Sportwetten, Health, Adult Content: Compliance geht weit über `age_over_X` hinaus |

---

## Limitierungen der EU Age Verification App (belegt)

- ZKP ist **"should implement"**, nicht **"must"** — nationale Implementierungen können pseudonymous sein
- Kein Revocation Support (Single-Use als Workaround)
- Kein physischer POS definiert
- Digitale Exklusion: Geflüchtete, Menschen ohne amtlichen Ausweis (EFF-Kritik)

---

## Wo miTch einzigartig ist

```
EU Age Verification App:    User → Credential → Plattform
                            STOP. Plattform macht danach was sie will.

miTch:                      User → Credential → Policy Engine → Plattform
                            Policy Engine erzwingt, was Plattform darf.
                            WORM-Log dokumentiert, was passiert ist.
                            Crypto-Shredding belegt, was nicht gespeichert wurde.
```

---

## Zahlungsbereitschaft nach Segment (Einschätzung)

| Segment | Bereitschaft | Begründung |
|---|---|---|
| Sportwetten-Plattformen | **Hoch** | GlüStV-Auflagen, aktives Regulator-Enforcement, DSGVO-Bußgelder bis 4% Umsatz |
| Adult Content Plattformen | **Mittel-Hoch** | DSA Art. 28 Enforcement; Frankreich hat Pornhub 2024 geblockt |
| Health / Telemedicine | **Hoch** | DSGVO Art. 9 Sonderкатегorie; kein gutes Marktangebot |
| Alkohol / Tabak Online-Retail | **Mittel** | JuSchG-Auflagen, Bußgelder existent |
| KMU allgemein | **Niedrig** | EU-App kostenlos; Integration zu komplex |

---

## Förderungsmöglichkeiten (zu prüfen)

- **Digital Europe Programme (DEP)** — explizit für digitale Identität, Privacy-Tech
- **Horizon Europe** — mit akademischem Partner (z.B. Uni Innsbruck)
- **FFG Digital** (AT) / **BMBF** (DE) — nationale Programme

---

*Quellen: commission.europa.eu, ageverification.dev, nexigroup.com/ecb, biometricupdate.com, eff.org — vollständige Quellliste in der Analyse-Session vom 02.05.2026*
