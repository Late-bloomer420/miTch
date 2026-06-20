# miTch — Grenzen zu den EU-Systemen (Fundament)

**Status: Bindend | Stand: 2026-06-15 | Alle Aussagen belegt**

> **Zweck.** Bevor miTch sich positioniert, muss exakt feststehen, **wie weit die proven
> EU-Schienen reichen — und wo sie aufhören.** Wir wollen nicht *darüber* oder *dagegen*,
> sondern **daneben**: dort ansetzen, wo die EU-Systeme strukturell aufhören. Dieses
> Dokument benennt die Grenzen und belegt sie. Es ist das Fundament für Positionierung,
> Pilot und Zertifizierungs-Narrativ.

> **Leitsatz.** Alle drei EU-Systeme sind **Holder-/Presentation-Rails** — sie ermöglichen
> es, etwas *nachzuweisen* (Identität, Alter, Firmen-Status). **Keines** von ihnen regelt
> oder erzwingt, was der Verifier **nach** der Offenlegung mit den Daten tut. Genau diese
> Grenze ist miTchs Feld (Convener: Zweckbindung, Enforcement, neutrale Sichtbarmachung).

---

## 1. EUDI Wallet (European Digital Identity Wallet) — eIDAS 2.0

**Rechtsgrundlage:** Verordnung (EU) 2024/1183 (eIDAS 2.0), in Kraft seit Mai 2024.

**Was es tut / wie weit es geht:**
- Sichere mobile App für natürliche **und juristische** Personen, um Credentials zu
  speichern, verwalten und **selektiv vorzulegen**: nationale eID, mDL (Führerschein),
  Diplome, Berufsqualifikationen, Gesundheits-Credentials, Bankkonto-Attribute u. a.
- Level of Assurance **High**; Authentifizierung gegenüber öffentlichen und (große) privaten
  Diensten.
- **Pflicht:** alle 27 Mitgliedsstaaten müssen Bürgern/Residenten bis **Ende 2026** ein
  Wallet bereitstellen (EEA: +1 Jahr). Große Online-Plattformen und regulierte Sektoren
  (Banking, Health, Telecom) müssen das Wallet bis **Ende 2027** als Authentifizierung
  akzeptieren.
- Realität (06/2026): **weniger als ein Drittel** der MS erreicht den Readiness-Benchmark;
  DE-Sandbox seit Jan 2026, erste öffentliche Stufe erst ~Anfang 2027.

**Wo es STOPPT (die Grenze):**
- Es ist die **Vorlage-Schiene** (Issuer → Holder → Verifier-Protokoll, OID4VP/SD-JWT/mdoc).
  Es regelt **nicht**, was der Verifier *danach* darf — keine Zweckbindungs-Durchsetzung,
  kein Verifier-Overreach-Schutz, kein Nutzer-Audit-Trail über *wer wann was* abgefragt hat.
- Bekannte **Unlinkability-Schwäche** im aktuellen ARF (Geräte-/WIA-Korrelation) — nicht als
  harte Abhängigkeit behandeln.

**miTch daneben:** Policy-Layer für *„was darf der Verifier nach dem Proof"* + neutrale
Sichtbarmachung für den Nutzer. Auth-Layer so bauen, dass EUDIW *anschließbar* ist, ohne harte
Abhängigkeit (Invariante: User = Root of Trust, nicht die Plattform).

---

## 2. EU Age Verification App (white-label Mini-Wallet)

**Wer:** T-Scy Consortium (Scytáles AB + T-Systems International), EC-Auftrag. Basiert auf der
EUDI-ARF. **Rechtlicher Treiber:** DSA Art. 28 (Schutz Minderjähriger).

**Was es tut / wie weit es geht:**
- Datenschutz-erhaltender Nachweis **`age_over_18`** (Blueprint nennt auch jüngere Schwellen
  13/15) — ohne Ausweis-Upload, ohne weitere personenbezogene Daten.
- ~30 **Single-Use**-Attestationen lokal; kostenlos für Nutzer und Plattformen.
- **Feature-ready: 15. April 2026.** Pilotländer: FR, ES, DK, GR, IT. EC-Empfehlung: Deployment
  bis **31.12.2026**; in allen 27 MS bis **Jan 2027** — ab dann wertet die EC das Fehlen eines
  gleichwertigen Mechanismus als möglichen DSA-Verstoß.

**Wo es STOPPT (die Grenze):**
- Löst **genau ein Prädikat** (Alter). Keine Cross-Prädikate (z. B. `age_over_18` +
  `residency_DE` + `self_exclusion_check`, wie regulierte Märkte sie brauchen).
- **Kein Revocation-Support** (Single-Use als Workaround). ZKP ist im Blueprint
  *„should", nicht „must"* — nationale Implementierungen dürfen pseudonym sein.
- Hört beim Alters-Nachweis auf. Was die Plattform danach speichert/verknüpft, ist **nicht**
  Teil des Systems. Digitale Exklusion (kein amtlicher Ausweis) ungelöst (EFF-Kritik).

**miTch daneben:** Die EU-App löst `age_over_X`. miTch löst *„was danach"* — Zweckbindung,
Cross-Prädikat-Policy für regulierte Märkte, WORM-Log + Crypto-Shredding als Compliance-Beleg.
**Nicht konkurrieren, ergänzen.**

---

## 3. EU Business Wallet (EUDI für juristische Personen) — VORSCHLAG

**Status (Honesty-Check):** **Noch kein geltendes Recht.** Kommissionsvorschlag, Teil der
„**EU Inc.**"-Initiative (pan-europäische Rechtsform + Business Wallet). Einigung von Parlament
und Rat **bis Ende 2026** angestrebt; volle Binnenmarkt-Vision **operativ ~2028**. Baut auf
eIDAS 2 auf.

**Was es tun soll / wie weit es geht:**
- Credential mit **Firmen-Identität, Eigentümerstruktur, Rechtsstatus**, auf Anfrage mit
  Behörden in allen 27 MS teilbar.
- Digitalisierung von Geschäftsabläufen: Dokumente **signieren, zeitstempeln, siegeln**;
  verifizierte Dokumente erstellen/speichern/austauschen; sichere B2B-/B2G-Kommunikation über
  Staatsgrenzen.
- EC-Schätzung: bis zu **150 Mrd. €/Jahr** Einsparung für Unternehmen.

**Wo es STOPPT (die Grenze):**
- Identitäts- und Dokumenten-Schiene für **Firmen** (wer ist das Unternehmen, ist das Dokument
  echt/gesiegelt). Es ist **kein** Verbraucher-Datenschutz-Enforcement-Layer und regelt **nicht**
  die Datenminimierung *gegenüber dem Endnutzer* im nachgelagerten Verifier-Verhalten.

**miTch daneben:** Auf der Verifier-Seite ist die Business Wallet der *Identitätsnachweis des
Unternehmens*; miTch ist der **Nachweis, dass dieses Unternehmen DSGVO-konform verarbeitet**
(B2B-Compliance-Nachweis gegenüber DPA — eine der im Markt offenen Lücken).

---

## Die Grenze in einer Zeile

```
EUDI Wallet        →  WER bist du / WAS hältst du.            (Identitäts-/Vorlage-Rail)
EU Age App         →  bist du über 18.                        (1 Prädikat, DSA)
EU Business Wallet →  WER ist das Unternehmen (Vorschlag).    (Firmen-Identitäts-Rail)
─────────────────────────────────────────────────────────────────────────────────────
                      ↑ alle drei STOPPEN bei der Offenlegung ↑
miTch (daneben)    →  was darf der Verifier DANACH + mach es für den Nutzer SICHTBAR.
```

Das deckt sich mit der bereits belegten Lücken-Tabelle in [`04_MARKET.md`](04_MARKET.md):
Verifier-Side Compliance-Layer, Policy-Enforcement gegen Overreach, Cross-Predicate-Proofs,
User-Audit-Trail, B2B-Compliance-Nachweis — **keines** davon lösen die drei EU-Schienen.

---

## Entschiedene Richtung (Stand 2026-06-15)

- **Entscheidung 1 (Produktfokus): A **und** B.** Verifier-Side Compliance-as-a-Service (A)
  *und* User-Side Selbstkenntnis/Sichtbarmachung (B) — parallel.
- **Entscheidung 2 (Positionierung): daneben, nicht darüber/dagegen.** miTch ergänzt die proven
  EU-Schienen am Punkt, an dem sie strukturell aufhören. „Comparable to something proven" heißt:
  die EU-Schienen *sind* das Proven, miTch ist die orthogonale Governance-/Visibility-Schicht.
- **Nächster konkreter Schritt (gewünscht, noch nicht gebaut):** **Layer-2-Visibility** — eine
  **neutrale, lokale Sichtbarmachung für jeden Nutzer** (Layer 2 = `02-erwachsene-vulnerable`):
  klare, wertungsfreie Einschätzung dessen, was abgefragt/offengelegt/zurückgehalten wurde.
  *Neutral* = Transparenz, kein Reputations-Scoring (das wäre „Features um Features").

---

## Quellen (belegt)

- eIDAS 2.0 — Verordnung (EU) 2024/1183: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=legissum:4812147
- EUDI-Regulation (EC, Shaping Europe's digital future): https://digital-strategy.ec.europa.eu/en/policies/eudi-regulation
- EUDI Wallet 2026 Deadline/Rollout (Corbado): https://www.corbado.com/blog/eudi-wallet-2026-deadline-rollout-eic-2026
- Age-Verification-Blueprint (EC): https://digital-strategy.ec.europa.eu/en/news/commission-releases-enhanced-second-version-age-verification-blueprint
- White-label Age-Verification-App, Analyse (Biometric Update, 04/2026): https://www.biometricupdate.com/202604/breaking-down-the-european-commissions-white-label-age-verification-app
- EU Business Wallet / „EU Inc." (Biometric Update, 04/2026): https://www.biometricupdate.com/202604/eu-business-lobby-backs-digital-wallet-plan-calls-for-proportionate-identity-rules
- EU Business Wallet ↔ Unternehmensregistrierung (Reclaim The Net): https://reclaimthenet.org/eu-proposal-links-european-business-registration-to-digital-id-wallets

*Vorhandene Repo-Belege: [`04_MARKET.md`](04_MARKET.md) (Stand 02.05.2026), [`../vision/REGULATORY_CALENDAR.md`](../vision/REGULATORY_CALENDAR.md), [`../04-legal/certification_readiness_mapping.md`](../04-legal/certification_readiness_mapping.md).*
