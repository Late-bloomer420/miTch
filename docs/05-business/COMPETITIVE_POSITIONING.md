# AskMI / miTch: Wettbewerbs-Positionierung gegenüber klassischen Identity-Verification-Anbietern

Stand: 2026-10-28; ergänzt 2026-11-20 (§2a belegte Anbieterbeispiele, §3 API-Stand nach #312)
Status: Entwurf (Draft) zur Diskussion; keine rechtliche oder regulatorische Bewertung; keine unabhängig verifizierte Marktstudie.
Zielgruppe: Gründer, Marketing (gemäß `docs/05-business/marketing/07-messaging-rules.md`), Pitch-Unterlagen.

---

## 0. Warum dieses Dokument existiert

Bisher war die Wettbewerbsdifferenzierung im Repo nur an drei schwachen Stellen verankert:

1. Eine unbelegte Zeile in `docs/00-welt/application_domains.md:15`
   („Yoti, Veriff, IDnow sind die Incumbents — alle sammeln zu viele Daten") — Behauptung ohne
   Quelle. Die Zeile ist dort jetzt als unbelegte These markiert und verweist auf dieses Dokument;
   belegt ist sie damit nicht.
2. Quellenmarkierte Kostenannahmen in der Demo/Landingpage
   (`site/index.html`, `docs/BACKLOG.md` CL-02) — ein Kostenmodell, keine Wettbewerbsanalyse.
3. Eine „Konkurrenz-Matrix" nur in Präsentationscode
   (`src/packages/poc-hardened/src/server.ts`) — nicht in der Doku.

Dieses Dokument ersetzt keine dieser Stellen kommentarlos, sondern liefert eine erste
nachvollziehbare Positionierung. **Alle Aussagen über Wettbewerber basieren auf deren
öffentlichen Selbstdarstellungen und sind als solche gekennzeichnet; sie sind nicht
unabhängig verifiziert und müssen vor jeder externen Verwendung einzeln gegengeprüft
werden.**

---

## 1. Kategorie-Unterschied vor Anbieter-Unterschied

Die Differenzierung ist primär **architektonisch**, nicht nur eine Frage der Datensparsamkeit
im Geschäftsmodell:

| | Klassische Identity Verification (IDnow, Veriff, Yoti, Jumio, Onfido) | AskMI / miTch |
|---|---|---|
| Frage, die beantwortet wird | „Wer bist du?" (Vollidentifizierung) | Zielbild: „Reicht dir nicht auch ein minimaler Proof?" (z. B. „über 18: Ja/Nein"). Die Wallet legt seit #312 nur policy-freigegebene Claims offen (API-02); der Verifier sieht im aktiven Profil weiterhin das numerische Alter (#97) |
| Rolle im System | Verifizierer/Vertrauensdienst, der personenbezogene Daten verarbeitet | Policy-Vermittlungsschicht zwischen Wallet und Verifier; keine Identitätsverwahrung |
| Wo die Daten liegen | Zentral beim Anbieter/Verifier (Dokumentkopien, Biometrie-Match in der Cloud) | Am Gerät (Edge), AES-256-GCM-verschlüsselt; Crypto-Shredding flüchtiger Materialien |
| Biometrie | Remote Biometric Match (Cloud-Dienst, kostenpflichtig) | Geräte-lokal (WebAuthn / Face ID); biometrische Daten verlassen das Gerät nicht. Die serverseitige WebAuthn-Signaturprüfung ist seit #312 umgesetzt (API-05d); das Paket ist nicht im aktiven Pfad |
| Standardisierung | Proprietäre Prozesse plus eIDAS-/Gesetzes-Konformanz (VideoIdent, eID) | Zielbild: offene Standards (OID4VCI, OID4VP, SD-JWT, ISO 18013-5 mdoc, StatusList2021). Derzeit Teilimplementierungen ohne Konformitätsnachweis; die Stage-0-Befunde API-03..05 sind seit #312 behoben, Protokollstand vor OID4VP 1.0 Final (API-07) |
| Fehlerverhalten | Je Prozessimplementierung | Ziel: fail-closed, deny-biased. Umgesetzt in Komponenten wie `@askmi/policy-engine` (31+ deny codes), für den Demo-Pfad per Browser-Smoke belegt ([QA 2026-11-20](../qa/API_AUDIT_STAGE0_REMEDIATION_2026-11-20.md)), nicht als Produktionseigenschaft |

**Wichtig (gemäß `07-messaging-rules.md`):** Keine Aussage wie „wir blocken alles Tracking"
oder „vollständige Anonymität". Fail-closed, PII-minimal, auditable und
unlinkability-orientiert sind Designziele. Belegbar sind sie nur für die Komponente und den
Pfad, für die `06-claim-evidence-map.md` Evidenz verlinkt, nicht als Ende-zu-Ende-Eigenschaft.

---

## 2. Was wir ersetzen — und was wir bewusst NICHT ersetzen

### Nicht ersetzt (Kerngeschäft der Incumbents)

- **Gesetzliche Vollidentifizierung** (KYC nach GwG, eIDAS-Vertrauensdienst,
  notarielle Identifizierung): IDnow ist hierfür zertifiziert etabliert. AskMI ist kein
  Vertrauensdienst, hat keine eIDAS-Zertifizierung und ist Entwicklungs- und
  Evaluationssoftware, nicht produktionsreif (`docs/MATURITY_AND_LIMITATIONS.md`).
- **Onboarding von Personen ohne digitale Wallet** oder ohne EUDI-/kompatible Wallet.
- **Dokumenten-Prüfung** (Echtheit, Fälschungserkennung, PEP/Sanctions-Screening).

### Ergänzt (worin wir nicht Konkurrenz sind, sondern aufsetzen)

- AskMI ist kein Wallet-Ersatz: Es arbeitet *mit* EUDI-Wallets (siehe README
  „Not a wallet / Not an identity provider").
- Wo Incumbents die Identität *einmal vollständig* prüfen, verhindert AskMI den
  **Daten-Overkill bei jedem Folgenachweis**: Alter, Abschluss, Führerscheinklasse,
  EHDS-Freigaben — siehe `docs/00-welt/application_domains.md` (Tier 1).

### Potenziell substituiert (nur in Use Cases mit minimalem Proof-Bedarf)

- Altersverifikation im Online-Handel („über 18"-Ja/Nein statt Dokumentkopie/VideoIdent),
  sofern akzeptierte Credentials und ein regulatorischer Rahmen (EU-Altersverifikations-
  Verordnung) vorliegen. **Marktreife- und Zulassungsfragen sind offen.**

---

## 2a. Belegte Anbieterbeispiele (öffentliche Selbstdarstellung, abgerufen 2026-11-20)

Nur Aussagen der jeweiligen Seite, nicht unabhängig geprüft. Vor externer Nutzung neu abrufen.

### openapi (openapi.de / openapi.com) — „Certified Identitätsprüfung weltweit"

Quelle: <https://openapi.de/produkte/certified-identitatsprufung-weltweit>, abgerufen 2026-11-20.

- **Verfahren:** Fernidentifikation per Video; KI-Dokumentprüfung, Gesichtsabgleich mit
  Liveness-Erkennung, in der Stufe „Certified" zusätzlich menschliche Prüfung. Ergebnis laut
  Seite „in der Regel innerhalb von 3 Stunden oder mehr".
- **An den Kunden zurückgegeben (laut API-Beispielen):** Vor- und Nachname, Geburtsdatum,
  Dokumenttyp und -nummer, Ausstellungsland und -daten, MRZ, berechnetes Alter, Risiko-Labels;
  Gesichtsbild sowie Vorder- und Rückseite des Ausweises über eigene Endpunkte; Audit-Trail mit
  IP-Adresse und User-Agent.
- **Konformitätsangaben:** „DSGVO, PSD2" und „gemäß dem Standard ETSI EN 119 461 zertifiziert";
  keine Prüfstelle oder Zertifikatsnummer genannt. eIDAS-Vertrauensniveau, eID/NFC, TR-03147,
  Speicherdauer, Löschung, Datenstandort und Unterauftragnehmer werden auf der Seite nicht genannt.
- **Preis:** ab 2,68 € (Abo, 60.000 Aufrufe/Jahr) bis 4,50 € pro Einzelanfrage, jeweils zzgl. MwSt.
- **Einordnung (Wertung):** Klassisches Vollidentifizierungs-Modell. Auch für den in der FAQ
  genannten Use Case Altersprüfung erhält der Kunde Geburtsdatum und Ausweisbilder, obwohl das
  Alter bereits abgeleitet wird. AskMI gibt der Anwendung im aktiven Profil nur `eligible: true`
  zurück; der Verifier sieht dort derzeit noch das numerische Alter (#97). Der Vergleich gilt also
  gegenüber der Anwendung, noch nicht gegenüber dem Verifier.

### Digidentity

Quelle: <https://www.digidentity.eu/about-us/events>, abgerufen 2026-11-20.

- **Selbstbeschreibung:** „Qualified Trust Service Provider (QTSP)" auf der EU-Vertrauensliste
  (EUTL); „25+ million users", „over 250 thousand corporate customers".
- **Produkte (auf der Seite verlinkt):** Identity Proofing, Identity Verification,
  Authentication, eSignatures, eHerkenning, SERMI; Fernidentifikation „with passport chip
  reading and biometric liveness detection".
- **Nicht genannt:** ein eigenes EUDI-Wallet-Produkt oder ein Gesundheits-Produkt; beides
  erscheint nur in Veranstaltungstiteln.
- **Einordnung (Wertung):** Rolle auf Aussteller-/Vertrauensdienst-Seite. Eher möglicher Partner
  (Herausgabe, qualifizierte Dienste) als direkter Wettbewerber einer Verifier-seitigen
  Policy-Schicht. Offen: ob Digidentity Wallet oder Attestierungen für den niederländischen
  Gesundheitsbereich plant.

---

## 3. Ehrlichkeits-Grenzen (aus dem Repo selbst)

Damit kein überzogener Vergleich entsteht — alles bereits im Repo dokumentiert:

1. **Reifegrad:** Entwicklungs- und Evaluationssoftware ohne unabhängige Zertifizierung oder
   Produktionsnachweis (`docs/MATURITY_AND_LIMITATIONS.md`). Der reale `vc+sd-jwt`-Referenzpfad
   läuft gegen einen Mock-Issuer und legt derzeit das numerische Alter offen; die Browser-Demo
   nutzt synthetische Beispiele (`README.md`, `STATE.md`).
2. **Offene Integrationslücken:** #170 (Request-Binding/Replay auf `/oid4vp-present`),
   #171 (Single-Use/ gespeicherte SD-JWT), #172, #173 — siehe README
   „Integration findings" und `docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md`.
   Die Stage-0-Protokoll-Findings API-01..05 aus
   `docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md` sind seit #312 (2026-11-20) im Code
   behoben und durch Negativtests belegt
   ([QA-Protokoll](../qa/API_AUDIT_STAGE0_REMEDIATION_2026-11-20.md)). Offen bleiben:
   - **#97:** Der Verifier erhält im aktiven Connect-Profil das numerische Alter, nicht nur
     „≥ 18".
   - **API-04-Rest:** Roh-Bytes der DeviceNameSpaces, `OpenID4VPHandover`, echte
     `deviceSignature` im Wallet (kein aktiver mdoc-Pfad).
   - **API-07:** Protokollstand vor OpenID4VP 1.0 Final / OpenID4VCI 1.0 Final.
3. **Kostenvergleich ist ein Annahmenmodell:** CL-02 in `docs/BACKLOG.md` — belegt sind
   nur Veriff-Beispielpreis, AWS-CloudHSM- und CloudFront-Listenpreise; alles andere ist
   als Annahme gekennzeichnet. Keine unabhängige Verifikation.
4. **Wettbewerber-Angaben:** Public-Pricing-/Produkt-Angaben der Wettbewerber in
   `site/index.html` stammen aus öffentlichen Quellen (Jumio/Onfido/IDnow/Veriff
   Pricing-Seiten, Industry-Reports) mit Stand 2024/2025 — vor jeder externen Nutzung
   neu datieren und prüfen.
5. **Eigene Claims:** Nur Claims aus `06-claim-evidence-map.md` mit dort verlinkter
   Evidenz verwenden.

---

## 4. Quellen im Repo

- `docs/05-business/marketing/06-claim-evidence-map.md` — Claim-zu-Evidenz-Mapping
- `docs/05-business/marketing/07-messaging-rules.md` — Was wir (nicht) sagen
- `docs/00-welt/application_domains.md` — Tier-1-Use-Cases mit Ehrlichkeits-Check
- `docs/05-business/USE_CASE_LANDSCAPE_AND_SEQUENCED_ROADMAP_2026-09-11.md` —
  Use-Case-Landschaft
- `docs/GTM_SPRINT_ROADMAP.md` — GTM-Einordnung; Primary Competitor dort: „Internal build
  using official/open-source verifier components plus policy/configuration work" (nicht IDnow)
- `docs/BACKLOG.md` CL-02 — Kostenmodell-Belegstand
- `README.md` — Architektur, Integration Findings, Key Properties

## 5. Offene Aufgaben (aus diesem Entwurf)

- [ ] Wettbewerber-Produktseiten (IDnow, Veriff, Yoti, Jumio, Onfido) mit Abrufdatum
      einzeln belegen; je Anbieter 3–5 Kernaussagen mit URL und Stand. (openapi und
      Digidentity: §2a, 2026-11-20.)
- [ ] openapi: verlinkte GDPR-Unterlage und Länderliste lesen (Speicherdauer,
      Unterauftragnehmer); Digidentity: Produktseiten Identity Proofing/Verification belegen.
- [ ] Klarstellen, in welchen regulatorischen Verfahren (JuSchG, GwG, eIDAS) ein
      minimaler Proof heute bereits *anerkannt* ist — Rechtslage prüfen lassen.
- [ ] Nach #171: Evidenz-Zeile „realer SD-JWT-Flow prüft nur policy-selektierte Claims"
      ergänzen (API-02 und #170 sind behoben; Beleg siehe QA-Protokoll 2026-11-20).
- [ ] Die Incumbent-These in `application_domains.md:15` belegen oder streichen (der Verweis
      auf dieses Dokument steht dort bereits).
