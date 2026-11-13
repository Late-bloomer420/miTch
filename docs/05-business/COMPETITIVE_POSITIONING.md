# AskMI / miTch: Wettbewerbs-Positionierung gegenüber klassischen Identity-Verification-Anbietern

Stand: 2026-10-28
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
| Frage, die beantwortet wird | „Wer bist du?" (Vollidentifizierung) | „Reicht dir nicht auch ein minimaler Proof?" (z. B. „über 18: Ja/Nein") |
| Rolle im System | Verifizierer/Vertrauensdienst, der personenbezogene Daten verarbeitet | Policy-Vermittlungsschicht zwischen Wallet und Verifier; keine Identitätsverwahrung |
| Wo die Daten liegen | Zentral beim Anbieter/Verifier (Dokumentkopien, Biometrie-Match in der Cloud) | Am Gerät (Edge), AES-256-GCM-verschlüsselt; Crypto-Shredding flüchtiger Materialien |
| Biometrie | Remote Biometric Match (Cloud-Dienst, kostenpflichtig) | Geräte-lokal (WebAuthn / Face ID); biometrische Daten verlassen das Gerät nicht |
| Standardisierung | Proprietäre Prozesse plus eIDAS-/Gesetzes-Konformanz (VideoIdent, eID) | Offene Standards: OID4VCI, OID4VP, SD-JWT, ISO 18013-5 (mdoc), StatusList2021 |
| Fehlerverhalten | Je Prozessimplementierung | Fail-closed, deny-biased (31+ deny codes, `@askmi/policy-engine`) |

**Wichtig (gemäß `07-messaging-rules.md`):** Keine Aussage wie „wir blocken alles Tracking"
oder „vollständige Anonymität". Die belegbaren Eigenschaften sind: fail-closed,
PII-minimal, auditable, unlinkability-orientiert.

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

## 3. Ehrlichkeits-Grenzen (aus dem Repo selbst)

Damit kein überzogener Vergleich entsteht — alles bereits im Repo dokumentiert:

1. **Reifegrad:** Entwicklungs- und Evaluationssoftware ohne unabhängige Zertifizierung oder
   Produktionsnachweis (`docs/MATURITY_AND_LIMITATIONS.md`). Der reale `vc+sd-jwt`-Referenzpfad
   läuft gegen einen Mock-Issuer und legt derzeit das numerische Alter offen; die Browser-Demo
   nutzt synthetische Beispiele (`README.md`, `STATE.md`).
2. **Offene Integrationslücken:** #170 (Request-Binding/Replay auf `/oid4vp-present`),
   #171 (Single-Use/ gespeicherte SD-JWT), #172, #173 — siehe README
   „Integration findings" und `docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md`.
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
      einzeln belegen; je Anbieter 3–5 Kernaussagen mit URL und Stand.
- [ ] Klarstellen, in welchen regulatorischen Verfahren (JuSchG, GwG, eIDAS) ein
      minimaler Proof heute bereits *anerkannt* ist — Rechtslage prüfen lassen.
- [ ] Nach #170/#171-Behebung: Evidenz-Zeile „realer SD-JWT-Flow prüft nur
      policy-selektierte Claims" ergänzen.
- [ ] Die Incumbent-These in `application_domains.md:15` belegen oder streichen (der Verweis
      auf dieses Dokument steht dort bereits).
