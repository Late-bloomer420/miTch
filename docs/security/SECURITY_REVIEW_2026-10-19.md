# Security- und Privacy-Review: AskMI

**Ursprünglicher Review:** 2026-10-19; historische Baseline `624cf9a`.
**Statischer Abgleich:** 2026-11-13 gegen master `2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3`.
**Methode:** Git-Historie, Quellcode und datierte QA-Artefakte; Windows/PowerShell,
Git 2.50.0.windows.2. Issue #170 wurde zusätzlich live auf GitHub geprüft.
**Grenze:** Keine neuen Runtime-, Browser-, Interop- oder Auditläufe. Dieser
Abgleich ist kein Security-PASS und ändert keine Release-/Pilot-Gates.

## Historische Beobachtungen und nachfolgende Evidenz

Die [Reproduktionen vom 14.10.2026](../qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md)
und der [Finding-Register](REPO_EVIDENCE_STATUS_2026-10-14.md) behalten ihre
ursprünglichen 2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3s, Profile und Ergebnisse. Damals akzeptierte die aktive
Route wiederholte Präsentationen und vom Holder gewählte Bindungswerte;
Connect fehlte an dieser Baseline. Diese Aussagen beschreiben nicht den
unten geprüften master.

Die [Review-Fassung vom 24.10.2026](https://github.com/Late-bloomer420/miTch/blob/420f4452288de19cb476fd6e1716b32da61588b8/docs/security/SECURITY_REVIEW_2026-10-19.md)
bleibt über Git nachvollziehbar. Ihre zwischenzeitlichen PR-/CI-Zustände sind
keine aktuelle Merge-Empfehlung. Der dort referenzierte Lifecycle-Testbericht
von 66/66 Tests bleibt [an seinem damaligen Code-Stand](https://github.com/Late-bloomer420/miTch/blob/33c306947c034123bf8e9ad06d7697fa38b9b530/docs/qa/CONNECT_LIFECYCLE_CORRECTION_2026-10-24.md)
verortet; er wird hier nicht als neuer Testlauf ausgegeben.

## P0-1: Servereigene Request-Bindung und Eligibility (#170)

**Einordnung:** Die ursprüngliche Lücke wurde für den dokumentierten
Numeric-age-Pfad bearbeitet. [#170](https://github.com/Late-bloomer420/miTch/issues/170)
ist seit 25.10.2026 als completed geschlossen (live geprüft am 13.11.2026).

Im [gepinten `app.ts`](https://github.com/Late-bloomer420/miTch/blob/2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3/src/apps/verifier-demo/backend/src/app.ts#L487)
beginnt `/oid4vp-present` an Zeile 487. Die Route reserviert den Versuch mit
`authorization.attempted = true` vor asynchroner Prüfung, prüft die aktuelle
Authorization samt Ablauf und vergleicht den State mit
`authorization.request.state`. Die Signaturvalidierung erhält
`request: authorization.request` (Zeile 544). `acceptsActiveProfile` prüft den
Profil-/Eligibility-Vertrag; `reconstructedRequest` kommt nicht mehr vor.

Die Umsetzung ist über #208 (`a65774d`) und #224 (`3f376bf`) in master:

- [Aktive Numeric-age-Route, 25.10.2026](../qa/ACTIVE_AGE_PROFILE_2026-10-25.md):
  datierte echte Signatur-/HTTP-Negativtests mit synthetischem vertrauenswürdigem
  Issuer. Der damalige Hinweis auf noch offene Connect-Integration gehört zu
  diesem früheren Teilstand.
- [Connect-Integration, 25.10.2026](../qa/CONNECT_PROFILE_INTEGRATION_2026-10-25.md):
  nachfolgende Profil-/App-Integration, mit eigener Revision und Testmatrix.

Maßgeblich bleibt die vollständige Acceptance-/Evidence-Liste in #170:
Audience/Nonce/State/Expiry, vertrauenswürdige Signatur und Holder-Bindung,
atomare Reservierung im gewählten Store, Konkurrenz und Terminalzustände,
separate Eligibility, Excess-Claim-Reject sowie echte HTTP-/Signatur-Negative.
Eine feste Zahl von vier Tests ersetzt diesen Vertrag nicht.

**Grenzen:** Single-process/In-memory-Reservierung beweist keine verteilte
Atomarität oder Restart-Durabilität. Das Middleware-Profil empfängt numerisches
Alter; minimierte App-Ergebnisse sind kein Beleg für ZKP oder Unlinkability.

## P0-2: Connect- und Wallet-Enforcement getrennt beurteilen

**Einordnung:** [`src/packages/connect`](https://github.com/Late-bloomer420/miTch/blob/2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3/src/packages/connect/src/index.ts)
existiert. #193 (`df6b106`) brachte das Paket; #224 integrierte den gespeicherten
Altersprofil-Vertrag und Wallet-Handoff. Eine erneute Implementierung des
angeblich fehlenden Pakets ist keine aktuelle Maßnahme.

Die [Connect-QA](../qa/CONNECT_PROFILE_INTEGRATION_2026-10-25.md) beschreibt die
separaten Session-/Presentation-Endpunkte, Signatur-/Holder-Prüfung, terminale
Fehler und minimierte Statusprojektion. Ihre Laufzeit- und Profilgrenzen gelten
unverändert. Connect ist RP-seitige Integration gemäß
[Produktentscheidung](../tasks/ADOPT_1_PRODUCT_BOUNDARY_DECISION.md).

Der wallet-seitige finale Disclosure-PEP und adversariale Tests sind separate
Arbeit unter [#180](https://github.com/Late-bloomer420/miTch/issues/180) und
[#181](https://github.com/Late-bloomer420/miTch/issues/181). Die Existenz von
Connect beweist keine allgemeine Wallet-Enforcement-Garantie.

## P1-1: Bedeutung von HARDWARE_BOUND

[`IdentityKeyGuardian.getLevel()`](https://github.com/Late-bloomer420/miTch/blob/2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3/src/packages/shared-crypto/src/IdentityKeyGuardian.ts#L45)
liefert HARDWARE_BOUND bei registrierter WebAuthn-Identität.
[`webauthn.ts`](https://github.com/Late-bloomer420/miTch/blob/2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3/src/packages/shared-crypto/src/webauthn.ts#L245)
fordert bei Registrierung `attestation: 'none'` an. Daraus folgt kein allgemeiner
Nachweis von Hardware-Residency oder TEE-Attestation.

**Nicht festgestellt:** Ob BE/BS-Prüfung über alle relevanten Pfade korrekt
erzwungen wird, wurde hier nicht dynamisch nachgewiesen. BE/BS bezeichnet
Backup Eligibility/Backup State; das ist eine andere Eigenschaft als
Hardware-Attestation. Fehlende Evidenz ist kein Nachweis fehlender Prüfung.

**Maßnahme:** Label-/Dokumentationsaussagen an diese Grenze binden; eine Änderung
der öffentlichen Enum/API benötigt gesonderte Freigabe. Die ältere
[Key-Reality-Datei](../_core/10_KEY_PROTECTION_REALITY.md) ist kein Ersatz für den
hier gepinten Runtime-Code.

## P1-2: Lokale Predicates und dedizierter AV-Vertrag

Lokale Predicate-Auswertung mit Wallet-Signatur ist kein Nachweis einer
issuer-authentifizierten ZK-Ableitung. Der dokumentierte Connect-Pilot
verifiziert numerisches Alter; eine boolesche App-Antwort ändert diesen
Disclosure-Vertrag nicht.

**Maßnahme:** Unter [#97](https://github.com/Late-bloomer420/miTch/issues/97) und
[#182](https://github.com/Late-bloomer420/miTch/issues/182) exakte Profil-, Quell-
und Issuer-Versionen festlegen, dann einen dedizierten AV-Pfad mit
Negativ-/Interop-Evidenz prüfen. Den akzeptierten Numeric-age-Piloten nicht
stillschweigend durch mdoc-/Boolean-/ZKP-Semantik ersetzen. Dieser Abgleich
bestätigt keine aktuelle offizielle AV-Konformität.

## P1-3: Entscheidung-ID verwendet CSPRNG

[`evaluate.ts:376`](https://github.com/Late-bloomer420/miTch/blob/2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3/src/packages/predicates/src/evaluate.ts#L376)
verwendet `decision_${Date.now()}_${globalThis.crypto.randomUUID()}`.
#203 (`1d900d3`) ist in master enthalten. Die frühere Math.random-Entropiequelle
ist hier ersetzt; der Zeitstempel bleibt Bestandteil des Formats.

**Maßnahme:** CSPRNG-/Formatvertrag bei künftigen Änderungen gezielt prüfen.
Keine Empfehlung, den älteren PR #151 zur Behebung derselben Stelle zu mergen.
Diese statische Feststellung beweist weder allgemeine Unlinkability noch einen
historischen Forgery-/Tracking-Exploit.

## P2-1: Audit-Gate und EV-05

#194 (`7507976`) änderte das Gate. Die geprüfte
[`ci-security.yml`](https://github.com/Late-bloomer420/miTch/blob/2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3/.github/workflows/ci-security.yml)
ruft Regressionstests und [`check-security-audit.mjs`](https://github.com/Late-bloomer420/miTch/blob/2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3/scripts/check-security-audit.mjs)
auf. Der Parser lehnt ungültige Berichte und widersprüchliche Exitcodes ab;
Critical-Findings erzeugen einen Fehler. High-Findings bleiben sichtbar, sind
in dieser Implementierung aber allein kein Abbruchkriterium.

Die pauschale Aussage „weiterhin nur advisory“ beschreibt diese Konfiguration
nicht. Die historischen EV-05-Reproduktionen bleiben datiert erhalten.
Hier wurden weder `pnpm audit` noch Gate-Tests erneut ausgeführt: keine aktuelle
CVE-Zahl, kein grüner CI-Status und keine organisationsweite Gate-Garantie.

## Weitere Assurance-Grenzen

- **DPIA:** #191 (`11a27a9`) ist in master enthalten. Dessen Dokumentationsänderung
  ist keine Zertifizierung und kein Nachweis vollständiger Löschung.
- **Supply Chain:** Dieser Abgleich belegt keine vollständige SBOM-/Signaturkette.
  Fehlende Evidenz ist kein repo-weiter Nachweis ihrer Abwesenheit.
- **XSS/Key Extraction:** Kein Exploit wurde hier ausgeführt oder bestätigt.
  Holder-Key-Persistenz und Browser-Boundary sind unter
  [#186](https://github.com/Late-bloomer420/miTch/issues/186) getrennt zu prüfen;
  In-memory-WebCrypto allein schließt Angriffe nicht aus.
- **Lifecycle/Audit/Evidence:** #171–#173 und weitere Assurance-Arbeit bleiben
  eigenständige Themen. Dieser Abgleich ändert ihren Status nicht.

## Zusammenfassung und nächste Schritte

| ID | Einordnung am geprüften 2bdd8ac55569ccc5d9d4a2373ba61afe284f08f3 | Nächste Arbeit / Evidenzgrenze |
|---|---|---|
| P0-1 | Ursprünglicher Numeric-age-Befund durch #208/#224 bearbeitet; #170 geschlossen | Vollständigen #170-Vertrag und datierte Profil-Evidenz erhalten; keine allgemeine Deployment-Garantie |
| P0-2 | Connect vorhanden und integriert | RP-Integration und Wallet-PEP getrennt prüfen (#180/#181) |
| P1-1 | WebAuthn-Registrierung erklärt HARDWARE_BOUND; kein allgemeiner Attestationsnachweis | Dokumentation begrenzen; BE/BS-Enforcement nicht als bewiesen fehlend darstellen |
| P1-2 | Numeric-age-Pilot ist kein dedizierter AV-/ZKP-Pfad | Profil-/Issuer-Entscheidung unter #97/#182 vor Umsetzung |
| P1-3 | crypto.randomUUID seit #203 | Format-/Randomness-Vertrag erhalten; kein pauschaler Merge-Auftrag für #151 |
| P2-1 | Critical-/Fehler-Gate implementiert | Datierten Gate-Testlauf für weitergehende Aussagen benötigen; keine aktuelle CVE-Zahl |
| P2-2 | Vollständige Supply-chain-Assurance hier unbelegt | Gesonderte SBOM-/Signatur-Evidenz |
| P2-3 | XSS-/Key-Extraction-Exploit hier unbelegt | Browser-/Key-Boundary gesondert prüfen (#186) |

[BACKLOG](../BACKLOG.md), [Release-Roadmap](../RELEASE_READINESS_ROADMAP.md) und
[#142](https://github.com/Late-bloomer420/miTch/issues/142) /
[#143](https://github.com/Late-bloomer420/miTch/issues/143) bleiben die
zuständigen Tracker. Produktziele werden durch diese Eingrenzung nicht
zurückgenommen; Gate-Schließungen benötigen ihre eigene verlinkte Evidenz.
