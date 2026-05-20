# Sprint Candidates

Stand: 2026-05-20
Repo: miTch
Basis: `docs/BACKLOG.md`, `STATE.md`

## 1. Identity Firewall MVP

**Sprint-Ziel:**
Identifier-, Tracker-, Cookie- und sonstige Wiedererkennungszugriffe im Wallet-/Verifier-Kontext sichtbar machen, auditierbar loggen und dem Nutzer verstaendlich anzeigen.

**Warum jetzt:**
Sehr nah an der miTch-Vision: nicht nur Datenminimierung, sondern Transparenz darueber, wer versucht, Identitaet oder Verhalten zu verknuepfen.

**Kern-Ergebnis:**
Ein MVP, der verdaechtige Identifier-Zugriffe erkennt, Audit-Events erzeugt und sie in Wallet/DataFlow sichtbar macht.

**Drei Rollen:**

- Product/Policy: Definiert, welche Zugriffe als Identifier-Zugriff gelten.
- Engineer: Baut Detection, Audit-Event und UI-Anbindung.
- Reviewer/Security: Prueft Fail-closed-Verhalten, Datenschutz-Logik und Tests.

**Review-Gates:**

- Review 1: Scope, Event-Modell, UI-Verhalten.
- Review 2: Implementierungsplan, Tests, Akzeptanzkriterien.
- Danach kann der Engineer bauen.

## 2. Proof-Randomisierung

**Sprint-Ziel:**
Sicherstellen, dass derselbe Credential bei wiederholter Nutzung nicht denselben Proof-Output erzeugt und dadurch nicht linkbar wird.

**Warum jetzt:**
Staerkt Unlinkability kryptografisch, ist aber technischer und riskanter als Identity Firewall.

**Kern-Ergebnis:**
Design und erste Implementierung fuer randomisierte Proof-Ausgabe oder SD-JWT Ephemeral Holder Binding.

**Drei Rollen:**

- Crypto/Policy: Entscheidet zwischen BBS+, SD-JWT Holder Binding oder Uebergangsloesung.
- Engineer: Implementiert Proof-Variation und Tests.
- Reviewer/Security: Prueft Linkability-Risiken und Regressionen.

**Review-Gates:**

- Review 1: Kryptografischer Ansatz.
- Review 2: Teststrategie gegen Korrelation.
- Danach Implementierung.

## 3. Compliance Gap Sprint

**Sprint-Ziel:**
Aktuelle miTch-Funktionen gegen CIR/eIDAS-/EUDI-Anforderungen mappen und konkrete Luecken dokumentieren.

**Warum jetzt:**
Gut fuer Audit-, Pilot- und Investor-Reife. Weniger Produktfeature, aber strategisch wertvoll.

**Kern-Ergebnis:**
Compliance-Matrix mit Status: erfuellt, teilweise erfuellt, offen, nicht relevant.

**Drei Rollen:**

- Compliance/Product: Definiert relevante Regulierungspunkte.
- Engineer: Verlinkt Code, Tests und Dokumentation als Evidence.
- Reviewer: Prueft Nachvollziehbarkeit und Lueckenlogik.

**Review-Gates:**

- Review 1: Welche Regulierungen sind im Sprint enthalten.
- Review 2: Matrix-Struktur und Evidence-Standard.
- Danach Ausarbeitung.

## 4. Threat Model Finalisierung

**Sprint-Ziel:**
ADR-009 / STRIDE Threat Model in einen reviewbaren, pilotfaehigen Security-Artefaktstand bringen.

**Warum jetzt:**
Security-Reife erhoehen, offene Gaps priorisieren, externen Review vorbereiten.

**Kern-Ergebnis:**
Finalisiertes Threat-Model-Paket mit Risiken, Mitigations, Evidence Links und offenen Review-Fragen.

**Drei Rollen:**

- Security/Product: Priorisiert Bedrohungen und akzeptierte Restrisiken.
- Engineer: Verknuepft Threats mit Code, Tests und Architektur.
- Reviewer/Security: Prueft Vollstaendigkeit und Widersprueche.

**Review-Gates:**

- Review 1: Threat-Scope und STRIDE-Abdeckung.
- Review 2: Evidence, Gaps, Mitigation-Qualitaet.
- Danach Finalisierung.

## 5. brainpoolP512r1 Support

**Sprint-Ziel:**
Optionalen BrainpoolP512r1-Support ergaenzen, analog zum bestehenden P256/P384-Support.

**Warum jetzt:**
Technisch klar abgrenzbar, aber eher Nice-to-have als produktkritisch.

**Kern-Ergebnis:**
P512r1 Keygen, Sign, Verify, ECDH, Export und Cross-Curve-Isolationstests.

**Drei Rollen:**

- Crypto/Product: Bestaetigt Bedarf und Prioritaet.
- Engineer: Implementiert Kurvenparameter und Tests.
- Reviewer/Security: Prueft Parameter, Testabdeckung und Kompatibilitaet.

**Review-Gates:**

- Review 1: Parameterquelle und API-Verhalten.
- Review 2: Tests und Kompatibilitaetsgrenzen.
- Danach Implementierung.
