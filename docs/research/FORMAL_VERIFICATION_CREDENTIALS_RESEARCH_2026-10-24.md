# Research Intake: Formale Verifikation & Diskrete Mathematik in Credential-Systemen

**Datum:** 2026-10-24
**Status:** akzeptiert (Intake; Umsetzung über Issues #196–#199)
**Methode:** Deep Research über Primärquellen (Spezifikationen, formale Analysen, Preprints); Quellentabelle mit Glaubwürdigkeits-Bewertung im zugehörigen Brief (privat abgelegt).

## Executive Summary

1. Die OpenID Foundation ließ OID4VCI/OID4VP 2024 mit dem Web Infrastructure Model (Univ. Stuttgart, Fett/Küsters) formal verifizieren: **same-device-Flows bewiesen**; **pre-authorized-code-flow (OID4VCI) und cross-device-flow (OID4VP) ohne Nutzer-Aufmerksamkeit phishing-anfällig**. Feedback ist in aktuelle Spec-Versionen eingeflossen. → Issue #196 (Threat-Model-Update).
2. Selective Disclosure hat zwei mathematisch unterschiedliche Familien: **Hiding Commitments** (SD-JWT, mdoc — Präsentationen korrelierbar) vs. **Non-Interactive ZKP** (BBS+, PS — unlinkable, Prädikatsbeweise). Der EUDI-ARF schreibt heute SD-JWT/mdoc vor und deckt ZKP nicht ab. → Kontext für #97/#182.
3. **Unlinkability ist formal definiert** (Pfitzmann/Hansen) — relativ zu einem Angreifermodell; ein Gegenbeispiel widerlegt die Eigenschaft. miTchs Gegenbeispiel-Regressionen sind genau die richtige Testform. → Issue #199.
4. `@askmi/discrete-core` (PR #189) formalisiert Datenmodell-Invarianten (Injektivität, Bijektivität, Wohldefiniertheit) als fail-closed Guards — eine Engineering-Vorstufe, **kein Ersatz** für symbolische Protokollverifikation. → Issue #198 (Härtung + Verdrahtung).
5. Realistischster nächster Verification-Schritt: **Tamarin-Modell des ADOPT-Flows** (Impersonation/Replay/Trust-Bypass); Beweis oder Angriff sind beide Evidence-Pack-wertig (SECURE-Track). → Issue #197.

## Quellen (Kern)

- OIDF: Formal Security Analysis of OpenID for Verifiable Credentials — https://openid.net/formal-security-analysis-openid-verifiable-credentials/ (2024-01-18; vorläufig, nicht peer-reviewed, Spec-Basis Mai 2023)
- Fett/Küsters/Schmitz: OAuth 2.0 (CCS 2016) — https://arxiv.org/pdf/1601.01229 ; OpenID Connect (CSF 2017) — https://arxiv.org/pdf/1704.08539
- Flamini et al.: On Cryptographic Mechanisms for the Selective Disclosure of Verifiable Credentials — https://arxiv.org/pdf/2401.08196 (2024-01-16)
- RFC 9901 (SD-JWT) — https://www.rfc-editor.org/info/rfc9901/ ; SD-JWT-VC Draft — https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.html ; OpenID4VP 1.0 — https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- W3C vc-di-bbs — https://www.w3.org/TR/vc-di-bbs/ ; EUDI ARF — https://eudi.dev/1.1.0/arf/
- Pfitzmann/Hansen Terminology v0.34 — https://dud.inf.tu-dresden.de/literatur/Anon_Terminology_v0.34.pdf
- Tamarin Prover — https://tamarin-prover.com/ ; SIGLOG-Übersicht — https://people.inf.ethz.ch/basin/pubs/siglog-tamarin.pdf
- IACR ePrint 2026/1373 (Formalizing Privacy of Anonymous Credentials; nur Abstract geprüft) — https://eprint.iacr.org/2026/1373.pdf

## Grenzen / Vorbehalte

- OIDF-Analyse vorläufig, nicht peer-reviewed, basiert auf Spec-Versionen Mai 2023.
- IACR-ePrint nur anhand Titel/Abstract geprüft (Abruf blockiert).
- `discrete-core` leistet finit-empirische Invariantenprüfung, keine formale Verifikation im Dolev-Yao-Sinne; diese Grenze bleibt in der Paket-README dokumentiert.

## Verfolgung

| Issue | Thema | Priorität |
| --- | --- | --- |
| #196 | OIDF-Befunde in ADR-009 + SECURITY.md übernehmen | P1 |
| #197 | Tamarin-Modell des ADOPT-Flows | P1 |
| #198 | verifyBijectionPair härten + Guards verdrahten | P2 |
| #199 | Unlinkability-Claims an Angreifermodell binden | P2 |
