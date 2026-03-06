# miTch — Uni-Präsentation: Gliederung

**Titel:** miTch — The Forgetting Layer: Privacy-Preserving Compliance Middleware
**Format:** 20 Min Vortrag + 10 Min Q&A (Bachelor/Master Seminar)
**Ziel:** Technisches Konzept, Implementierung und gesellschaftliche Relevanz vermitteln

---

## Folie 1 — Problem (2 Min)

**Hook:** "Jedes Mal, wenn Sie Ihren Ausweis zeigen, hinterlassen Sie eine permanente Spur."

Kernproblem:
- Regulierung erzwingt Identitätsprüfung (KYC, Altersverifikation, EHDS, eIDAS 2.0)
- Klassische Systeme: rohe PII wird übertragen und gespeichert
- Resultat: zentrale PII-Honeypots, DSGVO-Risiken, Tracking

Konkrete Beispiele:
- Liquor Store: vollständiger Ausweis-Scan für "Ist 18?"
- Hospital: Akte mit allen Attributen — für einen Arztkontakt
- Data Broker Markt: Bewegungsprofile aus ID-Prüfungen

---

## Folie 2 — Vision / Leitsatz (1 Min)

> **"Alle sind miTch."**

- Uniformität als Datenschutz: Wenn alle gleich aussehen, kann niemand verfolgt werden
- Strukturelles Vergessen, nicht organisatorisches Versprechen
- Privacy by Construction vs. Privacy by Policy

---

## Folie 3 — Lösung: The Forgetting Layer (3 Min)

Kernkonzept:
- **Proof Mediation Layer** — keine Rohdaten, nur kryptografische Beweise
- **Edge-First** — Identitätsdaten bleiben lokal auf dem Endgerät
- **Crypto-Shredding** — ephemere Schlüssel werden nach jeder Transaktion zerstört

Architektur-Prinzipien:
- Fail-Closed: Zweifel = Deny (kein "Silent Allow")
- Zero Identity Custody: miTch-Server sieht keine Inhalte
- Unlinkability: Cross-Verifier-Isolation durch paarweise DIDs (HKDF)

**[Verweis auf ARCHITECTURE.md — Diagramm 1: System Overview]**

---

## Folie 4 — Technische Implementierung (5 Min)

### 4.1 Wallet (PWA)
- AES-256-GCM verschlüsselter Credential-Store (IndexedDB)
- WebAuthn Step-Up für sensible Operationen
- WORM Audit Log (Write-Once, Read-Many) — DSGVO Art. 32

### 4.2 Policy Engine
- Deterministische Evaluierung — gleicher Input, gleicher Output
- 31+ Deny Reason Codes (maschinenlesbar)
- Anti-Oracle-Muster: keine Informationsleckage bei Deny-Entscheidungen
- Fail-Closed als Protokoll-Eigenschaft

### 4.3 Shared Crypto
- `pairwise-did.ts`: HKDF-abgeleitete did:peer pro Verifier-Session
- ECDSA P-256 Signing + RSA-OAEP Key Wrapping
- did:peer:0 Inline-Resolution (kein Netzwerk nötig)

### 4.4 Protokolle
- OID4VP (OpenID for Verifiable Presentations) — E-01a–E-01d implementiert
- OID4VCI (OpenID for Verifiable Credential Issuance) — E-02 implementiert
- eIDAS 2.0 / EUDI Wallet Architektur-kompatibel

**[Verweis auf ARCHITECTURE.md — Diagramm 2: Crypto Flow]**

---

## Folie 5 — Demo: 4 Szenarien (4 Min)

*Live oder als Video-Mitschnitt. Vollständiges Script: DEMO_SCRIPT.md*

| Szenario | Layer | Mechanismus |
|---|---|---|
| Liquor Store | Alltag | Auto-Allow, ZKP Alter >= 18, Unlinkability |
| Hospital | Health | User-Prompt, Selektive Disclosure, Art. 9 DSGVO |
| EHDS Emergency | Notfall | Break-Glass WebAuthn Biometrie, Audit Trail |
| Pharmacy | Mehrfach | Proof-Fatigue-Schutz, Ephemeral Key Rotation |

---

## Folie 6 — Sicherheitsgarantien (2 Min)

Implementierte Security Properties:
- **Replay-Schutz:** Nonce-Store mit TTL, AAD-Binding (decision_id + nonce + verifier_did)
- **Unlinkability Phase 1+2:** U-01–U-05 — paarweise HKDF DIDs, Cross-Verifier-Isolation
- **Security Hardening S-01–S-05:** Verifier-Fingerprint, Manifest-Rollback-Schutz, Input Validation
- **OID4VP AAD Integrity:** AEAD-Verschlüsselung mit authentifiziertem Kontext
- **Revocation:** StatusList2021 Fail-Closed (Zweifel = Deny)

Test Coverage:
- 760+ Unit/Integration-Tests — alle grün
- 0 npm Vulnerabilities
- 0 ESLint Errors/Warnings

---

## Folie 7 — Gesellschaftliche Relevanz (1 Min)

- EU Digitale Identität: eIDAS 2.0 verpflichtet alle EU-Mitgliedstaaten bis 2026
- EHDS tritt 2025/2026 in Kraft — Health Data Sharing mit Datenschutz
- miTch zeigt: Compliance und Datenschutz sind kein Widerspruch
- "The Forgetting Layer" als generisches Pattern über use-cases hinaus

---

## Folie 8 — Ausblick / Roadmap (1 Min)

Offen (Phase 2+):
- BBS+ Signatures (randomisierte Proofs, echtes ZKP)
- ISO/IEC 18013-5 mdoc Support (Führerschein, EU-ID)
- BSI/SOG-IS Krypto (brainpoolP256r1, brainpoolP384r1)
- Controlled Insight — granulare Daten-Delegation

---

## Folie 9 — Q&A

Erwartete Fragen & Antworten: siehe DEMO_SCRIPT.md (Abschnitt Q&A Talking Points)

Key Messages zum Mitnehmen:
1. Privacy-by-Construction ist technisch lösbar — heute, ohne ZKP-Hardware
2. Fail-Closed ist eine Architektur-Entscheidung, keine Policy
3. "Alle sind miTch" — Uniformität schützt alle, auch die, die nichts zu verbergen haben

---

## Zeitplan

| Block | Inhalt | Min |
|---|---|---|
| Folie 1–2 | Problem + Vision | 3 |
| Folie 3 | Lösung | 3 |
| Folie 4 | Technik | 5 |
| Folie 5 | Demo | 4 |
| Folie 6–7 | Security + Relevanz | 3 |
| Folie 8 | Ausblick | 1 |
| Folie 9 | Q&A | 10 |
| **Gesamt** | | **29 Min** |
