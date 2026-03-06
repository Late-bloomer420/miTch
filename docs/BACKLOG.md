# miTch — Master Backlog
**Stand:** 2026-03-06 (Session 8 Update)
**Leitsatz:** *"Alle sind miTch."*

---

## Legende
- 🔴 P0 — Blocker / Must-Have für nächsten Meilenstein
- 🟡 P1 — Wichtig, sollte bald passieren
- 🟢 P2 — Nice-to-have / Langfristig
- ✅ — Erledigt

---

## Phase 0 — Foundation (DONE ✅)

Alle P0 + P1 Gaps geschlossen. 34/34 Turbo Tasks, 155+ Tests, 0 Audit Vulns.

| ID | Status | Beschreibung |
|---|---|---|
| G-01 | ✅ | DID Resolution + Signaturverifikation |
| G-02 | ✅ | StatusList2021 Revocation Runtime (Fail-Closed Bug gefixt) |
| G-03 | ✅ | Policy Determinism + 31 Deny Reason Codes + Anti-Oracle |
| G-04 | ✅ | Anti-Replay Binding (Canonicalization, Nonce Store, TTL) |
| G-05 | ✅ | eID Issuer Simulator (SD-JWT VC, ES256, DID Document) |
| G-06 | ✅ | Credential Persistence (AES-256-GCM + IndexedDB) |
| G-07 | ✅ | Key Separation (ECDH-P256 enc vs ECDSA signing) |
| G-08 | ✅ | JWE Encrypted Credentials at Rest |
| G-09 | ✅ | L2/Blockchain Anchoring Stubs |
| G-10 | ✅ | WebAuthn Step-Up + Challenge Expiry |
| AI-01–06 | ✅ | Alle Audit Issues geschlossen |
| EHDS T-A1–D1 | ✅ | 12 EHDS Tasks komplett |

---

## Phase 1 — Unlinkability ("Alle sind miTch") ✅

### 1.1 Pairwise-Ephemeral DIDs (Spec 111)
| ID | Prio | Beschreibung | Spec |
|---|---|---|---|
| U-01 | ✅ | `pairwise-did.ts` — did:peer Generation + HKDF Derivation | Spec 111 |
| U-02 | ✅ | did:peer Resolution in `did.ts` (inline, kein Netzwerk) | Spec 111 |
| U-03 | ✅ | Unlinkability Tests (Cross-Verifier, Cross-Session, Anti-Korrelation) | Spec 111 |
| U-04 | ✅ | Key Shredding nach Interaktion (EphemeralKey Integration) | Spec 111 |
| U-05 | ✅ | Policy Engine: Pairwise DID in Proof-Generierung einbinden | Spec 111 |

### 1.2 Randomisierte Proofs (Phase 2)
| ID | Prio | Beschreibung |
|---|---|---|
| U-10 | 🟡 | BBS+ Signatures evaluieren (WASM Performance, Browser-Support) |
| U-11 | 🟡 | Alternativ: SD-JWT Ephemeral Holder Binding Keys |
| U-12 | 🟡 | Proof-Randomisierung — gleicher Credential, anderer Output |
| U-13 | 🟢 | Issuer-Verifier Collusion Resistance (Blinded Issuance) |

### 1.3 Transparency Layer (Phase 3)
| ID | Prio | Beschreibung |
|---|---|---|
| U-20 | 🟡 | Identitäts-Firewall — Tracker-/Cookie-Zugriffe abfangen + loggen |
| U-21 | 🟡 | UI: Echtzeit-Benachrichtigung bei Identifier-Zugriff |
| U-22 | 🟢 | Anti-Fingerprinting: Wallet-Uniformität (Request-Normalisierung, Padding) |
| U-23 | 🟢 | Timing-Jitter für Netzwerk-Requests |

---

## Phase 2 — EUDI / eIDAS 2.0 Kompatibilität 🟡

### 2.1 OpenID-Protokolle
| ID | Prio | Beschreibung | Standard |
|---|---|---|---|
| E-01 | ✅ | OID4VP (OpenID for Verifiable Presentations) — E-01a–E-01d complete | OIDF.OID4VP |
| E-02 | ✅ | OID4VCI (OpenID for Verifiable Credential Issuance) — 32 tests | OIDF.OID4VCI |
| E-03 | ✅ | SIOPv2 (Self-Issued OpenID Provider v2) — 15 tests | OIDF.SIOPv2 |
| E-04 | ✅ | OAuth 2.0 Attestation-Based Client Auth — attestation+pop chain | RFC6749 ext |
| E-05 | ✅ | DPoP (Demonstrating Proof-of-Possession) — 13 tests | RFC 9449 |

### 2.2 Credential-Formate
| ID | Prio | Beschreibung | Standard |
|---|---|---|---|
| E-10 | ✅ | SD-JWT VC Compliance (draft 11) — 17 tests, vct/cnf/kb-jwt | I-D.ietf-oauth-sd-jwt-vc |
| E-11 | 🟡 | ISO/IEC 18013-5 (mdoc) Support — mobiler Führerschein | ISO.18013-5 |
| E-12 | 🟢 | Designated Verifier Signatures (JOSE draft 1) | DVS-JOSE |
| E-13 | ✅ | High Assurance Interoperability Profile — direct_post.jwt, verifier attestation | OpenID4VC HAIP |

### 2.3 Kryptographie (BSI/SOG-IS Konformität)
| ID | Prio | Beschreibung |
|---|---|---|
| E-20 | ✅ | brainpoolP256r1 Support (noble-curves, RFC 5639 §3.4) — 10 tests |
| E-21 | 🟡 | brainpoolP384r1 Support (stub — BSI param verification pending) |
| E-22 | 🟢 | brainpoolP512r1 Support (optional, höchste Sicherheit) |
| E-23 | ✅ | ECDH secp256r1 + HMAC-SHA2 MAC Verification — 10 tests |

### 2.4 Regulatory Compliance
| ID | Prio | Beschreibung | Referenz |
|---|---|---|---|
| E-30 | 🟡 | CIR 2024/2977 Compliance (PID + EAA Anforderungen) | EU Implementing Reg |
| E-31 | 🟡 | CIR 2024/2979 Compliance (Integrity + Core Functionalities) | EU Implementing Reg |
| E-32 | 🟡 | CIR 2024/2982 Compliance (Protocols + Interfaces) | EU Implementing Reg |
| E-33 | 🟡 | CIR 2024/2981 — Zertifizierungsanforderungen verstehen + Gap-Analyse | EU Implementing Reg |
| E-34 | 🟢 | CIR 2025/846 Cross-Border Identity Matching | EU Implementing Reg |
| E-35 | 🟢 | CIR 2025/848 Relying Party Registration | EU Implementing Reg |
| E-36 | 🟢 | DSGVO Verarbeitungsverzeichnis (Art. 30) | DSGVO |
| E-37 | 🟢 | Betroffenenrechte-Implementierung (Auskunft, Löschung, Berichtigung) | DSGVO |

---

## Phase 3 — Security Hardening (Salt Typhoon Patterns) 🟡

Basierend auf: `memory/miTch_security_patterns_memory.md`

| ID | Prio | Beschreibung | Angriffsmuster |
|---|---|---|---|
| S-01 | ✅ | `verifier_fingerprint` in Policy Manifest Spec | Fake Verifier Spoofing |
| S-02 | ✅ | `manifest_version` Monotonic Counter + `manifest_hash` | Manifest Rollback |
| S-03 | ✅ | Input Validation Schema (Whitelist-basiert) für Policy Parser | Claim-Name Injection |
| S-04 | ✅ | Komponenten-Isolations-Modell (Engine/Consent/Audit) | Internal Privilege Escalation |
| S-05 | ✅ | Zero Trust intern dokumentieren + implementieren | Chained Attacks |

---

## Phase 4 — Controlled Insight (Konzept) 🟢

Basierend auf: `docs/00-welt/concept_controlled_insight.md`

| ID | Prio | Beschreibung |
|---|---|---|
| CI-01 | 🟢 | Stufe 0 (Opaque) — Default, bereits implementiert durch Unlinkability |
| CI-02 | 🟢 | Stufe 1 (Mirror) — Lokale Analyse auf Device, Muster-Visualisierung |
| CI-03 | 🟢 | Stufe 2 (Delegate) — Zeitlich begrenzte, granulare Freigabe an Dienste |
| CI-04 | 🟢 | Datenwert-Dashboard (Visualisierung) |
| CI-05 | 🟢 | Delegations-Management UI mit Crypto-Shredding bei Widerruf |

---

## Housekeeping 🟢

| ID | Prio | Beschreibung |
|---|---|---|
| H-01 | ✅ | ESLint Sweep: 0 errors, 0 warnings (war 170 warnings + 2 errors) |
| H-02 | 🟢 | `mitch-temp` Repo archivieren |
| H-03 | 🟢 | `miTch---Policy-Enforcement-Layer` Repo löschen |
| H-04 | ✅ | GitHub `main` Branch löschen (nur `master` behalten) — war bereits gelöscht |
| H-05 | ✅ | `.gitattributes` mit `* text=auto eol=lf` (Line-Ending Fix) |
| H-06 | ✅ | Demo E2E Flow testen (4 Szenarien) — D-01: 17 E2E tests |
| H-07 | ✅ | Uni-Präsentation vorbereiten — OUTLINE.md + ARCHITECTURE.md |

---

## Referenzen

### EU/eIDAS
- ARF: https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- EUDI Wallet Repos: https://github.com/eu-digital-identity-wallet
- STS Roadmap: https://github.com/orgs/eu-digital-identity-wallet/projects/29/views/2
- Deutsche Architektur: https://gitlab.opencode.de/bmi/eudi-wallet/eidas-2.0-architekturkonzept
- EHDS: https://health.ec.europa.eu/ehealth-digital-health-and-care/european-health-data-space-regulation-ehds_en

### Implementing Regulations (2024-2025)
- CIR 2024/2977 (PID + EAA): https://data.europa.eu/eli/reg_impl/2024/2977/oj
- CIR 2024/2979 (Integrity): https://data.europa.eu/eli/reg_impl/2024/2979/oj
- CIR 2024/2980 (Notifications): https://data.europa.eu/eli/reg_impl/2024/2980/oj
- CIR 2024/2981 (Certification): https://data.europa.eu/eli/reg_impl/2024/2981/oj
- CIR 2024/2982 (Protocols): https://data.europa.eu/eli/reg_impl/2024/2982/oj
- CIR 2025/846 (Cross-Border): https://data.europa.eu/eli/reg_impl/2025/846/oj
- CIR 2025/848 (RP Registration): https://data.europa.eu/eli/reg_impl/2025/848/oj

### Standards
- SD-JWT: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/
- OID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OID4VCI: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- SIOPv2: https://openid.net/specs/openid-connect-self-issued-v2-1_0.html
- ISO 18013-5: https://www.iso.org/standard/69084.html
- BBS+ Signatures: https://www.w3.org/TR/vc-di-bbs/
- did:peer: https://identity.foundation/peer-did-method-spec/

### Intern
- Policy Manifest v2.0: `docs/00-welt/mitch_policy_manifest.md`
- Controlled Insight: `docs/00-welt/concept_controlled_insight.md`
- Unlinkability Vision: (workspace) `memory/unlinkability-vision.md`
- Security Patterns: (workspace) `memory/miTch_security_patterns_memory.md`
- EHDS Research: (workspace) `memory/eudi-compliance-research.md`
- Spec 111: `docs/specs/111_Unlinkability_Phase1_Pairwise_Ephemeral_DIDs.md`
