# Glossary — miTch Decoder Ring

> Acronyme, Kurzbezeichnungen, interne Begriffe.

## Projektname

| Term | Bedeutung |
|------|-----------|
| **miTch** | Privacy-preserving proof mediation middleware ("The Forgetting Layer") |
| **ZKQF** | Zero-Knowledge Query Filter — interner Name für den policy-engine Core |
| **The Forgetting Layer** | Architekturprinzip: das System vergisst Credential-Inhalte nach Nutzung |

## Architektur & Pakete

| Term | Bedeutung |
|------|-----------|
| **policy-engine** | Zentrale "Privacy Firewall" — evaluiert Disclosure Requests → ALLOW/DENY/PROMPT |
| **shared-crypto** | Alle Krypto-Primitiven (Ed25519, P-256, AES-256-GCM, JWE, WebAuthn, PQC) |
| **shared-types** | Zentrale TypeScript-Typdefinitionen |
| **layer-resolver** | Löst Trust-Layer und Credential-Schemas auf |
| **wallet-pwa** | React 18 + Vite PWA (Port 5174) |
| **issuer-mock** | Mock-Credential-Issuer (Port 3005) |
| **verifier-demo** | Demo-Verifier (Port 3004) |
| **oid4vci** | OpenID for Verifiable Credential Issuance (Wallet-Seite) |
| **oid4vp** | OpenID for Verifiable Presentations (Wallet-Seite) |
| **oid4vp-verifier** | OID4VP Verifier-Seite |
| **mdoc** | ISO 18013-5 mDL/mdoc — mobiler Führerschein |
| **verifier-sdk** | Verifier-Integrationsbibliothek |
| **anchor-service** | Merkle Batch Anchoring + L2-Provider Stubs |
| **revocation-statuslist** | StatusList2021, Multi-Source-Resolver |
| **secure-storage** | IndexedDB-backed verschlüsselter Speicher |
| **secure-memory** | Memory-safe Credential-Handling |
| **audit-log** | Immutable Audit-Trail |
| **webauthn-verifier** | WebAuthn + Step-Up Authentication |
| **predicates** | Predicate Proof Definitions (age-over, range, set-membership) |
| **wallet-core** | Core Wallet-Logik; `WalletService.ts` ist aktuell ein grosser Orchestrator (1395 LOC, Scan 2026-05-25) |
| **data-flow** | `@mitch/data-flow` — Transaction View Package |

## Kryptographie

| Term | Bedeutung |
|------|-----------|
| **PQC** | Post-Quantum Cryptography |
| **ML-DSA** | Module-Lattice Digital Signature Algorithm (via @noble/post-quantum) |
| **ML-KEM** | Module-Lattice Key Encapsulation Mechanism |
| **HKDF** | HMAC-based Key Derivation Function |
| **JWE** | JSON Web Encryption |
| **DPoP** | Demonstrating Proof-of-Possession (RFC 9449) |
| **SD-JWT VC** | Selective Disclosure JWT Verifiable Credential |
| **KB-JWT** | Key Binding JWT |
| **COSE** | CBOR Object Signing and Encryption |
| **MSO** | Mobile Security Object (mdoc) |
| **SSS** | Shamir's Secret Sharing |
| **brainpool** | BSI/SOG-IS konforme elliptische Kurven (P256r1, P384r1, P512r1) |

## Standards & Regulatorik

| Term | Bedeutung |
|------|-----------|
| **eIDAS 2.0** | EU-Verordnung über elektronische Identifizierung |
| **EUDI** | European Digital Identity (Wallet) |
| **GDPR Art. 25** | Datenschutz durch Technikgestaltung (Privacy by Design) |
| **CIR** | Commission Implementing Regulation (EU) |
| **PID** | Person Identification Data |
| **EAA** | Electronic Attestation of Attributes |
| **HAIP** | High Assurance Interoperability Profile |
| **SIOPv2** | Self-Issued OpenID Provider v2 |
| **STRIDE** | Security Threat Modelling Framework (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation) |

## Task-IDs

| Präfix | Bereich |
|--------|---------|
| **G-xx** | Gap / Foundation (Phase 0) |
| **U-xx** | Unlinkability (Phase 1) |
| **E-xx** | EUDI / eIDAS 2.0 Kompatibilität (Phase 2) |
| **S-xx** | Security Hardening (Phase 3, Salt Typhoon Patterns) |
| **CI-xx** | Consent Intelligence |
| **AI-xx** | Audit / Internal Findings |
| **AD-xx** | Ad-Tech Privacy Features |
| **F-xx** | Sprint Plan Audit Findings |
| **H-xx** | Hygiene / Housekeeping |
| **F-ARCH-xxx** | Findings aus `ARCHITECTURE_ANALYSIS_PROCESS_V2`, z.B. `F-ARCH-003` fuer `policy_hash` Semantik |

## Branches & Versionen

| Term | Bedeutung |
|------|-----------|
| **master** | Default-Branch (direkt committen nach jedem Block) |
| **pilot-ready-p0** | Release-Tag: Pilot-Ready Status |

## Commit-Stil

`feat:`, `fix:`, `docs:`, `test:`, `chore:` + `(package-name): Kurzbeschreibung`

## Sprint-Begriffe & Rollen

| Term | Bedeutung |
|------|-----------|
| **Sprint-Kandidat** | Potentielle nächste Sprints — dokumentiert in `docs/tasks/SPRINT_CANDIDATES.md` |
| **Review 1 / Review 2 / Abschlussreview** | Dreistufige Review-Gates in jedem Sprint (Scope → Plan → Fertig) |
| **Consent Manager** | Visualisierungsschicht: ConsentModal + DataFlowPanel + ConsentReceipt + DecisionCapsule |
| **ConsentModal** | UI-Komponente: startet Zustimmung im Wallet |
| **ConsentReceipt** | Evidence-Objekt: nachweisbarer Consent-Nachweis |
| **DataFlowPanel** | UI: zeigt Transaktions-, Claim- und Firewall-Sicht |
| **PrivacyAuditService** | Service: Sichtbarkeits-/Tracker-Kontext für DataFlowPanel |
| **Identity Firewall** | Sprint 1 — erkennt und loggt Identifier-/Tracker-/Cookie-Zugriffe |
| **MKT-xx** | Marketing / Landing-Page Tasks (interne Nummerierung) |
| **Antigravity** | Rolle / Akteur — zuständig für UX-Entscheidungen (`standalone.html`) |
| **Architecture Analysis Process v2** | `docs/03-architecture/ARCHITECTURE_ANALYSIS_PROCESS_V2_2026-05-24.md`; Arbeitsstandard fuer Architekturpruefungen |
| **Coding Agent Handoff** | `docs/03-architecture/CODING_AGENT_HANDOFF_2026-05-25.md`; Startpunkt fuer Folgearbeit |
| **UNKNOWN => FAIL** | Privacy-Firewall-Regel: unklare Architektur-/Policy-/Code-Aussagen gelten als nicht bestanden, bis sie belegt sind |

## Interne Sicherheitsmuster

| Term | Bedeutung |
|------|-----------|
| **fail-closed** | Bei Ambiguität → DENY. Nie default zu ALLOW. |
| **DecisionCapsule** | Felder: `verdict`, `decision_id`, `policy_hash` (NICHT `policy_manifest_id`) |
| **policy_hash** | Soll laut DecisionCapsule-Spec den aktiven `PolicyManifest` hashen; aktueller Codebefund vor Handoff: Engine hasht `matchedRule`, siehe `F-ARCH-003` |
| **ConsentReceiptV1** | Noch nicht kanonisch entschieden; aktuell in Wallet-PWA und OID4VP Demo Flow vorhanden, siehe `F-ARCH-005` |
| **PrivacyReasonCode** | Deterministische Reason Codes aus dem Privacy-Firewall-Skill, z.B. `FAIL_SPEC_AMBIGUOUS`, `FAIL_POLICY_MISMATCH`, `FAIL_STORE_RAW_PII` |
| **Salt Typhoon Patterns** | Interne Bezeichnung für Phase-3-Sicherheitshärtung (nach dem Angriffsmuster) |
| **crypto-shredding** | Schlüssel löschen um Daten unlesbar zu machen |
| **pairwise DID** | Für jeden Verifier unterschiedliche DID → Unlinkability |
| **proof-fatigue** | Rate-Limiting für Disclosure-Requests |
| **ReDoS** | Regular Expression Denial of Service |
