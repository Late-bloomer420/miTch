# TASKS.md — miTch Productivity Tracker

> Aktiver Task-Überblick für den täglichen Arbeitsfluss.
> Detailliertes Tracking mit Einzel-IDs: [`docs/BACKLOG.md`](docs/BACKLOG.md)
> Sprint-Docs: [`docs/tasks/`](docs/tasks/)
> Operativer Health-Snapshot: [`STATE.md`](STATE.md)

**Stand:** 2026-05-22
**Letzte Aktualisierung:** 2026-05-22 (via /productivity:update — Git-Log-Abgleich)
**Projektstand:** Alle P0 + P1 Gaps geschlossen. Pilot-Ready (`pilot-ready-p0`). Phase 2–3 laufend.

---

## 🔴 Active — In Arbeit

### U-20 — Identitäts-Firewall (Implementation v1 complete, Abschlussreview pending)
- Sprint-Doc: [`docs/tasks/SPRINT_01_IDENTITY_FIREWALL.md`](docs/tasks/SPRINT_01_IDENTITY_FIREWALL.md)
- Was passiert ist: Identity-Firewall-Events (`IDENTIFIER_ACCESS`, `COOKIE_ACCESS`, etc.) in Audit-Log + `WalletService` + `DataFlowPanel` integriert — commit `386d07e` (2026-05-20)
- Nächster Schritt: **Abschlussreview durch Reviewer/Security** (Fail-closed-Verhalten, Datenschutz-Logik, UI-Texte)
- Backlog-Status bleibt 🟡 bis Review abgeschlossen

### U-21 — UI: Echtzeit-Benachrichtigung bei Identifier-Zugriff
- Hängt direkt an U-20 — Firewall-Events werden bereits in DataFlowPanel angezeigt
- Abschlussreview gemeinsam mit U-20 erledigen

---

## 🟡 Next Up — P1 (wichtig, bald)

- [ ] **U-10** — BBS+ Signatures evaluieren (WASM Performance, Browser-Kompatibilität)
- [ ] **U-11** — SD-JWT Ephemeral Holder Binding Keys (Alternative zu BBS+)
- [ ] **U-12** — Proof-Randomisierung: gleicher Credential, unterschiedlicher Output
  - Sprint-Kandidat: [`docs/tasks/SPRINT_CANDIDATES.md`](docs/tasks/SPRINT_CANDIDATES.md) — "Proof-Randomisierung"
- [ ] **E-30** — CIR 2024/2977 Compliance (PID + EAA Anforderungen)
- [ ] **E-31** — CIR 2024/2979 Compliance (Integrity + Core Functionalities)
- [ ] **E-32** — CIR 2024/2982 Compliance (Protocols + Interfaces)
- [ ] **E-33** — CIR 2024/2981 — Zertifizierungsanforderungen + Gap-Analyse
  - Sprint-Kandidat: [`docs/tasks/SPRINT_CANDIDATES.md`](docs/tasks/SPRINT_CANDIDATES.md) — "Compliance Gap Sprint"
- [ ] **S-10** — Formales Threat Model (STRIDE)
  - ADR-009 vollständig (STRIDE-Tabelle, 22 Einträge, 3 Szenarien, 4 Gaps) — commit `428dc4c` (2026-03-18)
  - Status: **PROPOSED** — blockiert auf externem Security Review (menschliche Vorbedingung)
  - Keine Code-Arbeit möglich bis externer Reviewer bestätigt

---

## 🟢 Someday — P2 (nice-to-have)

- [ ] **U-13** — Issuer-Verifier Collusion Resistance (Blinded Issuance)
- [ ] **U-22** — Anti-Fingerprinting: Wallet-Uniformität (Request-Normalisierung, Padding)
- [ ] **U-23** — Timing-Jitter für Netzwerk-Requests
- [ ] **E-12** — Designated Verifier Signatures (JOSE draft 1)
- [ ] **E-22** — brainpoolP512r1 Support (optional, höchste Sicherheit)
- [ ] **E-34** — CIR 2025/846 Cross-Border Identity Matching
- [ ] **E-35** — CIR 2025/848 Relying Party Registration
- [ ] **E-36** — DSGVO Verarbeitungsverzeichnis (Art. 30)
- [ ] **E-37** — Betroffenenrechte-Implementierung (Auskunft, Löschung, Berichtigung)
- [ ] **CI-02** — Stufe 1 (Mirror): Lokale Analyse auf Device, Muster-Visualisierung
- [ ] **CI-03** — Stufe 2 (Delegate): Zeitlich begrenzte, granulare Freigabe an Dienste
- [ ] **CI-04** — Datenwert-Dashboard (Visualisierung)
- [ ] **CI-05** — Delegations-Management UI mit Crypto-Shredding bei Widerruf
- [ ] **H-02** — `mitch-temp` Repo archivieren
- [ ] **H-03** — `miTch---Policy-Enforcement-Layer` Repo löschen
- [ ] **MKT-01** — Landing Page Review — Standalone-Seite + Claim-Evidence-Map fertig (commits `48a1165`, `47954fd`, `fe37d6c`, 2026-05-20/21); Review auf Richtigkeit und Vollständigkeit ausstehend

---

## ✅ Zuletzt abgeschlossen

### Mai 2026

- [x] **Sprint 2 — Consent Manager Data Visualization** — `Implementation v5 complete` (2026-05-21)
  - Sprint-Doc: [`docs/tasks/SPRINT_02_CONSENT_MANAGER_DATA_VISUALIZATION.md`](docs/tasks/SPRINT_02_CONSENT_MANAGER_DATA_VISUALIZATION.md)
  - Umfang: ConsentModal + DataFlowPanel + ConsentReceipt als gemeinsame Visualisierungsschicht
  - Commits: `9a2824f` (View Model), `97aeab0` (History), `ae91f48` (Pagination)
- [x] **E-21** — brainpoolP384r1 Support (RFC 5639 §3.6, SHA-384, 7 Tests + 2 Cross-Curve) — `03c95b2` (2026-05-16)
- [x] **E-11** — ISO 18013-5 mdoc vollständig: COSE_Mac0 + ECDH Key Derivation — `be5f631` (2026-05-16)

### Frühere Sessions (Überblick)

- [x] Phase 0 Foundation (G-01–G-10) — DID, Revocation, Policy, Crypto
- [x] Phase 1 Unlinkability (U-01–U-05) — Pairwise DIDs, Key Shredding
- [x] U-18/U-19/U-19a — Data Flow Transparency Panel + `claimsWithheld`
- [x] E-01–E-05 — OID4VP, OID4VCI, SIOPv2, OAuth-Attestation, DPoP
- [x] E-10 — SD-JWT VC Compliance (draft 11)
- [x] E-13 — HAIP (High Assurance Interop Profile)
- [x] E-20 — brainpoolP256r1 Support
- [x] S-01–S-09 — Security Hardening (Salt Typhoon Patterns)
- [x] F-01–F-18 — Sprint Plan Audit-Fixes (Security Hardening Session 10)
- [x] Alle AI-01–AI-06 + AD-01–AD-05 Findings geschlossen
