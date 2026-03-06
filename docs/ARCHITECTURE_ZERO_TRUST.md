# miTch — Zero Trust Interne Architektur

**Stand:** 2026-03-06
**Scope:** S-05 — Zero Trust intern dokumentieren + implementieren
**Referenz:** BACKLOG S-05, Spec 112 (Component Isolation), Salt Typhoon Attack Patterns

---

## Prinzip: "Never Trust, Always Verify" — auch intern

Das klassische Sicherheitsmodell vertraut allem innerhalb des eigenen Prozesses oder Browsers.
miTch lehnt dieses Modell ab.

**Grund:** Supply-Chain-Angriffe (kompromittierte NPM-Pakete), Browser-Extensions, modifizierte
Service Workers und XSS können Komponenten innerhalb derselben Origin kompromittieren.

Jede Komponente behandelt andere Komponenten als **potentiell feindlich**,
bis das Gegenteil durch kryptografische Mittel nachgewiesen ist.

---

## Zero Trust Axiome für miTch

| # | Axiom | Implementierung |
|---|---|---|
| ZT-1 | Kein implizites Vertrauen | Jede Komponente validiert ihre Inputs, unabhängig von der Quelle |
| ZT-2 | Minimale Berechtigungen | Policy Engine sieht nur Metadaten — niemals Rohdaten |
| ZT-3 | Explizite Autorisierung | ALLOW-Verdicts erfordern signierten DecisionCapsule + Nonce |
| ZT-4 | Continuous Verification | Rate Limiting + Risk Scoring per Verifier-Session |
| ZT-5 | Fail Closed | Jede Unsicherheit resultiert in DENY oder PROMPT — niemals silent ALLOW |
| ZT-6 | Kryptografische Bindung | Pairwise DIDs + Capsule-Signaturen — keine Trust-by-Origin |
| ZT-7 | Audit alles | Jede Entscheidung wird lokal geloggt — kein "Dark Access" |

---

## Interne Vertrauens-Topologie

```
Externer Verifier
      │
      │  VerifierRequest (validiert: S-03 Input Validation)
      ▼
┌──────────────────────────────────────────────────────────────┐
│                        Shell (WalletService)                 │
│                                                              │
│  Orchestriert, aber vertraut keiner Komponente blind:        │
│                                                              │
│  1. Manifest-Rollback-Check (S-02) ─────────────────────┐   │
│  2. Input Validation (S-03) ────────────────────────┐   │   │
│  3. Fingerprint in Request prüfbar (S-01) ──────┐   │   │   │
│                                                 │   │   │   │
│  ┌──────────────┐          ┌────────────────┐   │   │   │   │
│  │ Policy Engine│◄─Metadaten─ Credential   │   │   │   │   │
│  │              │          │    Store       │   │   │   │   │
│  │ Returns:     │          │  (Encrypted)   │   │   │   │   │
│  │ Signed       │          │                │   │   │   │   │
│  │ Capsule      │          │ Rohdaten NUR   │   │   │   │   │
│  │              │          │ nach ALLOW     │   │   │   │   │
│  └──────────────┘          └────────────────┘   │   │   │   │
│          │                                      │   │   │   │
│          │ Shell verifiziert Capsule-Signatur   │   │   │   │
│          ▼                                      │   │   │   │
│  ┌──────────────┐          ┌────────────────┐   │   │   │   │
│  │ Audit Logger │◄─Events─ Consent Store    │   │   │   │   │
│  │ (append-only)│          │ (Grant/Revoke) │   │   │   │   │
│  └──────────────┘          └────────────────┘   │   │   │   │
└──────────────────────────────────────────────────────────────┘
```

---

## Zero Trust Maßnahmen je Angriffsvektor

### Chained Attacks (Salt Typhoon Pattern)
Ein Angreifer kompromittiert eine Komponente und versucht, sich darüber zu anderen
vorzuarbeiten.

**Mitigationen:**
- `ZT-2`: Policy Engine hat KEINEN Schreibzugriff auf Consent Store oder Audit Logger
- `ZT-3`: Shell verifiziert `wallet_attestation` des DecisionCapsule — manipulierte
  Engine-Outputs werden erkannt
- `ZT-6`: Pairwise DIDs — Verifier können nicht erkennen, welcher Nutzer mehrere
  Anfragen stellt, auch wenn eine Session kompromittiert wurde
- `I-7` (Spec 112): Kein Modul akzeptiert seinen eigenen Output als Input

### Supply Chain Compromise (kompromittiertes NPM-Paket)
Ein Paket wird kompromittiert und versucht, Policy-Entscheidungen zu manipulieren.

**Mitigationen:**
- `ZT-1`: Policy Manifest ist versioniert + gehasht (S-02) — Manipulation wird erkannt
- `ZT-5`: Fail-Closed: Jede Exception in der Engine resultiert in DENY
- `S-02`: Rollback-Schutz verhindert Downgrade auf ältere, schwächere Policy-Versionen
- Subresource Integrity (SRI) für Bundles (geplant, H-06)

### Browser Extension / XSS
Extension versucht, Policy-Entscheidungen abzufangen oder zu modifizieren.

**Mitigationen:**
- `ZT-6`: DecisionCapsule ist ECDSA-signiert — Modifikation wird erkannt
- `ZT-3`: Nonce in Capsule — Replay-Schutz (5-Minuten-Expiry)
- `ZT-4`: Rate Limiting pro Verifier-Session — Burst-Angriffe werden geblockt
- Pairwise DIDs (U-05) — kein persistenter Identifier für Extension sichtbar

### Fake Verifier Spoofing
Ein Angreifer gibt vor, ein anderer Verifier zu sein.

**Mitigationen:**
- `S-01`: `verifier_fingerprint` in Policy Manifest — Mismatch → PROMPT (nie auto-ALLOW)
- `ZT-5`: Unbekannte Verifier → DENY by Default (`blockUnknownVerifiers: true`)
- DID-basierte Identität — kein IP-Spoofing möglich

### Manifest Rollback
Angreifer ersetzt neues Policy-Manifest durch älteres, schwächeres.

**Mitigationen:**
- `S-02`: `manifest_version` als monotoner Zähler — Rollback wird erkannt
- `S-02`: `manifest_hash` — Tamper-Erkennung beim Laden
- Shell prüft `checkManifestRollback()` VOR jedem `engine.evaluate()`

---

## Fail-Closed-Garantien

| Fehlerfall | Verhalten |
|---|---|
| Policy Engine wirft Exception | DENY |
| Manifest fehlt manifest_version | Validation schlägt fehl → kein evaluate() |
| Fingerprint im Request fehlt | PROMPT (nie auto-ALLOW) |
| DID-Resolution schlägt fehl | DENY (G-01) |
| Revocation-Check schlägt fehl | DENY (G-02) |
| Ephemeral Key kann nicht generiert werden | Engine loggt Error, Capsule ohne pairwise_did |
| Capsule-Signatur kann nicht verifiziert werden | Shell akzeptiert Result nicht |
| Credential ist expired | DENY |
| Rate Limit überschritten | DENY (RATE_LIMIT_EXCEEDED) |
| Risk Score zu hoch | PROMPT (HIGH_RISK_VERIFIER) |

---

## Nicht-funktionale Anforderungen

| Eigenschaft | Wert | Quelle |
|---|---|---|
| DecisionCapsule-Expiry | 5 Minuten | engine.ts |
| Rate Limit | 10 Requests/Minute/Verifier | engine.ts |
| Risk Score Threshold | 5 Excess Claims | engine.ts |
| Pairwise DID Lifetime | 1 Interaction (shred after use) | pairwise-did.ts |
| Ephemeral Key Shredding | Sofort nach Signatur | U-04 |
| Manifest Version Check | Vor jedem evaluate() | S-02 |
| Input Validation | Vor jedem evaluate() | S-03 |

---

## Geplante Erweiterungen (Phase 2+)

- **TEE-Attestation:** Policy Engine in Trusted Execution Environment (Spec 53)
- **SRI für Bundles:** Subresource Integrity für JS-Bundles im PWA
- **Content Security Policy:** Strict CSP gegen XSS/Extension-Injections
- **Quorum-basierte DID-Resolution:** Mehrere Resolver, Konsensus-Check (Spec 84)
- **HKDF-basierte Pairwise DIDs:** Phase 2 — deterministisch aus Master-Key (Spec 111)

---

## Referenzen

- Spec 112: Komponenten-Isolations-Modell (`docs/specs/112_Component_Isolation_Model.md`)
- Spec 111: Pairwise-Ephemeral DIDs (`docs/specs/111_Unlinkability_Phase1_Pairwise_Ephemeral_DIDs.md`)
- Threat Model: `docs/specs/05_Threat_Model.md`
- Agentic Threats: `docs/specs/49_Agentic_Threat_Model_and_Controls.md`
- Salt Typhoon Patterns: BACKLOG S-01–S-05
