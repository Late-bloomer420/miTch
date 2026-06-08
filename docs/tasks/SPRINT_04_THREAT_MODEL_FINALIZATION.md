# Sprint 4: Threat Model Finalization

Stand: 2026-06-08
Quelle: `docs/tasks/SPRINT_CANDIDATES.md` (Kandidat #4)
Status: Review 1+2 entschieden; ADR-009 (mvp) auf "Accepted (technical) / pending external review" angehoben

## Sprint-Ziel

`ADR-009_Threat_Model.md` (mvp) in einen reviewbaren, pilotfähigen Security-Artefaktstand
bringen — ohne neue Threats zu erfinden, aber mit ehrlicher Bestandsaufnahme nach Sprint 1
(Identity Firewall) und Sprint Proof-Randomization, deren Mitigations die ADR noch nicht
abbildet.

## Bestandsaufnahme (2026-06-08)

### Was schon existiert

- **`docs/03-architecture/mvp/ADR-009_Threat_Model.md`** (214 Z., Status `PROPOSED` seit
  2026-03-18) — vollständige STRIDE-Tabelle mit 22 Einträgen, alle Evidenz-Status `belegt`,
  jeweils mit Test-Referenz. Manifest-Prinzip-Abdeckung über alle 4 Säulen. 3 Test-Szenarien
  (Cold-Boot, Verifier-Collusion, Device-Loss). Gap-Analyse mit 4 Gaps (1 🔴, 3 🟡). Bleibt
  PROPOSED wegen GAP-4 (externer Security-Reviewer fehlt).
- `docs/specs/05_Threat_Model.md` — praktisches Threat Model (T-01..T-06).
- `docs/specs/49_Agentic_Threat_Model_and_Controls.md` — Agentic Threats (T-A1..T-A6).
- `docs/ops/EVIDENCE_PACK_P0.md` — Guarantee Evidence (G-01..G-06).

### Befund: Namens-Doppelung "ADR-009"

`docs/compliance/ADR/ADR-009.md` ist **inhaltlich ein anderer ADR** (WebAuthn Native vs.
HMAC-Proxy Mode), nicht das Threat Model. Das ist die im DOCS_CANON dokumentierte
Nummerierungs-Trennung zweier ADR-Sammlungen (mvp/, compliance/ADR/) — kein Bug, aber für
Auditoren irreführend ohne Cross-Pointer. Dieser Sprint setzt den Pointer.

### Befund: ADR-009 (mvp) ist veraltet bzgl. Sprint 1 + Sprint Proof-Randomization

Zwei Aussagen in ADR-009 (mvp) sind seit den jüngsten Sprints nicht mehr aktuell:

1. **Szenario 2 Verifier-Collusion, Residualrisiko:** "Kein Request-Jitter implementiert".
   → Nicht mehr wahr. `src/apps/wallet-pwa/src/utils/anti-fingerprinting.ts` enthält die
   Sektion *"U-23: Network Timing Jitter"* sowie Header-/JSON-Uniformität und
   Payload-Padding (U-22) — geliefert in der ursprünglichen Phase-1.3-Gruppe (siehe
   BACKLOG Legacy-Audit-Tabelle).

2. **STRIDE-Tabelle, Kategorie I (Information Disclosure):** Kein Eintrag für
   Identifier-/Tracker-Zugriffe durch Browser/Netzwerk/OS-Layer, obwohl
   `IDENTITY_ACCESS_DETECTED`-Audit-Events + PII-minimale `IdentityFirewallMetadata` +
   DataFlow `identity`-Kategorie auf master liegen (Sprint 1 — siehe
   `SPRINT_01_IDENTITY_FIREWALL.md` Abschlussreview 2026-06-07).

3. **Proof-Randomization (U-11/U-12):** Sprint
   `SPRINT_PROOF_RANDOMIZATION.md` hat ephemerale Holder-Bindings + Single-Use-Pool-
   Selektion live auf master. Das verstärkt das Verifier-Collusion-Szenario gegenüber
   stabilen Holder-Keys / wiederverwendeten Signaturen.

## Review 1 — Scope & Erwartung

Entscheidungen:

- **Kein neues Threat-Modell.** Die vorhandene STRIDE-Tabelle ist die kanonische Form.
- **Aktualisieren, nicht ersetzen.** Sprint-1/Sprint-Proof-Randomization-Mitigations werden
  als zusätzliche STRIDE-Zeilen + Update der Residualrisiken eingepflegt.
- **Statuswechsel mit ehrlicher Granularität.** ADR-009 (mvp) wird von `PROPOSED` auf
  `Accepted (technical) — pending external review` angehoben: die technischen
  Acceptance-Criteria sind erfüllt; GAP-4 (externer Security-Reviewer) bleibt explizit
  als menschliche Voraussetzung für vollen `Accepted` dokumentiert.
- **Namens-Doppelung "ADR-009"** wird über einen Cross-Pointer im DOCS_CANON (und ein
  kurzer "siehe-auch"-Vermerk in beiden Dateien) eindeutig gemacht — nicht durch Rename
  (das hieße ADR-IDs umnummerieren, was Quer-Verweise bricht).

## Review 2 — Konkrete Änderungen in diesem PR

Dieser Sprint ist doc-only. Keine Code-Änderungen, keine neuen Tests.

### 1. ADR-009 (mvp) Update

- Status: `Accepted (technical) — pending external review` (statt `PROPOSED`).
- Neue STRIDE-Zeilen in Kategorie I (Information Disclosure):
  - **I-8 — Browser/OS/Network-layer Identifier-Zugriffe** → `IDENTITY_ACCESS_DETECTED` +
    `IdentityFirewallMetadata` mit `actor_label`-Sanitizing, `blocked: false` (informierend),
    keine Roh-PII (Sprint 1 Abschlussreview).
  - **I-9 — Cross-Verifier-Korrelation über stabile Holder-Bindings/Signaturen** →
    Ephemeral Holder Binding (`generateHolderBinding()`) + Single-Use Credential Pool
    (`credential-pool.ts` mit Fail-closed Exhaustion). Honesty-Boundary explizit dokumentiert:
    Unlinkability durch Nicht-Wiederverwendung, nicht durch Multi-Show-Krypto (BBS+ deferred).
- Neue D-Zeile (Denial of Service / Side-Channel-nahe):
  - **D-4 — Traffic-Analyse über Request-Größe/-Timing** → Header-/JSON-Normalisierung,
    Payload-Padding (U-22), Timing-Jitter (U-23) in `anti-fingerprinting.ts`.
- Szenario 2 (Verifier-Collusion) Residualrisiko aktualisiert: Timing-Jitter ist nicht
  mehr "kein dedizierter Test" — `anti-fingerprinting.test.ts` deckt es ab. Ergänzt um
  den Hinweis auf Proof-Randomization als neue Mitigation-Säule.
- Gap-Analyse: GAP-3 (Timing-Side-Channel) auf `teilweise belegt` runtergestuft (U-23
  liefert Jitter; dedizierter Anti-Oracle-Timing-Test bleibt offen). GAP-4 (externer
  Reviewer) bleibt 🔴.
- Change Log: Eintrag `2026-06-08: Sprint-1+Proof-Randomization Mitigations integriert,
  Status -> Accepted (technical); GAP-4 (externer Review) offen`.

### 2. `docs/compliance/ADR/ADR-009.md` & ADR-009 (mvp) — Cross-Pointer

Je ein kurzer "Hinweis"-Block am Anfang beider Dateien:

> Es existieren zwei `ADR-009`-Dateien mit unterschiedlichem Thema (mvp: Threat Model;
> compliance: WebAuthn Native vs. HMAC-Proxy). Beide sind authoritative in ihrer
> Sammlung. Siehe `docs/DOCS_CANON.md` "Architecture Decision Records (3 Sammlungen)".

### 3. DOCS_CANON — Punkt-Eintrag

Eine zusätzliche Zeile unter "Architecture Decision Records (3 Sammlungen)" mit Hinweis
auf die ADR-009-Doppelung samt Themenabgrenzung.

## Out of Scope

- Externer Security-Review (Voraussetzung für `Accepted` ohne Zusatz) — bleibt offen.
- Neue Threats erfinden, die nicht durch geliefert Code mitigated sind.
- ADR-Renumbering / Umbenennen.
- Tooling-/CI-Änderungen.

## Acceptance Criteria

- ADR-009 (mvp) Status: `Accepted (technical) — pending external review`.
- Identity Firewall (Sprint 1) und Proof-Randomization (Sprint) erscheinen als
  STRIDE-Zeilen mit Code-Pointern.
- Verifier-Collusion-Szenario Residualrisiko ist faktisch korrekt (Jitter vorhanden).
- DOCS_CANON enthält den Cross-Pointer zur ADR-009-Doppelung.
- Bestehende STRIDE-Tabellen-Zeilen bleiben unverändert (kein Rewriting der Historie).
- Kein Code-Change.
