# miTch Roadmap

> **Historical strategy snapshot:** the May 2026 schedule below is not the active delivery baseline. Use [release roadmap](../RELEASE_READINESS_ROADMAP.md), [GTM plan](../GTM_SPRINT_ROADMAP.md), [findings](../security/REPO_EVIDENCE_STATUS_2026-10-14.md) and #142/#143. No old “stable”/date closes current gates.

**Stand: 02.05.2026 | Basis: Inventur 02.05.2026 + MVP Stand 2026-02-16**

---

## Jetzt stabil (STABLE)

- `policy-engine` — Fail-Closed, 42/42 Tests ✓
- `shared-crypto` — Crypto-Shredding, Key Guardian ✓
- `sd-jwt-vc` — Credential Stack (SD-JWT, ES256) ✓
- `layer-resolver` — Layer 0/1/2 Modell ✓

**Vor kommerziellem Einsatz: Sicherheitsaudit `shared-crypto` + `policy-engine` empfohlen.**

---

## BUILD NOW (0–3 Monate)

| Aufgabe | Paket | Warum |
|---|---|---|
| Wallet Sync / CRDT fertigstellen | `wallet-core` | Produkt B Fundament |
| WebAuthn Step-Up Auth | `webauthn-verifier` | Regulierte Märkte brauchen starke Auth |
| Erster Pilot-Partner identifizieren | Business | Revenue + Validierung |
| Förderantrag vorbereiten (DEP/FFG) | Business | Alternative Finanzierung |

---

## BUILD NEXT (3–6 Monate)

| Aufgabe | Abhängigkeit |
|---|---|
| SQL Storage Layer (Drizzle ORM, aus M.I.T.C.H.) | wallet-core stabil |
| Parser: Google Takeout / Meta / Browser History | wallet-core stabil |
| Privacy Revocation Design für Sportwetten | Pilot-Partner definiert |
| Cross-Predicate Proofs (age + residency + license) | sd-jwt-vc Erweiterung |

---

## BUILD LATER (6–18 Monate)

| Aufgabe | Voraussetzung |
|---|---|
| Probabilistische Inferenz (Produkt B) | Ethik-Review, AI-Act Prüfung |
| Multi-Device Sync | wallet-core production-ready |
| Sportwetten Pilot (vollständig) | Privacy Revocation gelöst |
| Health Pilot | Regulatorische Klärung EHDS |
| ML-DSA Migration (Post-Quantum) | Library-Reifegrad |
| Digital Euro Integration | Gesetzgebung 2026 + Pilot 2027 |

---

## Was NICHT auf der Roadmap steht (bewusst)

- Blockchain-Abhängigkeit
- Zentrales Nutzerprofil
- Custodial Asset Management
- Eigene Credential-Issuance (miTch ist kein Issuer)

---

## Meilensteine

| Datum | Meilenstein |
|---|---|
| 2026-02-16 | MVP Complete — 42/42 Tests, 0 TS-Errors |
| 2026-05-02 | Marktanalyse + Strategische Neuausrichtung |
| 2026-Q3 | Erster Pilot-Partner (Ziel) |
| 2026-Q4 | Förderantrag eingereicht (Ziel) |
| 2027 | Produkt A kommerziell (Ziel) |
| 2028+ | Digital Euro Layer Opportunity |
