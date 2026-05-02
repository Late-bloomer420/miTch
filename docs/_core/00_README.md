# miTch — Arbeitsoberfläche

**Einstiegspunkt für alle Sessions. Hier beginnt jede Arbeit.**

---

## Was ist miTch?

Privacy-Infrastruktur für regulierte Märkte. Kein Identitätsanbieter.  
Kein Datenverwalter. **Convener eines regelbasierten Ökosystems.**

Technisch: Selective Disclosure + Policy Engine + Crypto-Shredding.  
Rechtlich: DSGVO-konform durch Konstruktion, nicht durch Versprechen.

---

## Kernverzeichnis

| Dokument | Inhalt | Status |
|---|---|---|
| [01_NORTH_STAR.md](01_NORTH_STAR.md) | Mission & Werte | Bindend |
| [02_POLICY.md](02_POLICY.md) | Nicht-Verhandelbarkeiten | Bindend |
| [03_ARCHITECTURE.md](03_ARCHITECTURE.md) | Technische Grundlage | Bindend |
| [04_MARKET.md](04_MARKET.md) | Wettbewerb & Lücken (Stand 05.2026) | Aktuell |
| [05_LEGAL.md](05_LEGAL.md) | DSGVO-Basis & Crypto-Shredding | Bindend |
| [06_OPEN_DECISIONS.md](06_OPEN_DECISIONS.md) | Offene Entscheidungen | Aktiv |
| [07_ROADMAP.md](07_ROADMAP.md) | Was als nächstes kommt | Aktiv |

---

## Wo liegt der Code?

```
src/packages/
├── policy-engine/        ← Fail-Closed Policy Engine (STABLE)
├── shared-crypto/        ← Crypto-Shredding, Key Guardian (STABLE)
├── sd-jwt-vc/            ← Credential Stack (STABLE)
├── layer-resolver/       ← Layer 0/1/2 Modell (STABLE)
├── wallet-core/          ← Wallet Sync/CRDT (IN PROGRESS)
└── webauthn-verifier/    ← WebAuthn Step-Up Auth (IN PROGRESS)
```

---

## Wo liegen die ADRs (Architecture Decision Records)?

`docs/03-architecture/mvp/` — ADR-001 bis ADR-012  
ADR-001 (Credential Stack: SD-JWT VC) ist die wichtigste.

---

## Was gehört NICHT hierher?

Session-Logs, Nightly Reports, Experimental Specs → `docs/archive/`  
Alles mit Stand vor 2026-02-16 → wahrscheinlich überholt, prüfen.

---

## Wichtige Regel

Ein Dokument in `_core/` ist bindend oder aktiv.  
Wenn es weder das eine noch das andere ist — gehört es nicht hierher.
