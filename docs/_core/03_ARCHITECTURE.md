# miTch / AskMI Architecture — Technische Grundlage

**Stand: Historical MVP Snapshot (2026-02-16) | Scoped API & Protocol Reality Update: 2026-11-03 | Stack: TypeScript Monorepo**

> **Aktuelle Architektur- & Protokoll-Evidenz (2026-11-03):** Siehe [`docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](../qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md) und den 4-Stufen-Zielarchitektur-Plan [`docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md`](../tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md).

---

## Credential Stack (ADR-001, ACCEPTED — aktualisiert 2026-11-03)

**Primary:** SD-JWT VC (Selective Disclosure JWT Verifiable Credentials) + ISO/IEC 18013-5 `mso_mdoc` (`@askmi/mdoc`)  
**Implementierung (`@askmi/shared-crypto`):** Eigene In-House-Implementierung (`sd-jwt-vc.ts`) auf Basis von `jose` und WebCrypto (`crypto.subtle`); **keine** externen `@sd-jwt/*`-Pakete (`API-06`, korrigiert 2026-11-03; die historische MVP-Notiz nannte irrtümlich `@sd-jwt/core`, `@sd-jwt/decode`, `@sd-jwt/present`, `@sd-jwt/verify`).  
**Signatur:** ES256 (ECDSA P-256), Brainpool (`brainpool.ts`), ML-DSA (`pqc.ts`)  
**Protokoll-Stand & offene Lücken (2026-11-03):** Aktueller Code implementiert einen Pre-Final-Subset von OID4VCI / OID4VP (DIF Presentation Exchange v2, `vc+sd-jwt`, `client_id_scheme`). Die Migration auf OpenID4VP 1.0 Final (DCQL, Client Identifier Prefixes, `response_uri`, `verifier_info`), W3C Digital Credentials API, `dc+sd-jwt` (RFC 9901 §7.1 strikt) und ISO/IEC 18013-5 §9.1.3.6 `DeviceAuthenticationBytes` ist im 4-Stufen-Plan [`docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md`](../tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md) getrackt.  

⚠️ ECDSA P-256 ist **nicht** post-quantum sicher. ML-DSA Migration auf der Roadmap.

---

## Implementierte Prädikate (MVP)

| Prädikat | Typ | Demo-Use-Case |
|---|---|---|
| `isOver18` | boolean | Altersnachweis |
| `residencyCountry` | equality | Regionale Services |
| `hasDriversLicense` | boolean | Car Rental |

---

## Komponenten auf dem Nutzergerät

```
Policy Manifest        ← Regeln: was darf abgefragt werden
Proof Builder          ← ZK-Prädikate, Selective Disclosure
Binding Layer          ← Bindet Proof an Request-Kontext (nonce, audience)
Key Guardian           ← Ephemere Schlüssel; kein TEE-Claim ohne Implementierung
Local Audit Trail      ← Nutzer-sichtbar, lokal, was wurde wann geteilt
```

---

## Server-Komponenten (minimal, erlaubt)

```
Verification API       ← Prüft Proof-Validität; speichert KEINE PII
WORM Log               ← Decision Receipts, keine Identitätsattribute
Rate Limiting          ← DoS-Schutz ohne Nutzerprofile
```

---

## Crypto-Shredding

Für jede Session: `K_trans` (AES-256) → verschlüsselt PII → nach Session irreversibel zerstört.  
Rückstand im Log: mathematisch nicht unterscheidbar von Rauschen.  
Rechtsbasis: DSGVO Art. 17, EDPB Guidelines 04/2020. Siehe [05_LEGAL.md](05_LEGAL.md).

---

## Layer-Modell

| Layer | Zielgruppe | Beispiel |
|---|---|---|
| 0 — WELT | Universal | Altersnachweis, Reisepass |
| 1 — GRUNDVERSORGUNG | Kinder, Basis-Services | Jugendschutz, Schulzugang |
| 2 — VULNERABLE | Health, Finance, Elderly | Rezept, Kontolimit |

---

## MVP-Metriken (Stand 2026-02-16)

- 18 Packages buildbar
- 42/42 Tests passing (Policy Engine E2E: 11/11, Mock Issuer: 14/14)
- 0 TypeScript Errors
- E2E Flow: <100ms
- Build: Cold 5.9s / Cached 2.4s (94% Cache Hit Rate)

---

## Offene technische Risiken

| Risiko | Priorität | Status |
|---|---|---|
| ML-DSA Migration (Post-Quantum) | Mittel | Roadmap |
| TEE/Hardware-Attestation | Mittel | Nicht implementiert |
| Privacy Revocation für regulierte Märkte | Hoch | Design offen |
| EUDIW-Abhängigkeit (Stabilisierung) | Mittel | Beobachten |

*Quellen: docs/03-architecture/mvp/ADR-001 bis ADR-012, MVP_SUMMARY.md*
