# miTch Architecture — Technische Grundlage

**Stand: MVP Complete (2026-02-16) | Stack: TypeScript Monorepo**

---

## Credential Stack (ADR-001, ACCEPTED)

**Primary:** SD-JWT VC (Selective Disclosure JWT Verifiable Credentials)  
**Libraries:** `@sd-jwt/core`, `@sd-jwt/decode`, `@sd-jwt/present`, `@sd-jwt/verify`, `jose`  
**Signatur:** ES256 (ECDSA P-256)  
**Standard:** W3C VC 2.0, eIDAS 2.0 ready, OID4VCI / OID4VP  

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
