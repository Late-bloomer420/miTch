# 49 — EHDS Compliance Map

| Key       | Value                          |
|-----------|--------------------------------|
| Datum     | 2026-03-04                     |
| Status    | Living Document                |
| Version   | 1.0                            |
| Autor     | miTch-Team                     |

## Overview

Dieses Dokument bildet die systematische Zuordnung zwischen den Anforderungen des **European Health Data Space (EHDS)** und den konkreten technischen Mechanismen in miTch ab. Es dient als Compliance-Nachweis und Tracking-Instrument für offene Lücken.

## Compliance Matrix

| EHDS Anforderung | Artikel | miTch-Mechanismus | Package | Status |
|---|---|---|---|---|
| Patient Summary Austausch | Art. 5 | PatientSummary VC + SD-JWT | `shared-crypto`, `wallet-pwa` | ✅ |
| Primärnutzungs-Consent | Art. 8 | ConsentModal + WebAuthn | `wallet-pwa`, `shared-crypto` | ✅ |
| Sekundärnutzungs-Widerspruch | Art. 11 | PolicyManifest `denySecondaryUse` | `policy-engine`, `shared-types` | ✅ |
| HDAB-Permit-Pflicht | Art. 46 | TrustedIssuer hdab-Rolle + `requiresHdabPermit` | `policy-engine`, `shared-types` | ✅ |
| Cross-Border-Freizügigkeit | GDPR Art. 1 | Verifier-Pattern EU-Wildcard + `geoScope` | `policy-engine` | ✅ |
| Notfallzugriff (Break-Glass) | Art. 8(5) | `allowBreakGlass` + audit alert | `policy-engine` | 🔧 In Progress |
| Geo-Scope Drittländer | GDPR Art. 46 | GeoScope (`eu-only` / `eu-plus-adequacy` / `global`) | `policy-engine` | ✅ |
| ePrescription Single-Use | Art. 14 | Credential status + nullifier | `policy-engine` | 🔧 In Progress |
| Sprachlocale Medizinbegriffe | §3.3 | i18n-Map (planned) | `wallet-pwa` | ❌ Planned |
| Audit Export Schema | Art. 31 | `audit-export-schema.ts` + V1 spec | `audit-log` | ✅ |
| Verifiable Presentation | Art. 12 | SD-JWT VP + selective disclosure | `shared-crypto` | ✅ |
| Credential Revocation | Art. 9 | StatusList2021 revocation check | `shared-crypto` | ✅ |
| Anti-Replay Protection | Art. 13 | Nonce store + TTL + canonicalization | `shared-crypto` | ✅ |
| DID Resolution + Verification | Art. 10 | `did.ts` + `did-verification.ts` | `shared-crypto` | ✅ |

## Legende

| Symbol | Bedeutung |
|--------|-----------|
| ✅ | Implementiert und getestet |
| 🔧 In Progress | In Arbeit, teilweise vorhanden |
| ❌ Planned | Geplant, noch nicht begonnen |

## Architecture Note

miTch implementiert EHDS-Compliance **auf der lokalen Policy-Ebene**, nicht über eine zentrale Registry. Der `policy-engine` wertet Regeln lokal aus — der User behält die Hoheit über seine Daten, ohne dass ein zentraler Gatekeeper entscheidet. Verifiable Credentials und SD-JWT ermöglichen dabei selektive Offenlegung, ohne dass ein Backend den vollen Datensatz sehen muss.

## Key Insight

> *„Primär- und Sekundärnutzung sind strukturell verschiedene Rechtsverhältnisse. Der User definiert seine Grenze lokal."*

Diese Trennung ist kein Feature — sie ist die Architektur. `denySecondaryUse` im PolicyManifest ist kein Opt-out-Button, sondern die Default-Haltung des Systems.

## Referenzen

- [48 — EHDS Gap Analysis and Tasks](./48_EHDS_Gap_Analysis_and_Tasks.md)
- [ehds-jurist.nl](https://ehds-jurist.nl)
