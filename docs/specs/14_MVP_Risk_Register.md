# 14 — MVP Risk Register

Stand: 2026-02-11

| ID | Risiko | Auswirkung | Wahrscheinlichkeit | Gegenmaßnahme | Owner | Status |
|---|---|---|---|---|---|---|
| R1 | Unklare Proof-Stack-Entscheidung | Verzögerung aller Folgearbeiten | Hoch | Week-1 Decision Gate mit Timebox | Architecture | Open |
| R2 | Replay-Schutz unvollständig | Sicherheitsvorfall / Trust-Verlust | Mittel-Hoch | Nonce+audience+expiry+canonical hash + adversarial tests | Security | Open |
| R3 | Metadata-Linkability in Logs | Privacy-Verstoß / regulatorisches Risiko | Mittel | Log-Redaction + no-stable-ID checks + retention matrix | Privacy Eng | Open |
| R4 | RP-Integration zu komplex | Pilot scheitert operativ | Mittel | Versionierte Schemas + SDK + Referenz-Client | DevRel/API | Open |
| R5 | Issuer/Revocation Abhängigkeit instabil | Unzuverlässige Verifikation | Mittel | Degraded mode Regeln + Cache/TTL policy + graceful deny | Platform | Open |
| R6 | Falsche Security-Claims (TEE etc.) | Reputations- und Compliance-Risiko | Mittel | Honesty check in CI + claim review gate | PM/Sec | Open |
| R7 | Key-Compromise ohne Runbook | Incident eskaliert | Niedrig-Mittel | Key rotation/compromise playbooks + tabletop exercise | Security/Ops | Open |
| R8 | Scope Creep im MVP | Zeitplan bricht | Hoch | Strict MVP scope lock + change control | Product | Open |

## Notes
- Risiko-Review mindestens wöchentlich.
- „Open“ → „Mitigating“ → „Accepted/Closed“.
- Für Pilot-Go müssen R1, R2, R3, R4 auf mindestens „Mitigating“ sein.
