# ADR-014 — GNAP-Aligned Delegation Token Schema

**Status:** PROPOSED
**Date:** 2026-06-05
**Owner:** Architecture Lead
**Inspired by:** Truvera Webinar (Dock Labs, 2026)
**Relationship:** Ergänzt ADR-007 (DelegationToken) — ersetzt es **nicht**.

## Context

ADR-007 definiert ein Scoped Delegation Token für AI-Agent-Authorization mit vier Enforcement-Layern. Das Token-Format ist proprietär und trägt für Phase 1.

Im Webinar wird **GNAP** (Grant Negotiation and Authorization Protocol, [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) als das Protokoll beschrieben, das multi-party delegation, ephemeral clients und fine-grained access nativ löst — genau die Konzepte, die miTch für AI-Agent-Authorization braucht.

miTch fährt **keinen** vollständigen GNAP Authorization Server. Aber das Token-Schema lässt sich GNAP-kompatibel gestalten — ohne Mehraufwand und mit klarem Migrationspfad.

Drei GNAP-Konzepte sind direkt relevant:

1. **Ephemeral Client Registration** — GNAP-Clients müssen sich nicht vorab registrieren. ADR-007 setzt aktuell voraus, dass `agentId` im System bekannt ist. GNAP erlaubt einen Agent, der sich für genau eine Session selbst einführt, ohne Pre-Registration.
2. **Structured Access Object** — GNAPs `access` ist ein strukturiertes Objekt (keine flache Claim-Liste), das Ressource, Aktion und Kontext beschreibt. Das matcht miTchs Anforderung *„Agent darf `over_18` für `*.trusted-merchants.eu` für max. 10 Requests"* präziser als ein Array von Claim-Namen.
3. **Continuation** — GNAP hat eingebautes mehrstufiges Grant-Building. Das matcht `requestEscalation()` aus ADR-007 konzeptuell, aber bisher ohne Standard-Protokoll darunter.

## Decision

**Option A (gewählt): GNAP-aligned Token Schema.**
Das DelegationToken-Format wird strukturell mit GNAPs Access Request Model kompatibel gestaltet. Kein vollständiger GNAP-Stack, kein Authorization-Server-Deployment — aber das Schema erlaubt spätere Migration ohne Breaking Change.

**Option B (verworfen): Explizit proprietär.**
Kurzfristig einfacher, schließt aber Interoperabilität mit GNAP-basierten AI-Agent-Frameworks (z. B. Open Payments Network, künftige WIMSE-Profile) aus.

### Token Schema (GNAP-aligned)

```typescript
interface DelegationTokenV2 {
  version: 'v2';
  id: string; // UUID, einmalig

  // GNAP-style: structured access statt flacher Claim-Liste
  access: AccessDescriptor[];

  delegator: {
    walletId: string;
    signature: string; // ECDSA über Token-Body
  };

  delegate: {
    agentId: string;
    agentType: 'openai-function' | 'langchain-tool' | 'mcp-server' | 'custom';
    // GNAP: ephemeral clients können sich self-describe
    ephemeral?: boolean; // true = keine Pre-Registration erforderlich
    instanceId?: string; // session-spezifisch, nicht persistent
  };

  // GNAP Continuation Pattern: mehrstufiger Grant
  continuation?: {
    maxEscalations: number;
    escalationRequiresWebAuthn: boolean;
  };

  constraints: {
    validFrom: number; // Unix timestamp
    validUntil: number; // hard expiry, max 24h
    maxPresentations: number;
    taskDescription: string; // human-readable, für Activity Feed
    purposeConstraint: string;
  };

  deny: {
    claims: string[]; // niemals, unabhängig vom Scope
    verifiers: string[]; // geblockt auch bei Wildcard-Match
  };

  escalation: 'ask_human' | 'fail_silent' | 'fail_with_reason';

  meta: {
    createdAt: number;
    issuedBy: string; // wallet DID
    schemaVersion: 'gnap-v1';
  };
}

// GNAP-style structured access descriptor
interface AccessDescriptor {
  type: string; // z. B. "credential-presentation"

  // Was der Agent präsentieren darf
  claims?: string[]; // ["over_18", "email_verified"]

  // Für wen
  locations?: string[]; // ["coolshop.at", "*.trusted-merchants.eu"]

  // Wie oft (GNAP: pro Access-Descriptor steuerbar)
  maxUses?: number;

  // Kontext (GNAP: Rich Authorization Requests kompatibel)
  context?: {
    purpose: string; // "travel_booking", "age_verification"
    expiresAt?: number;
  };
}
```

### Warum das GNAP-kompatibel ist

GNAPs core access request sieht so aus:

```json
{
  "access": [
    {
      "type": "credential-presentation",
      "locations": ["coolshop.at"],
      "actions": ["present"],
      "datatypes": ["over_18"]
    }
  ]
}
```

Der obige `AccessDescriptor` mappt direkt darauf. Bei echter GNAP-Migration:

| miTch `AccessDescriptor` | GNAP `access` | Änderung |
| --- | --- | --- |
| `claims` | `datatypes` | Umbenennung |
| `locations` | `locations` | identisch |
| `type` | `type` | identisch |

Kein Breaking Change in der Wallet-Logik — nur eine Schema-Umbenennung.

### WIMSE-Relevanz

GNAP wird im IETF-Umfeld der [WIMSE Working Group](https://datatracker.ietf.org/wg/wimse/) weiterentwickelt. WIMSE adressiert exakt miTchs Zwitterstellung: weder reiner Workload noch User Agent, sondern ein Mediation Layer, der über Trust-Domain-Grenzen operiert.

Die Felder `delegate.ephemeral` und `delegate.instanceId` sind bewusst WIMSE-kompatibel gestaltet: Ein AI-Agent, der sich für eine Session identifiziert, ohne persistent registriert zu sein, ist das Kernszenario, das WIMSE für Workload-Identity löst.

Sobald die WIMSE-Standards stabiler sind (voraussichtlich 2027), kann miTchs Delegation Layer als WIMSE-konforme Implementierung positioniert werden.

## Abgrenzung zu ADR-007

ADR-007 bleibt **unverändert gültig** für:

- Four-Layer Enforcement
- Process Isolation
- `deny`-Listen-Semantik
- Activity Feed / Kill Switch

ADR-014 **erweitert**:

- Token Schema: proprietäre Claim-Liste → GNAP-style `AccessDescriptor`
- Ephemeral Client Support: `agentId` muss nicht vorab bekannt sein
- Continuation Pattern: formalisiert, was vorher `requestEscalation()` war

## Sicherheitseigenschaften (unverändert zu ADR-007)

- **Max Delegation Duration:** 24h
- **Max Claims per Delegation:** 5 (via `AccessDescriptor.claims`-Länge)
- **Never-delegatable:** `health_data`, `biometric`, `financial_full`
- **Session-gebunden:** Token nicht cross-session wiederverwendbar
- **Sofort-Widerruf:** Human kann jederzeit via Kill Switch revoken

## Acceptance Evidence

- [ ] `DelegationTokenV2` TypeScript-Interface in `@askmi/shared-types`
- [ ] `AccessDescriptor` Schema-Validation in der Policy Engine
- [ ] Migration von ADR-007 `DelegationToken` auf V2 ohne Breaking Change
- [ ] Test: ephemeral Agent ohne Pre-Registration kann Delegation erhalten
- [ ] Test: GNAP Access Object wird korrekt auf miTch-Policy evaluiert
- [ ] Demo in `wallet-pwa`: Activity Feed zeigt strukturierten `AccessDescriptor`

## References

- GNAP Core Grant — [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)
- [WIMSE Working Group (IETF)](https://datatracker.ietf.org/wg/wimse/)
- Truvera Webinar (Dock Labs, 2026): *„GNAP natively solves ephemeral clients, fine-grained access, multi-party delegation"*
- ADR-007 — AI Orchestrator Integration (Scoped Delegation)
- docs/specs/111 — Pairwise-Ephemeral DIDs (komplementär)

## Change Log

- 2026-06-05: Initial proposal (PROPOSED)
