# DECISION-007: AI Orchestrator Integration

**Date:** 2026-02-20  
**Status:** Accepted  
**Scope:** Phase 1–2 (design in Phase 0)

---

## Summary

AI agents get scoped delegation tokens — pre-authorized by the human for specific claims, verifiers, time windows, and use counts. Four-layer policy enforcement ensures no single point of failure. Tool I/O is certified against strict schemas with runtime sanitization.

---

## Integration Model

### Models Evaluated

| Model | Description | Verdict |
|---|---|---|
| A: AI as Credential Proxy | Full wallet access, autonomous | **Rejected** — no consent per interaction |
| B: AI as Consent Requestor | Human approves every action | Correct but unusable at scale |
| **C: AI with Scoped Delegation** | Pre-authorized bounded scope | **Selected** ✅ |

---

## Delegation Token

```typescript
interface DelegationToken {
  version: "v0";
  id: string;
  delegator: { walletId: string; signature: string; };
  delegate: { agentId: string; agentType: string; };
  scope: {
    allowedClaims: string[];       // ["over_18", "email_verified"]
    allowedVerifiers: string[];    // ["coolshop.at", "*.trusted-merchants.eu"]
    validFrom: number;
    validUntil: number;            // hard expiry
    maxPresentations: number;      // e.g., 10 uses
    taskDescription: string;       // "Book hotel in Vienna"
    purposeConstraint: string;     // "travel_booking"
  };
  deny: {
    claims: string[];              // never, regardless of scope
    verifiers: string[];           // blocked even if wildcard matches
  };
  escalation: "ask_human" | "fail_silent" | "fail_with_reason";
}
```

### Security Constraints
- Max delegation duration: 24 hours
- Max claims per delegation: 5
- Never-delegatable: `health_data`, `biometric`, `financial_full`
- Token bound to specific AI session
- Human can revoke instantly via kill switch

---

## Four-Layer Policy Enforcement

```
Layer 1: AI Orchestrator (soft, untrusted)
  → AI's system prompt includes scope awareness
  → Efficiency only — prevents wasted tool calls
  → Trust level: ZERO

Layer 2: SDK Gateway (HARD ENFORCEMENT) ⭐
  → Runs in wallet's trust domain, NOT the AI's
  → Checks: time, uses, claims, verifiers, purpose, denials
  → API boundary between AI and SDK (AI cannot modify enforcement)
  → Trust level: HIGH

Layer 3: Wallet Core (capability check)
  → Credential exists? Not expired? Not revoked? Audience match?
  → Delegation signature valid?
  → Trust level: HIGH

Layer 4: Transport Relay (absolute limits)
  → Rate limit: 10 presentations/min
  → Max claims per presentation: 5
  → Max payload: 8KB
  → Verifier blocklist
  → Trust level: HIGH (independent of all other layers)
```

### Critical Architecture Decision
**SDK Gateway runs in a separate process/sandbox from the AI.** The AI calls it over an API boundary (JSON-RPC/REST). The AI can send requests but cannot modify, patch, or bypass enforcement logic.

### Failure Modes
| Scenario | What stops it |
|---|---|
| AI requests out-of-scope claim | Layer 2 (SDK) |
| AI prompt-injected to dump all creds | Layer 2 (scope) + Layer 3 (per-claim) + Layer 4 (rate limit) |
| Delegation token stolen | Layer 2 (session binding) + Layer 3 (sig check) |
| Bug in SDK | Layer 3 (audience) + Layer 4 (rate/size limits) |
| Everything compromised | Human revokes delegation via kill switch |

---

## Agent SDK Interface

```typescript
interface MitchAgentSession {
  canPresent(claims: string[], verifierId: string): ScopeCheck;
  present(request: VerificationRequestV0): Promise<PresentationResult>;
  requestEscalation(additionalClaims: string[], reason: string): Promise<EscalationResult>;
  remainingScope(): ScopeStatus;
  release(): void;  // voluntary token destruction
}
```

Works with OpenAI function calling, LangChain tools, or any framework that supports tool interfaces.

---

## Tool I/O Certification & Output Redaction

### Problem
Once data enters the AI context window, you've lost control. Prevention > cleanup.

### Three Enforcement Layers

**Layer A: Certified Output Schemas (compile-time)**
- TypeScript types with forbidden field names
- `additionalProperties: false` at every level of JSON Schema
- If it's not in the schema, it can't exist in the output

**Layer B: Runtime Output Sanitizer (belt-and-suspenders)**
- Deep scan for banned keys (`birthdate`, `name`, `email`, `address`, etc.)
- Regex scan for PII patterns (dates, emails, phone numbers)
- Runs on every tool output before it enters AI context
- Also runs on tool INPUTS (blocks AI from stuffing PII into tool calls)

**Layer C: Cryptographic Tool Certification (Phase 2)**
- Tools sign their output against a registered schema
- Runtime verifies signature + schema conformance + no extra fields
- For untrusted third-party tools in the ecosystem

### Pipeline
```
Tool executes → Tool signs output (Layer C)
  → Runtime verifies cert (Layer C) → Sanitizer scans (Layer B)
  → AI context (only certified, validated, sanitized data)
```

---

## Human Oversight: Activity Feed

```
🤖 AI Activity (live)
  ⏱ 47 min remaining | 📊 3 of 10 uses

  15:23 ✅ over_18 → hotel-a.at
  15:24 ✅ over_18 → hotel-b.at
  15:31 ⚠️ BLOCKED: full_name → hotel-c.at (not in scope)

  [🛑 Revoke delegation now]
```

---

## Positioning

> "miTch: the identity layer that lets AI agents prove things about you without knowing things about you."

---

## Phase Deliverables

| Feature | Phase |
|---|---|
| Delegation token spec (data model only) | 0 (design) |
| SDK gateway + scope enforcement | 1 |
| Process isolation (SDK separate from AI) | 1 |
| Escalation to human | 1 |
| Certified output schemas | 1 |
| Runtime output sanitizer | 1 |
| Framework integrations (OpenAI, LangChain) | 2 |
| Cryptographic tool certification | 2 |
| Live activity feed + kill switch | 2 |
