# 48 — Mitigation Plan: Proof Fatigue, Policy Tamper, Recovery, GDPR

Stand: 2026-02-11

## A) Proof Fatigue / Social Engineering

### Controls
1. **Risk-tiered consent UX**
   - Low-risk: lightweight approval
   - High-risk: explicit friction + summary + timeout
2. **Purpose-bound display**
   - Always show requester, purpose, exact claim requested.
3. **Consent cooldown**
   - Repeated high-risk prompts in short windows require extra confirmation.
4. **Deny-safe defaults**
   - Ambiguous/unknown request => deny.

### Evidence
- Prompt telemetry (count/accept/deny by risk tier)
- Override/adjudication trend for suspicious patterns

---

## B) Policy Engine Tamper (Client-side)

### Controls
1. **Signed policy manifests** (versioned + verified before use)
2. **Server-side policy re-validation** (no blind trust in client outcome)
3. **Tamper-evident decision logs** (hash-chain event stream)
4. **Integrity check on startup** (detect local policy corruption)

### Evidence
- Signature verification logs
- Audit-chain verification status
- Deterministic deny mapping coverage

---

## C) Recovery Security

### Controls
1. **Explicit recovery threat model** (coercion, collusion, phishing)
2. **Guardian quorum design** (no single-point recovery)
3. **Recovery delay + alerting** for high-risk resets
4. **No hidden central override keys**

### Evidence
- Recovery tabletop test reports
- Simulated adversarial recovery test outcomes

---

## D) GDPR Legal Readiness

### Controls
1. **External legal opinion** for pilot data flows
2. **Controller/processor mapping** per endpoint
3. **Retention matrix + lawful basis mapping**
4. **DPIA-style risk summary for pilot scope**

### Evidence
- Signed legal memo
- Mapping artifacts in pilot dossier
- Demonstrable minimization in logs/receipts

---

## E) Crypto Shredding / Hardware Gap

### Controls
1. **Honest protection-level labels**
   - SOFTWARE_EPHEMERAL
   - HARDWARE_BACKED (only when provable)
2. **No overclaims in docs/marketing**
3. **Optional hardware-backed profile** for high-assurance deployments

### Evidence
- Protection-level declaration in config/profile
- Security posture statement split by assurance tier
