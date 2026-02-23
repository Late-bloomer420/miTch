```mermaid
flowchart TD
    Start([Verifier Request]) --> Intake[Stage 1: Request Intake<br/>mi.request.intake]
    
    Intake -->|Valid| VerifierID[Stage 2: Verifier Identification<br/>mi.verifier.resolve]
    Intake -->|Invalid| Deny1[DENY: INVALID_REQUEST]
    
    VerifierID -->|Resolved| PolicyEval[Stage 3: Policy Evaluation<br/>policy.eval]
    VerifierID -->|Failed| Deny2[DENY: VERIFIER_UNRESOLVABLE]
    
    PolicyEval -->|ALLOW| Assembly[Stage 6: Proof Assembly<br/>proof.build]
    PolicyEval -->|PROMPT| Verdict[Stage 4: Verdict Handling<br/>mi.verdict.dispatch]
    PolicyEval -->|DENY| Deny3[DENY: Reason Codes]
    
    Verdict -->|User Grants| Assembly
    Verdict -->|User Denies| Deny4[DENY: USER_DENIED]
    Verdict -->|Timeout| Deny5[DENY: CONSENT_TIMEOUT]
    
    Assembly -->|Presence Required?| PresenceCheck{Check Required}
    Assembly -->|No Presence| Delivery
    
    PresenceCheck -->|Yes| Presence[Stage 5: Presence Binding<br/>mi.login]
    PresenceCheck -->|No| Delivery
    
    Presence -->|Success| Delivery[Stage 7: Delivery<br/>mi.transport.seal]
    Presence -->|Failed| Deny6[DENY: PRESENCE_REQUIRED]
    
    Delivery --> Audit[Stage 8: Local Audit<br/>audit.local]
    
    Audit --> Success([Encrypted VP Sent])
    
    Deny1 --> AuditDeny[Log Denial]
    Deny2 --> AuditDeny
    Deny3 --> AuditDeny
    Deny4 --> AuditDeny
    Deny5 --> AuditDeny
    Deny6 --> AuditDeny
    
    AuditDeny --> End([Request Rejected])
    
    style Start fill:#e1f5fe
    style Success fill:#c8e6c9
    style End fill:#ffcdd2
    style PolicyEval fill:#fff9c4
    style Presence fill:#f3e5f5
    style Assembly fill:#e0f2f1
    style Delivery fill:#ffe0b2
    style Audit fill:#d1c4e9
    
    classDef denyNode fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    class Deny1,Deny2,Deny3,Deny4,Deny5,Deny6 denyNode
```

## Workflow Invariants Mapping

### Invariant 1: Request Integrity
```mermaid
graph LR
    A[Request] --> B{Has verifier_id?}
    B -->|No| C[DENY: MISSING_VERIFIER_ID]
    B -->|Yes| D{Has challenge?}
    D -->|No| E[DENY: MISSING_CHALLENGE]
    D -->|Yes| F{Has purpose?}
    F -->|No| G[DENY: MISSING_PURPOSE]
    F -->|Yes| H[Continue]
    
    style C fill:#ffcdd2
    style E fill:#ffcdd2
    style G fill:#ffcdd2
    style H fill:#c8e6c9
```

### Invariant 2: Unknown Verifier Blocking
```mermaid
graph LR
    A[Verifier ID] --> B{Matches Policy Pattern?}
    B -->|No| C{blockUnknownVerifiers?}
    C -->|Yes| D[DENY: VERIFIER_NOT_ALLOWED]
    C -->|No| E[PROMPT]
    B -->|Yes| F[Continue]
    
    style D fill:#ffcdd2
    style E fill:#fff9c4
    style F fill:#c8e6c9
```

### Invariant 3: Claim Denial
```mermaid
graph LR
    A[Requested Claims] --> B{Any in deniedClaims?}
    B -->|Yes| C[DENY: CLAIM_DENIED]
    B -->|No| D{All in allowedClaims?}
    D -->|No| E[DENY: CLAIM_NOT_PERMITTED]
    D -->|Yes| F[Continue]
    
    style C fill:#ffcdd2
    style E fill:#ffcdd2
    style F fill:#c8e6c9
```

### Invariant 4: Presence Requirement
```mermaid
graph LR
    A[Decision] --> B{requiredPresence?}
    B -->|No| C[Skip Presence]
    B -->|Yes| D[Trigger WebAuthn]
    D --> E{Success?}
    E -->|No| F[DENY: PRESENCE_REQUIRED]
    E -->|Yes| G[Attach Proof]
    
    style F fill:#ffcdd2
    style C fill:#c8e6c9
    style G fill:#c8e6c9
```

### Invariant 5: Issuer Trust
```mermaid
graph LR
    A[Credential] --> B{Issuer in trustedIssuers?}
    B -->|No| C{requireTrustedIssuer?}
    C -->|Yes| D[DENY: ISSUER_NOT_TRUSTED]
    C -->|No| E[PROMPT]
    B -->|Yes| F[Continue]
    
    style D fill:#ffcdd2
    style E fill:#fff9c4
    style F fill:#c8e6c9
```

### Invariant 6: Replay Protection
```mermaid
graph LR
    A[Nonce] --> B{In Nonce Store?}
    B -->|Yes| C{Expired?}
    C -->|No| D[DENY: REPLAY_DETECTED]
    C -->|Yes| E[Remove & Continue]
    B -->|No| F[Register Nonce]
    F --> G[Continue]
    
    style D fill:#ffcdd2
    style E fill:#c8e6c9
    style G fill:#c8e6c9
```

### Invariant 7: Temporal Validity
```mermaid
graph LR
    A[Timestamp] --> B{Within ±5 min?}
    B -->|No| C[DENY: REQUEST_EXPIRED]
    B -->|Yes| D{Credential Fresh?}
    D -->|No| E[DENY: CREDENTIAL_EXPIRED]
    D -->|Yes| F[Continue]
    
    style C fill:#ffcdd2
    style E fill:#ffcdd2
    style F fill:#c8e6c9
```

## Data Flow (Never Events Enforcement)

```mermaid
flowchart LR
    subgraph Wallet ["User Wallet (Edge)"]
        Storage[Encrypted Storage<br/>IndexedDB]
        Policy[Policy Engine<br/>Deterministic]
        ZKP[ZKP Engine<br/>Predicates Only]
    end
    
    subgraph Network ["Network Layer"]
        Encrypt[AES-GCM Encryption<br/>Ephemeral Keys]
    end
    
    subgraph Verifier ["Verifier (Server)"]
        Decrypt[Decrypt VP]
        Verify[Verify Proofs]
    end
    
    Storage -->|Raw PII| Policy
    Policy -->|Decision| ZKP
    ZKP -->|Boolean Results| Encrypt
    Encrypt -->|Ciphertext| Network
    Network --> Decrypt
    Decrypt -->|VP Bundle| Verify
    
    style Storage fill:#e1f5fe
    style ZKP fill:#fff9c4
    style Encrypt fill:#ffecb3
    style Verify fill:#c8e6c9
    
    Note1[❌ No Raw PII Leaves Device]
    Note2[❌ No Credential IDs in VP]
    Note3[❌ No Cross-Session Tracking]
    
    Storage -.->|Never| Network
    ZKP -.->|Only Booleans| Encrypt
```

## Audit Chain Structure

```mermaid
flowchart TD
    Genesis[Genesis Entry<br/>Hash: 0x000...]
    
    Entry1[Entry 1<br/>Event: POLICY_EVALUATED<br/>PrevHash: 0x000...<br/>Signature: sig1]
    
    Entry2[Entry 2<br/>Event: KEY_USED<br/>PrevHash: hash1<br/>Signature: sig2]
    
    Entry3[Entry 3<br/>Event: KEY_DESTROYED<br/>PrevHash: hash2<br/>Signature: sig3]
    
    Genesis -->|Hash Chain| Entry1
    Entry1 -->|Hash Chain| Entry2
    Entry2 -->|Hash Chain| Entry3
    
    style Genesis fill:#e1f5fe
    style Entry1 fill:#fff9c4
    style Entry2 fill:#ffe0b2
    style Entry3 fill:#ffcdd2
    
    Verify[Verification:<br/>1. Recompute Hashes<br/>2. Verify ECDSA Signatures<br/>3. Check Chain Integrity]
    
    Entry3 -.->|Export| Verify
```

## Antigravity Workspace Integration

```mermaid
graph TB
    subgraph Workspaces ["Antigravity Workspaces"]
        Login[mi.login<br/>WebAuthn Presence]
        Intake[mi.request.intake<br/>Schema Validation]
        Resolve[mi.verifier.resolve<br/>DID Resolution]
        PolicyWS[policy.eval<br/>Rule Matching]
        Verdict[mi.verdict.dispatch<br/>Consent UI]
        Build[proof.build<br/>ZKP + Disclosure]
        Seal[mi.transport.seal<br/>Encryption]
        Audit[audit.local<br/>Hash Chain]
    end
    
    Intake --> Resolve
    Resolve --> PolicyWS
    PolicyWS --> Verdict
    Verdict --> Login
    Login --> Build
    Build --> Seal
    Seal --> Audit
    
    style Login fill:#f3e5f5
    style PolicyWS fill:#fff9c4
    style Build fill:#e0f2f1
    style Audit fill:#d1c4e9
```
