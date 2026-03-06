# miTch — Architektur-Diagramme

*Technische Übersicht für Uni-Präsentation und Developer Onboarding*

---

## Diagramm 1: System Overview (High-Level)

```mermaid
flowchart TB
    subgraph Gov["Government / Issuer"]
        ISS[eID Issuer<br/>SD-JWT VC / OID4VCI]
        REV[Revocation Registry<br/>StatusList2021]
    end

    subgraph Device["User Device (Edge-First)"]
        direction TB
        WALLET[Wallet PWA]
        PE[Policy Engine<br/>Fail-Closed · Deterministic]
        CRYPTO[Shared Crypto<br/>ECDSA · AES-GCM · HKDF]
        STORE[Secure Storage<br/>AES-256-GCM · IndexedDB]
        AUDIT[WORM Audit Log<br/>DSGVO Art. 32]
        WALLET --> PE
        PE --> CRYPTO
        WALLET --> STORE
        WALLET --> AUDIT
    end

    subgraph Verifier["Verifier (Shop / Hospital / Behörde)"]
        SDK[Verifier SDK<br/>OID4VP · AAD Binding]
        LOG[WORM Log<br/>Nur Proofs, keine PII]
        SDK --> LOG
    end

    ISS -- "Credential<br/>(einmalig, OID4VCI)" --> WALLET
    WALLET -- "Kryptografischer Proof<br/>(Ephemeral Key · Pairwise DID)" --> SDK
    SDK -- "Revocation Check<br/>(Fail-Closed)" --> REV

    style Device fill:#e6f3ff,stroke:#0066cc,stroke-width:2px
    style Gov fill:#f0f0f0,stroke:#999,stroke-width:1px
    style Verifier fill:#fff2e6,stroke:#e67300,stroke-width:2px
```

**Kernprinzip:** Identitätsdaten verlassen das Gerät nicht. Der Verifier empfängt ausschließlich kryptografische Beweise.

---

## Diagramm 2: Crypto Flow — Presentation Protocol

```mermaid
sequenceDiagram
    participant V as Verifier
    participant W as Wallet (Policy Engine)
    participant C as Shared Crypto

    Note over V,W: OID4VP Request
    V->>W: VerifierRequest {requestedClaims, purpose, verifierDid}

    Note over W: Policy Evaluation (Fail-Closed)
    W->>W: evaluate(request, manifest)
    alt DENY
        W-->>V: PolicyDenyError (reason code)
    else ALLOW
        W->>C: deriveSessionDID(verifierDid, sessionSeed)
        C-->>W: pairwiseDid (did:peer:0, HKDF)

        Note over W,C: Selective Disclosure + Signing
        W->>C: sign(proofPayload, ECDSA-P256)
        C-->>W: signature

        Note over W,C: Encryption (AEAD)
        W->>C: encrypt(artifact, AES-256-GCM, AAD)
        C-->>W: ciphertext {decision_id, nonce, verifier_did}

        W->>C: wrapKey(ephemeralKey, RSA-OAEP, verifierPubKey)
        C-->>W: encryptedKey

        W-->>V: TransportPackage {ciphertext, aad_context, recipient}

        Note over C: Crypto-Shredding
        C->>C: destroy(ephemeralKey)
        C->>C: destroy(sessionDID_material)
    end
```

**Sicherheitseigenschaften:** AAD-Binding verhindert Replay-Angriffe. Pairwise DIDs verhindern Cross-Verifier-Korrelation. Crypto-Shredding eliminiert nach jeder Sitzung alle ephemeren Schlüssel.

---

## Diagramm 3: Policy Engine — Fail-Closed Decision Tree

```mermaid
flowchart TD
    REQ[Verifier Request] --> VAL{Input Validation<br/>Whitelist Schema}
    VAL -- Invalid --> D1[DENY: INVALID_REQUEST]
    VAL -- Valid --> MANI{Manifest<br/>Lookup}
    MANI -- Not Found --> D2[DENY: NO_POLICY_MATCH]
    MANI -- Found --> FINGER{Verifier Fingerprint<br/>Match?}
    FINGER -- Mismatch --> D3[DENY: VERIFIER_MISMATCH]
    FINGER -- OK --> REV{Credential<br/>Revocation Check}
    REV -- Revoked --> D4[DENY: CREDENTIAL_REVOKED]
    REV -- Fail/Timeout --> D5[DENY: REVOCATION_CHECK_FAILED<br/>Fail-Closed]
    REV -- Valid --> PRED{Predicate<br/>Evaluation}
    PRED -- False --> D6[DENY: PREDICATE_FAILED]
    PRED -- True --> CAP{Capability<br/>Negotiation}
    CAP -- Mismatch --> D7[DENY: CAP_MISMATCH]
    CAP -- OK --> ALLOW[ALLOW<br/>DecisionCapsule]

    style ALLOW fill:#d4edda,stroke:#28a745,stroke-width:2px
    style D1 fill:#f8d7da,stroke:#dc3545,stroke-width:1px
    style D2 fill:#f8d7da,stroke:#dc3545,stroke-width:1px
    style D3 fill:#f8d7da,stroke:#dc3545,stroke-width:1px
    style D4 fill:#f8d7da,stroke:#dc3545,stroke-width:1px
    style D5 fill:#f8d7da,stroke:#dc3545,stroke-width:2px
    style D6 fill:#f8d7da,stroke:#dc3545,stroke-width:1px
    style D7 fill:#f8d7da,stroke:#dc3545,stroke-width:1px
```

**Fail-Closed:** Jeder Fehlerfall (Timeout, fehlende Daten, Revocation-Check-Fehler) resultiert in einem Deny. Kein "Silent Allow" unter Ungewissheit.

---

## Diagramm 4: Unlinkability — Pairwise DID Derivation (Spec 111)

```mermaid
flowchart LR
    subgraph Wallet["Wallet (einmalige Master-Key)"]
        MK[Master Key<br/>Ed25519]
    end

    subgraph Session1["Session: Liquor Store"]
        DID1[did:peer:0_xyz1<br/>Einmalig · HKDF]
    end

    subgraph Session2["Session: Hospital"]
        DID2[did:peer:0_abc2<br/>Einmalig · HKDF]
    end

    subgraph Session3["Session: Pharmacy"]
        DID3[did:peer:0_qrs3<br/>Einmalig · HKDF]
    end

    MK -- "HKDF(masterKey, verifierId_A, session_seed)" --> DID1
    MK -- "HKDF(masterKey, verifierId_B, session_seed)" --> DID2
    MK -- "HKDF(masterKey, verifierId_C, session_seed)" --> DID3

    DID1 -. "Kein gemeinsamer Identifier" .-> DID2
    DID2 -. "Keine Korrelation möglich" .-> DID3

    style Wallet fill:#e6f3ff,stroke:#0066cc,stroke-width:2px
```

**Unlinkability:** Jeder Verifier sieht eine andere DID. Kein Verifier kann Transaktionen eines Nutzers verifier-übergreifend verknüpfen — auch bei Kollusion.

---

## Diagramm 5: Monorepo Package-Struktur

```mermaid
graph TD
    subgraph Apps
        WPWA[wallet-pwa<br/>React PWA · Port 5174]
        VDEMO[verifier-demo<br/>Express + Frontend · 3004]
        IMOCK[issuer-mock<br/>OID4VCI Server · 3005]
    end

    subgraph Core["Core Packages"]
        SCRYPTO[shared-crypto<br/>ECDSA · AES-GCM · HKDF · did:peer]
        STYPES[shared-types<br/>TypeScript Interfaces]
        PE[policy-engine<br/>Fail-Closed Evaluator]
        PREDS[predicates<br/>isOver18 · hasLicense]
    end

    subgraph Protocol["Protocol Packages"]
        OID4VP[oid4vp<br/>VP Token Builder · Parser]
        OID4VCI[oid4vci<br/>Credential Offer · Issuance]
        VSDK[verifier-sdk<br/>Decrypt · Verify · Replay-Check]
        VBROW[verifier-browser<br/>Browser Adapter]
    end

    subgraph Infra["Infrastructure Packages"]
        ANCHOR[anchor-service<br/>Merkle Batch · L2 Stubs]
        AUDIT[audit-log<br/>WORM IndexedDB Store]
        SSTOR[secure-storage<br/>AES-256-GCM · IndexedDB]
        REVOC[revocation-statuslist<br/>StatusList2021 · Fail-Closed]
        CATA[catalog<br/>Policy Manifest Registry]
    end

    WPWA --> SCRYPTO
    WPWA --> PE
    WPWA --> SSTOR
    WPWA --> AUDIT
    VDEMO --> VSDK
    VDEMO --> OID4VP
    SCRYPTO --> STYPES
    PE --> STYPES
    PE --> PREDS
    PE --> CATA
    OID4VCI --> SCRYPTO
    VSDK --> SCRYPTO
    REVOC --> ANCHOR
```

---

## Technische Kennzahlen (Session 6 — 2026-03-06)

| Metrik | Wert |
|---|---|
| Turbo Tasks | 38/38 grün |
| Individual Tests | 760+ |
| npm Vulnerabilities | 0 |
| ESLint Errors | 0 |
| ESLint Warnings | 0 |
| P0 Gaps | 9/9 geschlossen |
| P1 Gaps | 5/5 geschlossen |
| OID4VP | E-01a–E-01d implementiert |
| OID4VCI | E-02 implementiert (32 Tests) |
| Unlinkability | U-01–U-05 implementiert |
| Security Hardening | S-01–S-05 implementiert |
