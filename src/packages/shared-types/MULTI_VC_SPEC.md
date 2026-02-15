# T-29: Multi-Credential Pipelining & SD-JWT Hardening

## 1. Objective
Expand the miTch presentation layer to support atomic proofs involving multiple, heterogeneous Verifiable Credentials (VCs). Implement a hardened "Selective Disclosure" mechanism inspired by SD-JWT (IETF) to allow granular field-level disclosure alongside ZKP predicates.

## 2. The Multi-VC Challenge
In a real-world scenario (e.g., EHDS - European Health Data Space), a single presentation request might require:
1.  **Identity VC**: To prove legal identity (Name, Birthdate).
2.  **Professional VC**: To prove license to practice (Medical ID, Specialization).
3.  **Employment VC**: To prove current affiliation (Hospital DID).

## 3. Technical Design: "The Presentation Bundle"

### 3.1 Composite Policy Request
The `VerifierRequest` is updated to handle a list of credential requirements:
```typescript
export interface MultiVCRequest {
    nonce: string;
    verifier_did: string;
    requirements: {
        credentialType: string;
        requestedClaims: string[];     // Selective Disclosure
        requestedPredicates: string[]; // ZKP (e.g., age >= 18)
    }[];
}
```

### 3.2 Atomic Session Handshake
- The `WalletService` must now "match" the request against the local vault, identifying which VCs satisfy which requirements.
- **Cross-VC Logic**: If a policy requires attributes from VC_A and VC_B, the presentation is only generated if BOTH are present and valid.

### 3.3 Selective Disclosure (SD-JWT style)
- Instead of just returning a "Fact" (ZKP), the wallet can now "unmask" specific Salted Hashes (Disclosures).
- **Hardening**: Each disclosed field remains cryptographically bound to the original VC signature, preventing "Mixed & Match" attacks where claims from different people are combined into one proof.

## 4. Implementation Workflow
1.  **Type Refactoring**: Update `VerifierRequest` and `PresentationCapsule` in `shared-types`.
2.  **Engine Update**: Enhance `PolicyEngine` to evaluate multi-requirement bundles.
3.  **Wallet Pipeline**: Implement `generateCompositePresentation` in `WalletService`.
4.  **UI Support**: Update the Presentation Dialog to show a "Bundle View" of all credentials being accessed.

## 5. Security Property: Presentation Unlinkability
Even with multiple VCs, the bundle must utilize **Pairwise DIDs** (per-verifier DIDs) so that Verifier A cannot collude with Verifier B to reconstruct the user's global profile.
