# Technical Spec: ZK-Query Firewall (ZKQF) Expansion

## 1. Objective
To extend the existing `@mitch/policy-engine` to handle **Real-Time Data Minimization** for AI training sets. The goal is to transform raw SD-JWT claims into anonymized feature vectors before they reach the consumer.

## 2. Architectural Extensions

### 2.1. Vectorization Layer (`TransformationService`)
- **New Module:** `src/packages/policy-engine/src/transform/vectorizer.ts`
- **Function:** Instead of simple `ALLOW/DENY`, a rule can now specify a `TRANSFORM` action.
- **Prerequisites:** Use salt-based hashing (HMAC-SHA256) to ensure anonymized identifiers are consistent within a batch but non-linkable across batches.

### 2.2. Policy Manifest Updates
Extend `PolicyManifest` to include `transformationRules`:
```typescript
{
  "resource": "clinical_data",
  "action": "READ",
  "transform": {
    "patient_id": "HASH_SALTED",
    "exact_age": "BUCKET_5_YEARS",
    "blood_pressure": "NORMALIZE_0_1"
  }
}
```

## 3. Implementation Steps in `@mitch/policy-engine`

1.  **Context Enhancement:** Update `EvaluationContext` to carry a `transformationMap`.
2.  **Rule Processor:** Add a new handler in `engine.ts` that checks for the `transform` key in a matched policy.
3.  **Secure Output Generation:** Create a `MinimizedPayload` object that strips all claims not explicitly transformed or allowed as-is.

## 4. Security Guarantees
- **Inversion Resistance:** All transformations must be one-way.
- **Side-Channel Protection:** The processing occurs within the `EphemeralKey` window (already implemented in `secure-memory`).
- **Audit Integration:** The specific transformation logic applied is logged as part of the `DecisionCapsule`.
