# 31 — Interface Definitions v0

Stand: 2026-02-11

## Goal
Define clear internal interfaces so multiple contributors can implement in parallel without breaking behavior.

---

## IPolicyEvaluator
```ts
interface IPolicyEvaluator {
  evaluate(input: {
    request: VerificationRequestV0;
    policy: PolicyManifestV0;
    bindingOk: boolean;
    proofOk: boolean;
  }): Promise<DecisionResult>;
}
```

## IBindingService
```ts
interface IBindingService {
  canonicalize(request: VerificationRequestV0): Uint8Array;
  computeHash(canonicalBytes: Uint8Array): string; // base64url SHA-256
  validateBinding(request: VerificationRequestV0, runtimeAudience: string): Promise<BindingResult>;
}
```

## INonceStore
```ts
interface INonceStore {
  consumeOnce(audience: string, nonce: string, ttlSec: number): Promise<"ok" | "replay">;
}
```

## IProofVerifier
```ts
interface IProofVerifier {
  verify(bundle: ProofBundleV0): Promise<{ ok: boolean; reason?: string }>;
}
```

## IReceiptWriter
```ts
interface IReceiptWriter {
  append(receipt: DecisionReceiptV0): Promise<{ receiptRef: string }>;
}
```

---

## Error/Decision mapping rule
- Service-layer exceptions must be transformed to deny codes, never leaked raw.
- Unknown exceptions => `DENY_INTERNAL_SAFE_FAILURE`.

---

## Concurrency rule
- Nonce consumption must be atomic across concurrent verifier instances.
