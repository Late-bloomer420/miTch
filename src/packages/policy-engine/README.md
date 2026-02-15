# @mitch/policy-engine

Core logic for the miTch Identity Wallet ("Wallet as a Lawyer").  
Evaluates Verifier Requests against User Policy before any data is shared.

## Features

- **Rule Matching**: Matches requests based on Verifier DID or Origin.
- **Claim Permissions**: Enforces `allowedClaims` and `deniedClaims` locally.
- **Trust Registry**: Checks if the Issuer of the credential is trusted.
- **Consent Logic**: Algorithms to determine if USER CONSENT or PROOF OF PRESENCE is needed.
- **Decision Capsule**: Generates cryptographically bound decision artifacts (T-12).

## Usage

```typescript
import { PolicyEngine } from '@mitch/policy-engine';
import { type VerifierRequest, type PolicyManifest } from '@mitch/shared-types';

const engine = new PolicyEngine();

const decision = await engine.evaluate(
  verifierRequest,
  evaluationContext,
  availableCredentials,
  userPolicyManifest
);

if (decision.verdict === 'ALLOW') {
  // Proceed to generate VP
} else if (decision.verdict === 'PROMPT') {
  // Show UI to user with decision.decisionCapsule
} else {
  // Auto-reject
}
```

## Testing

Run unit tests via Vitest:

```bash
npm test
```
