# @mitch/verifier-sdk

The **miTch Verifier SDK** enables any relying party (verifier) to cryptographically verify presentations from a miTch Wallet.

## Features

- **Privacy-by-Default**: Secure Key Unwrapping & Crypto-Shredding support.
- **Zero-Trust**: Strict AAD (Additional Authenticated Data) binding.
- **Replay Protection**: Built-in nonce tracking hooks.
- **Type-Safe**: Full TypeScript support.

## Installation

```bash
pnpm add @mitch/verifier-sdk
```

## Usage

```typescript
import { VerifierSDK } from '@mitch/verifier-sdk';
import { getMyPrivateKey } from './secrets';

const sdk = new VerifierSDK({
    verifierDid: 'did:example:my-service',
    privateKey: await getMyPrivateKey(),
    // Optional: Implement replay protection
    replayCheck: async (nonce, decisionId) => {
        const exists = await db.has(nonce);
        if (!exists) await db.save(nonce);
        return exists;
    }
});

// Using Express/Fastify? Pass the body directly!
app.post('/verify', async (req, res) => {
    try {
        const result = await sdk.verifyPresentation(req.body);
        
        console.log('Verified VC:', result.vp);
        console.log('Proof Metadata:', result.proof);
        
        res.json({ success: true, data: result.vp });
    } catch (err) {
        // SDK throws named errors for easy handling
        if (err.name === 'ReplayDetectedError') {
            res.status(409).send('Replay Detected');
        } else {
            res.status(400).send(err.message);
        }
    }
});
```

## Security Guarantees

1. **Confidentiality**: Presentations are encrypted (AES-GCM-256) specifically for your Verifier DID.
2. **Integrity**: The ciphertext is bound to the `decision_id` and `nonce` via AAD.
3. **Authenticity**: The inner VP is signed by an ephemeral key, which is attested by the Wallet Policy Engine.
4. **Freshness**: Presentations older than 5 minutes are rejected automatically.
