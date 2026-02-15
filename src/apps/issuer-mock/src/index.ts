import cors from 'cors';
import express from 'express';
import { generateKeyPair, signVC } from '@mitch/shared-crypto';
import type { AgeCredential, CredentialRequest, CredentialResponse } from '@mitch/shared-types';

const app = express();
// Enable CORS for Wallet PWA
app.use(cors({ origin: true })); // Allow all origins for PoC, or specific 'http://localhost:5173'
app.use(express.json());

// Global Issuer KeyPair (In-Memory for PoC)
let issuerKeys: CryptoKeyPair | null = null;
const ISSUER_DID = 'did:web:localhost%3A3005'; // encoding : to %3A for did:web

// Initialize keys on startup
async function initKeys() {
    console.log('🔑 Generating Issuer Keys...');
    issuerKeys = await generateKeyPair();
    console.log('✅ Issuer Keys Ready (ECDSA P-256)');
}

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'issuer-mock',
        keysReady: !!issuerKeys
    });
});

app.get('/', (req, res) => {
    res.send('miTch Issuer Mock Service (Port 3005) - OID4VCI Ready');
});

// OID4VCI Metadata Endpoint
// OID4VCI Metadata Endpoint
app.get('/.well-known/openid-credential-issuer', (req, res) => {
    res.json({
        credential_issuer: 'http://localhost:3005',
        credential_endpoint: 'http://localhost:3005/credential',
        credentials_supported: [
            {
                id: 'AgeCredential',
                format: 'jwt_vc_json',
                types: ['VerifiableCredential', 'AgeCredential'],
                cryptographic_binding_methods_supported: ['did:key'],
                credential_signing_alg_values_supported: ['ES256']
            }
        ]
    });
});

// JWKS Endpoint (for Verifier to fetch public key)
app.get('/.well-known/jwks.json', async (req, res) => {
    if (!issuerKeys) return res.status(503).json({ error: 'keys_not_ready' });

    // Export public key to JWK
    const jwk = await crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

    res.json({
        keys: [
            {
                ...jwk,
                kid: 'key-1', // Key ID matches 'verificationMethod' in VC
                use: 'sig',
                alg: 'ES256'
            }
        ]
    });
});

// Credential Issuance Endpoint
app.post('/credential', async (req, res) => {
    if (!issuerKeys) {
        return res.status(503).json({ error: 'keys_not_initialized' });
    }

    const { credential_definition, proof } = req.body as CredentialRequest; // Simplified request parsing

    console.log('📝 Received Credential Request');

    // PoC: We blindly issue an "Over 18" credential to anyone who asks
    // In reality, we would verify the 'proof' (PoP) and maybe a user session.

    const now = new Date();

    // Construct the VC payload
    const vcPayload: Omit<AgeCredential, 'proof'> = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://mitch.example/contexts/age/v1'
        ],
        id: `urn:uuid:${crypto.randomUUID()}`,
        type: ['VerifiableCredential', 'AgeCredential'],
        issuer: { id: ISSUER_DID, name: 'State Liquor Authority' },
        issuanceDate: now.toISOString(),
        credentialSubject: {
            id: 'did:key:zUnknownHolderForKeyBindingPoC', // Placeholder, normally extracted from request proof
            dateOfBirth: '1990-01-01',
            isOver18: true
        }
    };

    try {
        // Sign the credential
        const signedVC = await signVC(vcPayload, issuerKeys.privateKey);

        // Return standard OID4VCI response
        const response: CredentialResponse = {
            format: 'jwt_vc_json',
            credential: signedVC.proof?.jwt || '', // Return the JWT string
            c_nonce: crypto.randomUUID(),
            c_nonce_expires_in: 86400
        };

        console.log('✅ Credential Issued:', vcPayload.id);
        return res.json(response);

    } catch (error) {
        console.error('Signing failed:', error);
        return res.status(500).json({ error: 'server_error' });
    }
});

const PORT = process.env.PORT || 3005;

// Start server and init keys
app.listen(PORT, async () => {
    await initKeys();
    console.log(`Issuer Mock listening on http://localhost:${PORT}`);
});
