import cors from 'cors';
import express from 'express';
import { generateKeyPair, signVC } from '@mitch/shared-crypto';
import { buildMdocDocument, MDL_DOCTYPE, MDL_NAMESPACE, MDL_ELEMENTS } from '@mitch/mdoc';
import type { ValidityInfo } from '@mitch/mdoc';
import type { AgeCredential, CredentialRequest, CredentialResponse } from '@mitch/shared-types';

const app = express();
const defaultAllowedOrigins = [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:5174',
    'http://127.0.0.1:5175',
    'http://wallet.localhost',
    'http://verifier.localhost',
];
const allowedOrigins = new Set(
    (process.env.CORS_ORIGINS ?? defaultAllowedOrigins.join(','))
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean)
);
// Restrictive CORS for local wallet development only
app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.has(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Origin not allowed by issuer-mock CORS policy'));
    }
}));
app.use(express.json());
app.use(express.static('public'));

// Global Issuer KeyPair (In-Memory for PoC)
let issuerKeys: CryptoKeyPair | null = null;
const ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? 'http://localhost:3005';
const ISSUER_DID = process.env.ISSUER_DID ?? 'did:web:localhost%3A3005'; // encoding : to %3A for did:web

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
        credential_issuer: ISSUER_BASE_URL,
        credential_endpoint: `${ISSUER_BASE_URL}/credential`,
        credentials_supported: [
            {
                id: 'AgeCredential',
                format: 'jwt_vc_json',
                types: ['VerifiableCredential', 'AgeCredential'],
                cryptographic_binding_methods_supported: ['did:key'],
                credential_signing_alg_values_supported: ['ES256']
            },
            {
                id: 'mDL',
                format: 'mso_mdoc',
                types: [MDL_DOCTYPE],
                cryptographic_binding_methods_supported: ['cose_key'],
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

// mdoc (ISO 18013-5) Credential Issuance Endpoint
app.post('/credential/mdoc', async (req, res) => {
    if (!issuerKeys) {
        return res.status(503).json({ error: 'keys_not_initialized' });
    }

    console.log('📝 Received mdoc Credential Request');

    // In a real implementation, device_key would come from the wallet's proof of possession.
    // For PoC, we generate an ephemeral device key pair and return the public key.
    const deviceKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify'],
    );

    const now = new Date();
    const validFrom = now.toISOString();
    const validUntil = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString();

    try {
        const result = await buildMdocDocument({
            docType: MDL_DOCTYPE,
            nameSpaces: {
                [MDL_NAMESPACE]: {
                    [MDL_ELEMENTS.FAMILY_NAME]: 'Mustermann',
                    [MDL_ELEMENTS.GIVEN_NAME]: 'Erika',
                    [MDL_ELEMENTS.BIRTH_DATE]: '1990-01-01',
                    [MDL_ELEMENTS.AGE_OVER_18]: true,
                    [MDL_ELEMENTS.AGE_OVER_21]: true,
                    [MDL_ELEMENTS.ISSUING_COUNTRY]: 'DE',
                    [MDL_ELEMENTS.ISSUING_AUTHORITY]: 'Bundesdruckerei GmbH',
                },
            },
            issuerPrivateKey: issuerKeys.privateKey,
            devicePublicKey: deviceKeyPair.publicKey,
            validityInfo: {
                signed: validFrom,
                validFrom,
                validUntil,
            } as unknown as ValidityInfo,
        });

        // Base64url-encode the CBOR document for JSON transport
        let binary = '';
        for (let i = 0; i < result.documentCbor.length; i++) {
            binary += String.fromCharCode(result.documentCbor[i]);
        }
        const credentialBase64 = btoa(binary)
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        const response: CredentialResponse = {
            format: 'mso_mdoc',
            credential: credentialBase64,
            c_nonce: crypto.randomUUID(),
            c_nonce_expires_in: 86400,
        };

        console.log('✅ mdoc mDL Credential Issued');
        return res.json(response);

    } catch (error) {
        console.error('mdoc issuance failed:', error);
        return res.status(500).json({ error: 'server_error' });
    }
});

// Credential Issuance Endpoint
app.post('/credential', async (req, res) => {
    if (!issuerKeys) {
        return res.status(503).json({ error: 'keys_not_initialized' });
    }

    const { credential_definition: _credential_definition, proof: _proof } = req.body as CredentialRequest; // Simplified request parsing

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
