import cors from 'cors';
import express from 'express';
import { generateKeyPair, signVC } from '@askmi/shared-crypto';
import { buildMdocDocument, MDL_DOCTYPE, MDL_NAMESPACE, MDL_ELEMENTS } from '@askmi/mdoc';
import type { ValidityInfo } from '@askmi/mdoc';
import { newCorrelationId } from '@askmi/shared-types';
import type { AgeCredential, CredentialRequest, CredentialResponse } from '@askmi/shared-types';
import { assertValidBatch, issueAgeCredentialBatch } from './batch';

const app = express();
const allowedOrigins = new Set([
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:5174',
    'http://127.0.0.1:5175',
    // Wallet PWA dev server serves over HTTPS (self-signed) — allow the secure-context origins too.
    'https://localhost:5173',
    'https://localhost:5174',
    'https://localhost:5175',
    'https://127.0.0.1:5173',
    'https://127.0.0.1:5174',
    'https://127.0.0.1:5175',
]);
// Restrictive CORS for local wallet development only
app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.has(origin)) {
            return callback(null, true);
        }
        // Deny cleanly (fail-closed) without throwing — a disallowed origin simply
        // gets no CORS headers, rather than surfacing as a request-level error.
        console.warn(`⛔ CORS: origin not allowed: ${origin}`);
        return callback(null, false);
    }
}));
app.use(express.json());
app.use(express.static('public'));

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
    res.send('AskMI Issuer Mock Service (Port 3005) - OID4VCI Ready');
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

app.get('/status-list/1', (req, res) => {
    const bitstring = new Uint8Array(64);
    bitstring[5] = 0b00100000; // StatusList2021 index 42 is revoked (MSB-first)

    res.json({
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: `http://localhost:${PORT}/status-list/1`,
        type: ['VerifiableCredential', 'StatusList2021Credential'],
        issuer: ISSUER_DID,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
            id: `http://localhost:${PORT}/status-list/1#list`,
            type: 'StatusList2021',
            statusPurpose: 'revocation',
            encodedList: Buffer.from(bitstring).toString('base64'),
        },
    });
});

// mdoc (ISO 18013-5) Credential Issuance Endpoint
app.post('/credential/mdoc', async (req, res) => {
    if (!issuerKeys) {
        return res.status(503).json({ error: 'keys_not_initialized' });
    }

    const correlationId = req.headers['x-correlation-id']?.toString() ?? newCorrelationId();
    res.setHeader('x-correlation-id', correlationId);

    console.log('📝 Received mdoc Credential Request');
    console.log(`🔗 Correlation ID: ${correlationId}`);

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

    const correlationId = req.headers['x-correlation-id']?.toString() ?? newCorrelationId();
    res.setHeader('x-correlation-id', correlationId);

    const { credential_definition: _credential_definition, proof: _proof } = req.body as CredentialRequest; // Simplified request parsing

    console.log('📝 Received Credential Request');
    console.log(`🔗 Correlation ID: ${correlationId}`);

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
        renderMethod: [
            {
                id: `http://localhost:${PORT}/templates/age-credential.svg`,
                type: 'TemplateRenderMethod',
                format: 'svg-mustache'
            }
        ],
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

// OID4VCI Batch Issuance with Holder Binding (Proof-Randomization Increment 2 / C2)
// Wallet-generates / issuer-binds: the wallet sends N PUBLIC holder JWKs; we bind
// each into a distinct credential (did:jwk subject + cnf) and sign. No private keys.
app.post('/credential/batch', async (req, res) => {
    if (!issuerKeys) {
        return res.status(503).json({ error: 'keys_not_initialized' });
    }
    let batch;
    try {
        batch = assertValidBatch(req.body);
    } catch (e) {
        // Fail-closed: a single malformed member rejects the whole batch.
        return res.status(400).json({ error: 'invalid_batch_request', details: (e as Error).message });
    }
    try {
        const credentials = await issueAgeCredentialBatch(batch, issuerKeys.privateKey, ISSUER_DID);
        console.log(`✅ Batch Issued: ${credentials.length} holder-bound credentials`);
        return res.json({ credentials });
    } catch (error) {
        console.error('Batch signing failed:', error);
        return res.status(500).json({ error: 'server_error' });
    }
});

const PORT = process.env.PORT || 3005;

// Start server and init keys
app.listen(PORT, async () => {
    await initKeys();
    console.log(`Issuer Mock listening on http://localhost:${PORT}`);
});
