import { describe, test, expect } from 'vitest';
import { generateKeyPair } from '../src/keys';
import { signVC, verifyVC } from '../src/signing';
import type { AgeCredential } from '@mitch/shared-types';

describe('VC Signing', () => {
    test('sign and verify VC round‑trip', async () => {
        const { privateKey, publicKey } = await generateKeyPair();
        const vc: Omit<AgeCredential, "proof"> = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'AgeCredential'],
            issuer: 'did:example:issuer',
            issuanceDate: new Date().toISOString(),
            credentialSubject: {
                id: 'did:example:holder',
                dateOfBirth: '1990-01-01',
                isOver18: true,
            },
        };
        const signed = await signVC(vc, privateKey);
        expect(signed.proof).toBeDefined();
        const verified = await verifyVC(signed, publicKey);
        expect(verified.credentialSubject.isOver18).toBe(true);
    });
});
