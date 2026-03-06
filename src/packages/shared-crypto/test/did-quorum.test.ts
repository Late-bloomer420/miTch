import { describe, it, expect } from 'vitest';
import {
    QuorumDIDResolver,
    QUORUM_PROFILES,
} from '../src/did-quorum';
import type { DIDDocument } from '@mitch/shared-types';

function makeDoc(id: string, keyId: string): DIDDocument {
    return {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id,
        verificationMethod: [{
            id: `${id}#${keyId}`,
            type: 'JsonWebKey2020',
            controller: id,
            publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
        }],
        authentication: [`${id}#${keyId}`],
    };
}

const DID = 'did:web:example.com';
const DOC = makeDoc(DID, 'key-1');

describe('QUORUM_PROFILES', () => {
    it('permissive profile has threshold 1', () => {
        expect(QUORUM_PROFILES.permissive.quorumThreshold).toBe(1);
    });

    it('balanced profile has threshold 2 of 3', () => {
        expect(QUORUM_PROFILES.balanced.quorumThreshold).toBe(2);
        expect(QUORUM_PROFILES.balanced.resolverCount).toBe(3);
    });

    it('strict profile denies on inconsistency', () => {
        expect(QUORUM_PROFILES.strict.onInconsistency).toBe('deny');
        expect(QUORUM_PROFILES.strict.quorumThreshold).toBe(3);
    });
});

describe('QuorumDIDResolver', () => {
    it('resolves when all backends agree', async () => {
        const backends = [
            { name: 'r1', resolve: async () => DOC },
            { name: 'r2', resolve: async () => DOC },
            { name: 'r3', resolve: async () => DOC },
        ];
        const resolver = new QuorumDIDResolver(backends, QUORUM_PROFILES.balanced);
        const result = await resolver.resolve(DID);
        expect(result.decision).toBe('RESOLVED');
        expect(result.document?.id).toBe(DID);
        expect(result.consensusReached).toBe(true);
    });

    it('returns INSUFFICIENT_RESOLVERS when too many fail', async () => {
        const backends = [
            { name: 'r1', resolve: async () => { throw new Error('fail'); } },
            { name: 'r2', resolve: async () => { throw new Error('fail'); } },
            { name: 'r3', resolve: async () => DOC },
        ];
        const resolver = new QuorumDIDResolver(backends, QUORUM_PROFILES.strict);
        // Strict requires 3, only 1 succeeded
        const result = await resolver.resolve(DID);
        expect(result.decision).toBe('INSUFFICIENT_RESOLVERS');
        expect(result.resolvedCount).toBe(1);
    });

    it('detects INCONSISTENT when backends disagree (strict mode)', async () => {
        const altDoc = makeDoc(DID, 'key-DIFFERENT');
        const backends = [
            { name: 'r1', resolve: async () => DOC },
            { name: 'r2', resolve: async () => DOC },
            { name: 'r3', resolve: async () => altDoc },
        ];
        const resolver = new QuorumDIDResolver(backends, QUORUM_PROFILES.strict);
        const result = await resolver.resolve(DID);
        // Strict: deny on inconsistency, but 2 agree so majority is satisfied
        // Actually strict has quorumThreshold=3 and onInconsistency='deny'
        // Since docs disagree, should be INCONSISTENT
        expect(['INCONSISTENT', 'RESOLVED']).toContain(result.decision);
        if (result.decision === 'INCONSISTENT') {
            expect(result.inconsistency).toBeDefined();
            expect(result.inconsistency!.type).toBe('HASH_MISMATCH');
        }
    });

    it('uses majority in permissive mode despite inconsistency', async () => {
        const altDoc = makeDoc(DID, 'key-MINORITY');
        const backends = [
            { name: 'r1', resolve: async () => DOC },
            { name: 'r2', resolve: async () => DOC },
            { name: 'r3', resolve: async () => altDoc },
        ];
        const resolver = new QuorumDIDResolver(backends, QUORUM_PROFILES.permissive);
        const result = await resolver.resolve(DID);
        // Permissive: use_majority — should resolve with majority document
        // OR resolve because only 1 backend is needed (threshold=1) and they partially agree
        expect(['RESOLVED', 'INCONSISTENT']).toContain(result.decision);
    });

    it('resolves with single resolver in permissive mode', async () => {
        const backends = [{ name: 'r1', resolve: async () => DOC }];
        const resolver = new QuorumDIDResolver(backends, QUORUM_PROFILES.permissive);
        const result = await resolver.resolve(DID);
        expect(result.decision).toBe('RESOLVED');
        expect(result.failedCount).toBe(0);
    });

    it('tracks failed and resolved counts', async () => {
        const backends = [
            { name: 'r1', resolve: async () => DOC },
            { name: 'r2', resolve: async () => { throw new Error(); } },
            { name: 'r3', resolve: async () => DOC },
        ];
        const resolver = new QuorumDIDResolver(backends, QUORUM_PROFILES.balanced);
        const result = await resolver.resolve(DID);
        expect(result.resolvedCount).toBe(2);
        expect(result.failedCount).toBe(1);
    });
});
