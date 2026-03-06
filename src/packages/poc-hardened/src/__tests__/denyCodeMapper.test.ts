import { describe, it, expect } from 'vitest';
import { mapToDeny } from '../policy/denyCodeMapper';

describe('mapToDeny', () => {
    it('maps known DENY codes through', () => {
        expect(mapToDeny('DENY_SCHEMA_MISSING_FIELD')).toBe('DENY_SCHEMA_MISSING_FIELD');
        expect(mapToDeny('DENY_BINDING_NONCE_REPLAY')).toBe('DENY_BINDING_NONCE_REPLAY');
        expect(mapToDeny('DENY_CREDENTIAL_REVOKED')).toBe('DENY_CREDENTIAL_REVOKED');
        expect(mapToDeny('DENY_RATE_LIMIT_EXCEEDED')).toBe('DENY_RATE_LIMIT_EXCEEDED');
    });

    it('maps ALLOW code (pass-through for known decision codes)', () => {
        expect(mapToDeny('ALLOW_MINIMAL_PROOF_VALID')).toBe('ALLOW_MINIMAL_PROOF_VALID');
    });

    it('maps unknown code to safe fallback', () => {
        expect(mapToDeny('SOME_UNKNOWN_CODE')).toBe('DENY_INTERNAL_SAFE_FAILURE');
    });

    it('maps undefined to safe fallback', () => {
        expect(mapToDeny(undefined)).toBe('DENY_INTERNAL_SAFE_FAILURE');
    });

    it('maps empty string to safe fallback', () => {
        expect(mapToDeny('')).toBe('DENY_INTERNAL_SAFE_FAILURE');
    });
});
