import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import {
    canonicalizePredicate,
    canonicalizeRequest,
    legacyToDSL,
    type Predicate,
    type PredicateRequest,
    type LegacyPredicateRequest
} from '../src/predicates';

describe('shared-types/predicates canonicalization', () => {
    it('canonicalizePredicate is stable for semantically identical predicates', () => {
        const p1: Predicate = {
            id: 'age-18',
            description: 'Age >= 18',
            credentialTypes: ['IdentityCredential'],
            expression: {
                logic: 'and',
                clauses: [
                    { path: 'credentialSubject.birthDate', op: 'gte', value: 18, type: 'age_years' }
                ]
            }
        };

        const p2: Predicate = {
            description: 'Age >= 18',
            credentialTypes: ['IdentityCredential'],
            id: 'age-18',
            expression: {
                logic: 'and',
                clauses: [
                    { op: 'gte', path: 'credentialSubject.birthDate', type: 'age_years', value: 18 }
                ]
            }
        };

        expect(canonicalizePredicate(p1)).toBe(canonicalizePredicate(p2));
    });

    it('canonicalizeRequest is stable when predicate order differs (AND semantics)', () => {
        const base = {
            verifierDid: 'did:web:shop.example',
            nonce: 'n-123',
            purpose: 'Age gate',
            timestamp: '2026-01-28T00:00:00.000Z'
        };

        const pA: Predicate = { id: 'a', description: 'A', credentialTypes: ['X'], expression: { logic: 'and', clauses: [] } };
        const pB: Predicate = { id: 'b', description: 'B', credentialTypes: ['X'], expression: { logic: 'and', clauses: [] } };

        const r1: PredicateRequest = { ...base, predicates: [pA, pB] };
        const r2: PredicateRequest = { ...base, predicates: [pB, pA] };

        expect(canonicalizeRequest(r1)).toBe(canonicalizeRequest(r2));
    });
});

describe('shared-types/predicates legacy adapter', () => {
    it('converts legacy constraints into a canonical predicate expression', () => {
        const legacy: LegacyPredicateRequest = {
            verifierDid: 'did:web:shop.example',
            nonce: 'n-123',
            purpose: 'Age gate',
            constraints: [{ attribute: 'birthDate', operator: 'gte', value: 18 }]
        };

        const request = legacyToDSL(legacy);
        const predicate = request.predicates[0] as Predicate;
        const clause = predicate.expression.clauses[0];

        if ('logic' in clause) {
            throw new Error('Expected clause, got expression');
        }

        expect(clause.type).toBe('age_years');
        expect(clause.path).toBe('birthDate');
    });

    it('fails closed for unsupported legacy operators', () => {
        const legacy: LegacyPredicateRequest = {
            verifierDid: 'did:web:shop.example',
            nonce: 'n-123',
            purpose: '???',
            constraints: [{ attribute: 'birthDate', operator: 'regex' as any, value: '.*' }]
        };

        expect(() => legacyToDSL(legacy)).toThrow('UNSUPPORTED_LEGACY_OPERATOR');
    });

    it('fails closed for unsupported legacy attributes', () => {
        const legacy: LegacyPredicateRequest = {
            verifierDid: 'did:web:shop.example',
            nonce: 'n-123',
            purpose: '???',
            constraints: [{ attribute: 'unknown' as any, operator: 'eq', value: 'x' }]
        };

        expect(() => legacyToDSL(legacy)).toThrow('UNSUPPORTED_LEGACY_ATTRIBUTE');
    });
});

describe('shared-types/predicates module hygiene', () => {
    it('does not import crypto implementations', () => {
        const fileUrl = new URL('../src/predicates.ts', import.meta.url);
        const source = fs.readFileSync(fileUrl, 'utf-8');

        expect(source).not.toMatch(/from ['"]crypto['"]/);
        expect(source).not.toMatch(/from ['"]jose['"]/);
        expect(source).not.toContain('@mitch/shared-crypto');
    });
});
