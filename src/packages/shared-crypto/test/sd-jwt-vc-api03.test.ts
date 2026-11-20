import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT } from 'jose';
import {
    buildCNFClaim,
    buildSdJwtPresentation,
    createSDJWTDisclosures,
    issueSDJWTVC,
    validateSDJWTVC,
} from '../src/sd-jwt-vc';

// API-03 (2026-11-03 audit): typ/alg enforcement and the zero-disclosure presentation form.

const ISS = 'https://issuer.example.com';
const VCT = 'https://credentials.example.com/age';
let issuer: CryptoKeyPair;
let holder: CryptoKeyPair;

beforeAll(async () => {
    issuer = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    holder = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
});

const payload = () => ({ iss: ISS, vct: VCT, iat: Math.floor(Date.now() / 1000), _sd_alg: 'sha-256' });

async function signWithTyp(typ: string | undefined): Promise<string> {
    return new SignJWT(payload())
        .setProtectedHeader(typ === undefined ? { alg: 'ES256' } : { alg: 'ES256', typ })
        .sign(issuer.privateKey);
}

describe('API-03a: validateSDJWTVC enforces typ and algorithm', () => {
    it('accepts vc+sd-jwt and dc+sd-jwt', async () => {
        expect((await validateSDJWTVC(await signWithTyp('vc+sd-jwt'), issuer.publicKey)).ok).toBe(true);
        expect((await validateSDJWTVC(await signWithTyp('dc+sd-jwt'), issuer.publicKey)).ok).toBe(true);
    });

    it.each([['JWT'], ['kb+jwt'], ['statuslist+jwt'], [undefined]])(
        'rejects a validly signed JWT with typ=%s',
        async (typ) => {
            const r = await validateSDJWTVC(await signWithTyp(typ), issuer.publicKey);
            expect(r.ok).toBe(false);
            expect(r.errors.join(' ')).toMatch(/typ/);
        }
    );

    it('rejects an HMAC-signed token even when the verifier key bytes are known', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const hs = await new SignJWT(payload())
            .setProtectedHeader({ alg: 'HS256', typ: 'vc+sd-jwt' })
            .sign(secret);
        const r = await validateSDJWTVC(hs, { kty: 'oct', k: Buffer.from(secret).toString('base64url') });
        expect(r.ok).toBe(false);
    });
});

describe('API-03c: zero selected disclosures produce `<jwt>~<kb>` (no `~~`)', () => {
    it('builds a well-formed presentation when nothing is selected', async () => {
        const { _sd, disclosures } = await createSDJWTDisclosures({ age: 24 });
        const jwt = await issueSDJWTVC(
            { iss: ISS, vct: VCT, iat: Math.floor(Date.now() / 1000), cnf: await buildCNFClaim(holder.publicKey), _sd },
            issuer.privateKey
        );
        const { vpToken, disclosedClaims } = await buildSdJwtPresentation(
            `${jwt}~${disclosures.join('~')}~`, [], holder.privateKey, { aud: 'v', nonce: 'n' }
        );
        expect(disclosedClaims).toEqual({});
        expect(vpToken).not.toContain('~~');
        const parts = vpToken.split('~');
        expect(parts).toHaveLength(2);
        expect(parts[0]).toBe(jwt);
        expect(parts[1].split('.')).toHaveLength(3);
    });
});
