import { afterEach, describe, expect, it, vi } from 'vitest';
import { EUDITrustListResolver, type TrustList } from './trust-list-resolver.js';
import { canonicalStringify } from './hashing.js';
import { signData } from './signing.js';

// #240: outside explicit dev mode the trust list must be signed by a configured
// anchor and fetched over HTTPS. Anything else is a DENY, not a warning.
const ISSUER = 'did:example:trusted-issuer';
const LIST: TrustList = {
    id: 'test-tsl',
    version: '1.0',
    validUntil: '2030-01-01',
    issuers: [ISSUER],
    verifiers: [],
};
const HTTPS_URL = 'https://trust.example/v1/list.json';

async function anchor() {
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
    ]);
    const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    return { keys, jwk };
}
const sign = async (list: TrustList, key: CryptoKey): Promise<TrustList> => ({
    ...list,
    signature: await signData(canonicalStringify(list), key),
});
const serving = (list: TrustList) =>
    vi.fn().mockResolvedValue({ ok: true, json: async () => list }) as unknown as typeof fetch;

describe('EUDITrustListResolver trust mode (#240)', () => {
    afterEach(() => {
        vi.unstubAllEnvs();
        vi.useRealTimers();
    });

    it('defaults to live mode and denies when no anchor key is configured', async () => {
        vi.stubEnv('ASKMI_TRUST_MODE', undefined);
        const resolver = new EUDITrustListResolver({ fetchFn: serving(LIST) });
        resolver.setUrl(HTTPS_URL);

        const result = await resolver.isIssuerTrusted(ISSUER);

        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TRUST_SOURCE_UNAVAILABLE');
        expect(result.reason).toContain('TSL_ANCHOR_KEY_MISSING');
    });

    it('treats an unknown ASKMI_TRUST_MODE value as live', async () => {
        vi.stubEnv('ASKMI_TRUST_MODE', 'development');
        const resolver = new EUDITrustListResolver({ fetchFn: serving(LIST) });
        resolver.setUrl(HTTPS_URL);

        const result = await resolver.isIssuerTrusted(ISSUER);

        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TSL_ANCHOR_KEY_MISSING');
    });

    it('live mode denies an unsigned list even with an anchor key', async () => {
        const { jwk } = await anchor();
        const resolver = new EUDITrustListResolver({ trustMode: 'live', fetchFn: serving(LIST) });
        resolver.setUrl(HTTPS_URL);
        await resolver.setAnchorKey(jwk);

        const result = await resolver.isIssuerTrusted(ISSUER);

        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TSL_SIGNATURE_MISSING');
    });

    it('live mode denies a list signed by a different key', async () => {
        const trusted = await anchor();
        const other = await anchor();
        const resolver = new EUDITrustListResolver({
            trustMode: 'live',
            fetchFn: serving(await sign(LIST, other.keys.privateKey)),
        });
        resolver.setUrl(HTTPS_URL);
        await resolver.setAnchorKey(trusted.jwk);

        const result = await resolver.isIssuerTrusted(ISSUER);

        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TSL_SIGNATURE_INVALID');
    });

    it('live mode denies a signed list whose issuers were changed after signing', async () => {
        const { keys, jwk } = await anchor();
        const signed = await sign(LIST, keys.privateKey);
        const resolver = new EUDITrustListResolver({
            trustMode: 'live',
            fetchFn: serving({ ...signed, issuers: [ISSUER, 'did:example:injected'] }),
        });
        resolver.setUrl(HTTPS_URL);
        await resolver.setAnchorKey(jwk);

        expect((await resolver.isIssuerTrusted('did:example:injected')).decision).toBe('DENY');
    });

    it('live mode refuses a non-HTTPS list URL without fetching it', async () => {
        const { keys, jwk } = await anchor();
        const fetchFn = serving(await sign(LIST, keys.privateKey));
        const resolver = new EUDITrustListResolver({ trustMode: 'live', fetchFn });
        resolver.setUrl('http://trust.example/v1/list.json');
        await resolver.setAnchorKey(jwk);

        const result = await resolver.isIssuerTrusted(ISSUER);

        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TSL_URL_INSECURE');
        expect(fetchFn).not.toHaveBeenCalled();
    });

    it('live mode accepts a correctly signed list over HTTPS', async () => {
        const { keys, jwk } = await anchor();
        const resolver = new EUDITrustListResolver({
            trustMode: 'live',
            fetchFn: serving(await sign(LIST, keys.privateKey)),
        });
        resolver.setUrl(HTTPS_URL);
        await resolver.setAnchorKey(jwk);

        expect((await resolver.isIssuerTrusted(ISSUER)).decision).toBe('ALLOW');
    });

    it('live mode reads the anchor key from ASKMI_TSL_ANCHOR_JWK', async () => {
        const { keys, jwk } = await anchor();
        vi.stubEnv('ASKMI_TRUST_MODE', 'live');
        vi.stubEnv('ASKMI_TSL_ANCHOR_JWK', JSON.stringify(jwk));
        const resolver = new EUDITrustListResolver({
            fetchFn: serving(await sign(LIST, keys.privateKey)),
        });
        resolver.setUrl(HTTPS_URL);

        expect((await resolver.isIssuerTrusted(ISSUER)).decision).toBe('ALLOW');
    });

    it('live mode denies when ASKMI_TSL_ANCHOR_JWK is not a usable key', async () => {
        vi.stubEnv('ASKMI_TSL_ANCHOR_JWK', '{not json');
        const resolver = new EUDITrustListResolver({ trustMode: 'live', fetchFn: serving(LIST) });
        resolver.setUrl(HTTPS_URL);

        const result = await resolver.isIssuerTrusted(ISSUER);

        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TSL_ANCHOR_KEY_INVALID');
    });

    it('dev mode accepts an unsigned list over HTTP when ASKMI_TRUST_MODE=dev', async () => {
        vi.stubEnv('ASKMI_TRUST_MODE', 'dev');
        const resolver = new EUDITrustListResolver({ fetchFn: serving(LIST) });
        resolver.setUrl('http://localhost:3005/v1/eudi-lotl.json');

        expect((await resolver.isIssuerTrusted(ISSUER)).decision).toBe('ALLOW');
    });

    it('dev mode still verifies the signature once an anchor key is set', async () => {
        const { jwk } = await anchor();
        const resolver = new EUDITrustListResolver({ trustMode: 'dev', fetchFn: serving(LIST) });
        await resolver.setAnchorKey(jwk);

        const result = await resolver.isIssuerTrusted(ISSUER);

        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TSL_SIGNATURE_MISSING');
    });

    describe('stale cache when the source is unreachable', () => {
        const HOUR = 60 * 60 * 1000;
        async function staleAfter(hours: number, riskTier: 'low' | 'high') {
            vi.useFakeTimers();
            const resolver = new EUDITrustListResolver({ trustMode: 'dev', fetchFn: serving(LIST) });
            await resolver.isIssuerTrusted(ISSUER);
            vi.advanceTimersByTime(hours * HOUR);
            resolver.setFetch(vi.fn().mockRejectedValue(new Error('down')) as unknown as typeof fetch);
            return resolver.isIssuerTrusted(ISSUER, riskTier);
        }

        it('low risk may use the cache inside the grace window', async () => {
            expect((await staleAfter(25, 'low')).decision).toBe('ALLOW');
        });

        it('high risk gets no grace window', async () => {
            const result = await staleAfter(25, 'high');
            expect(result.decision).toBe('DENY');
            expect(result.reason).toContain('TRUST_SOURCE_UNAVAILABLE');
        });

        it('low risk is denied once the grace window has passed', async () => {
            expect((await staleAfter(29, 'low')).decision).toBe('DENY');
        });
    });
});
