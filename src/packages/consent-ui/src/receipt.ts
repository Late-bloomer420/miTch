import type { ConsentReceipt, ConsentRequest, ConsentResult } from './types';

function stableStringify(value: unknown): string {
    if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
        a.localeCompare(b)
    );
    return `{${entries
        .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`)
        .join(',')}}`;
}

const HEX = '0123456789abcdef';

function bytesToHex(bytes: Uint8Array): string {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        out += HEX[(b >> 4) & 0xf] + HEX[b & 0xf];
    }
    return out;
}

async function sha256Hex(input: string): Promise<string> {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
        throw new Error('SubtleCrypto unavailable; consent receipts require a secure context.');
    }
    const data = new TextEncoder().encode(input);
    const digest = await subtle.digest('SHA-256', data);
    return bytesToHex(new Uint8Array(digest));
}

function canonicalRequest(req: ConsentRequest): Record<string, unknown> {
    return {
        requestId: req.requestId,
        verifierId: req.verifier.id,
        purpose: req.purpose,
        claims: [...req.claims].map((c) => ({ key: c.key, policyState: c.policyState })).sort((a, b) =>
            a.key.localeCompare(b.key)
        ),
        predicates: [...req.predicates]
            .map((p) => ({
                id: p.id,
                claim: p.claim,
                operation: p.operation,
                value: p.value,
                policyState: p.policyState,
            }))
            .sort((a, b) => a.id.localeCompare(b.id)),
    };
}

export async function buildConsentReceipt(
    request: ConsentRequest,
    result: ConsentResult
): Promise<ConsentReceipt> {
    if (request.requestId !== result.requestId) {
        throw new Error('ConsentResult.requestId does not match ConsentRequest.requestId');
    }
    const verifierHash = await sha256Hex(request.verifier.id);
    const requestHash = await sha256Hex(stableStringify(canonicalRequest(request)));
    const receiptBody = stableStringify({
        v: 'mitch.consent.v1',
        requestId: result.requestId,
        verdict: result.verdict,
        verifierRef: `sha256:${verifierHash}`,
        requestHash,
        policyHash: request.policy?.hash,
        timestamp: result.timestamp,
        allowedClaims: [...result.allowedClaims].sort(),
        allowedPredicateIds: [...result.allowedPredicateIds].sort(),
        withheldClaims: [...result.withheldClaims].sort(),
        withheldPredicateIds: [...result.withheldPredicateIds].sort(),
    });
    const receiptId = await sha256Hex(receiptBody);

    return {
        receiptId: `consent-${receiptId.slice(0, 16)}`,
        requestId: result.requestId,
        verifierRef: `sha256:${verifierHash}`,
        purpose: request.purpose,
        verdict: result.verdict,
        allowedClaims: [...result.allowedClaims].sort(),
        allowedPredicateIds: [...result.allowedPredicateIds].sort(),
        withheldClaims: [...result.withheldClaims].sort(),
        withheldPredicateIds: [...result.withheldPredicateIds].sort(),
        requestHash,
        policyHash: request.policy?.hash,
        timestamp: result.timestamp,
        rawClaimsStored: false,
    };
}

export const __test__ = { stableStringify, sha256Hex };
