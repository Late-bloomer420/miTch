/**
 * Correlation IDs (G-100.4) — one canonical, greppable identifier per demo
 * transaction that flows across Wallet ↔ Verifier ↔ Issuer, so a single id
 * traces the whole exchange end-to-end in every service's logs and audit events.
 *
 * Pure and zero-dependency by design: the verifier and the wallet both import
 * this one derivation, so they always agree on the same id for a transaction —
 * the verifier mints it, but if an un-upgraded verifier omits it, both sides
 * deterministically derive `txn_<nonce>` from the shared session nonce and still
 * line up. Never carries PII; the nonce is already an opaque session value.
 */

export const CORRELATION_ID_PREFIX = 'txn_';

/** Mint a fresh correlation id (verifier-side, at request creation). */
export function newCorrelationId(): string {
    return `${CORRELATION_ID_PREFIX}${crypto.randomUUID()}`;
}

/** True for a well-formed correlation id (prefix plus a non-empty body). */
export function isCorrelationId(value: unknown): value is string {
    return (
        typeof value === 'string' &&
        value.startsWith(CORRELATION_ID_PREFIX) &&
        value.length > CORRELATION_ID_PREFIX.length
    );
}

/**
 * Resolve the canonical correlation id for a transaction. Prefers an explicit
 * verifier-minted id; otherwise derives a stable `txn_<nonce>` from the session
 * nonce so services still converge on one id; falls back to a fresh id only when
 * neither is available.
 */
export function resolveCorrelationId(input: {
    correlationId?: string | null;
    nonce?: string | null;
}): string {
    if (isCorrelationId(input.correlationId)) {
        return input.correlationId;
    }
    if (typeof input.nonce === 'string' && input.nonce.length > 0) {
        return `${CORRELATION_ID_PREFIX}${input.nonce}`;
    }
    return newCorrelationId();
}
