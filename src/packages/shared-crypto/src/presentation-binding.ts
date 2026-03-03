/**
 * @module @mitch/shared-crypto/presentation-binding
 *
 * Presentation request canonicalization and binding validation.
 *
 * Spec: docs/specs/108_Presentation_Binding_AntiReplay_Spec_v1.md
 */

import { sha256, canonicalStringify } from './hashing';
import {
    BindingNonceStore,
    DENY_SCHEMA_MISSING_FIELD,
    DENY_BINDING_HASH_MISMATCH,
    DENY_BINDING_AUDIENCE_MISMATCH,
    DENY_BINDING_EXPIRED,
    type ConsumeResult,
} from './nonce-store';

// ── Types ───────────────────────────────────────────────────────────────────

export interface PresentationRequestBinding {
    nonce: string;
    expiresAt: string; // ISO 8601
    requestHash?: string; // hex-encoded SHA-256
}

export interface PresentationRequestRP {
    id: string;
    audience: string;
}

export interface PresentationRequest {
    version: string;
    requestId: string;
    rp: PresentationRequestRP;
    purpose: string;
    claims: string[];
    policyRef?: string;
    binding: PresentationRequestBinding;
}

export type BindingValidationResult =
    | { ok: true }
    | { ok: false; code: string };

// ── Canonicalization ────────────────────────────────────────────────────────

/**
 * Build the canonical hash input object from a presentation request.
 * Excludes `binding.requestHash` per spec.
 */
function buildHashInput(req: PresentationRequest): Record<string, unknown> {
    const obj: Record<string, unknown> = {
        version: req.version,
        requestId: req.requestId,
        rp: { id: req.rp.id, audience: req.rp.audience },
        purpose: req.purpose,
        claims: req.claims,
        binding: {
            nonce: req.binding.nonce,
            expiresAt: req.binding.expiresAt,
        },
    };
    if (req.policyRef !== undefined) {
        obj.policyRef = req.policyRef;
    }
    return obj;
}

/**
 * Compute the canonical request hash (SHA-256, hex).
 */
export async function computeRequestHash(req: PresentationRequest): Promise<string> {
    const input = buildHashInput(req);
    const canonical = canonicalStringify(input);
    return sha256(canonical);
}

// ── Binding Validation ──────────────────────────────────────────────────────

/**
 * Validate a presentation request's binding against the nonce store.
 *
 * Validation order (spec §5):
 * 1. Required fields present
 * 2. Nonce exists in store for audience
 * 3. Not expired (with skew)
 * 4. Audience matches verifier's own ID
 * 5. Request hash matches
 * 6. Consume nonce atomically
 */
export async function validateBinding(
    req: PresentationRequest,
    nonceStore: BindingNonceStore,
    verifierAudience: string,
    now: number = Date.now()
): Promise<BindingValidationResult> {
    // 1. Required fields
    if (
        !req.version ||
        !req.requestId ||
        !req.rp?.id ||
        !req.rp?.audience ||
        !req.purpose ||
        !req.claims ||
        !req.binding?.nonce ||
        !req.binding?.expiresAt ||
        !req.binding?.requestHash
    ) {
        return { ok: false, code: DENY_SCHEMA_MISSING_FIELD };
    }

    // 3. Expiry check (before nonce consume to avoid consuming on expired requests)
    const expiresAtMs = new Date(req.binding.expiresAt).getTime();
    if (isNaN(expiresAtMs)) {
        return { ok: false, code: DENY_BINDING_EXPIRED };
    }

    // 4. Audience matches verifier's own identifier
    if (req.rp.audience !== verifierAudience) {
        return { ok: false, code: DENY_BINDING_AUDIENCE_MISMATCH };
    }

    // 5. Request hash matches
    const expectedHash = await computeRequestHash(req);
    if (expectedHash !== req.binding.requestHash) {
        return { ok: false, code: DENY_BINDING_HASH_MISMATCH };
    }

    // 2 + 6. Nonce exists + consume atomically (nonce store handles expiry + replay)
    const consumeResult: ConsumeResult = nonceStore.consume(req.rp.audience, req.binding.nonce, now);
    if (!consumeResult.ok) {
        return consumeResult;
    }

    return { ok: true };
}
