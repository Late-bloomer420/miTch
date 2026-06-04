/**
 * Adapter: maps @askmi/policy-engine outputs onto the embeddable ConsentRequest.
 *
 * Type-only import keeps the runtime decoupled — the policy engine's Node-side
 * crypto never gets pulled into the browser bundle.
 */

import type { Decision, DisclosureRequest, Policy } from '@askmi/policy-engine';
import type { ClaimItem, ConsentRequest, PredicateItem } from './types';

export interface FromPolicyDecisionInput {
    request: DisclosureRequest;
    decision?: Decision;
    policy?: Pick<Policy, 'id' | 'version'> & { hash?: string };
    /** Optional display name for the verifier — id alone is opaque. */
    verifierDisplayName?: string;
    /** Optional preview map: claim key -> non-sensitive preview string. */
    previews?: Record<string, string>;
    /** Optional human label map. */
    labels?: Record<string, string>;
}

function predicateKey(claim: string, operation: string, value: unknown): string {
    return `${claim}|${operation}|${stableValue(value)}`;
}

function stableValue(v: unknown): string {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(stableValue).join(',')}]`;
    const entries = Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
        a.localeCompare(b)
    );
    return `{${entries.map(([k, val]) => `${JSON.stringify(k)}:${stableValue(val)}`).join(',')}}`;
}

export function fromPolicyDecision(input: FromPolicyDecisionInput): ConsentRequest {
    const { request, decision, policy, verifierDisplayName, previews, labels } = input;

    const denied = new Set(decision?.deniedClaims ?? []);
    const allowedDisclosureKey =
        decision?.allowedDisclosure && decision.allowedDisclosure.type === 'predicate'
            ? predicateKey(
                  decision.allowedDisclosure.claim,
                  decision.allowedDisclosure.operation,
                  decision.allowedDisclosure.value
              )
            : null;

    const claims: ClaimItem[] = request.requestedClaims.map((key) => {
        if (denied.has(key)) {
            return { key, label: labels?.[key], policyState: 'denied' as const };
        }
        return {
            key,
            label: labels?.[key],
            preview: previews?.[key],
            policyState: 'requested' as const,
        };
    });

    const predicates: PredicateItem[] = request.requestedPredicates.map((p, idx) => {
        const id = `pred_${idx}_${p.claim}_${p.operation}`;
        const k = predicateKey(p.claim, p.operation, p.value);
        let policyState: PredicateItem['policyState'] = 'requested';
        if (denied.has(p.claim)) policyState = 'denied';
        else if (allowedDisclosureKey && k === allowedDisclosureKey) policyState = 'allowed';
        return {
            id,
            claim: p.claim,
            operation: p.operation,
            value: p.value,
            label: labels?.[p.claim],
            policyState,
        };
    });

    return {
        requestId: request.requestId,
        verifier: { id: request.verifierDid, displayName: verifierDisplayName },
        purpose: request.purpose,
        claims,
        predicates,
        policy: policy ? { id: policy.id, version: policy.version, hash: policy.hash } : undefined,
    };
}

/** Internal export used by tests. */
export const __test__ = { predicateKey, stableValue };
