import type { DecisionCapsule } from '@askmi/shared-types';

/**
 * API-02: the claim names a presentation may disclose.
 *
 * The policy engine's DecisionCapsule is the only authority for disclosure.
 * The verifier's request may ask for more; those extra claims are never
 * disclosed. The result is the union of `allowed_claims` over all authorized
 * requirements, intersected with what the verifier actually requested
 * (never disclose something nobody asked for).
 *
 * Fail-closed: a missing capsule, a DENY verdict or an empty intersection
 * returns an empty list, and the caller must not present.
 */
export function authorizedDisclosureClaims(
  capsule: Pick<DecisionCapsule, 'verdict' | 'authorized_requirements'> | null | undefined,
  requestedClaimNames: readonly string[]
): string[] {
  if (!capsule || (capsule.verdict !== 'ALLOW' && capsule.verdict !== 'PROMPT')) return [];
  const allowed = new Set(
    (capsule.authorized_requirements ?? []).flatMap((req) => req.allowed_claims ?? [])
  );
  const out: string[] = [];
  for (const name of requestedClaimNames) {
    if (allowed.has(name) && !out.includes(name)) out.push(name);
  }
  return out;
}
