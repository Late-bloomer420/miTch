import type { AuthorizationRequest } from '@askmi/oid4vp';
import { ASKMI_SCENARIO_VCT } from '@askmi/shared-types';

/** Bounded numeric-age profile, not a general Presentation Exchange evaluator. */
export function acceptsActiveProfile(
  request: AuthorizationRequest,
  submission: unknown,
  verifiedIssuerJwt: string,
  claims: Record<string, unknown>
): boolean {
  if (request.presentation_definition.id !== 'pd-age-verification') return false;
  if (!submission || typeof submission !== 'object') return false;
  const candidate = submission as Record<string, unknown>;
  if (candidate.definition_id !== request.presentation_definition.id) return false;
  if (!Array.isArray(candidate.descriptor_map) || candidate.descriptor_map.length !== 1)
    return false;
  const descriptor = candidate.descriptor_map[0];
  if (
    !descriptor ||
    descriptor.id !== 'age-credential' ||
    descriptor.format !== 'sd-jwt' ||
    descriptor.path !== '$' ||
    descriptor.path_nested !== undefined
  )
    return false;
  // Call only after issuer signature, disclosures and holder binding have passed.
  const payload = JSON.parse(Buffer.from(verifiedIssuerJwt.split('.')[1], 'base64url').toString());
  if (payload.vct !== ASKMI_SCENARIO_VCT['liquor-store']) return false;
  const keys = Object.keys(claims);
  return (
    keys.length === 1 &&
    keys[0] === 'age' &&
    typeof claims.age === 'number' &&
    Number.isFinite(claims.age) &&
    claims.age >= 18
  );
}
