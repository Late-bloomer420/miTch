import type { AuthorizationRequest, PresentationDefinition } from '@askmi/oid4vp';
import { ASKMI_SCENARIO_VCT } from '@askmi/shared-types';

/**
 * Identifiers of the active verifier profiles. The application receives one of
 * these with an eligibility result, never the underlying claim value.
 */
export type ActiveProfileId = 'askmi-numeric-age-v0' | 'askmi-age-over-18-exploration-v0';

/**
 * Profile C (docs/tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md): an issuer-signed
 * flat `age_over_18: true` SD-JWT claim under a repository-owned VCT.
 *
 * NOT an official EUDI / EU Age Verification profile, not a ZK proof and not an
 * unlinkability guarantee. Exists to fix the verifier's application contract and
 * its negatives before an official profile (#97) is selected.
 */
export const AGE_OVER_18_EXPLORATION = {
  scenarioId: 'age-over-18-exploration',
  profileId: 'askmi-age-over-18-exploration-v0' as const,
  definitionId: 'pd-askmi-age-over-18-exploration',
  descriptorId: 'age-over-18-credential',
  vct: 'https://askmi.demo/vct/age-over-18-exploration',
  claim: 'age_over_18',
};

export const AGE_OVER_18_EXPLORATION_DEFINITION: PresentationDefinition = {
  id: AGE_OVER_18_EXPLORATION.definitionId,
  name: 'Age over 18 (AskMI exploration profile, not EUDI)',
  purpose: 'Verify an issuer-signed statement that the holder is at least 18 years old',
  input_descriptors: [
    {
      id: AGE_OVER_18_EXPLORATION.descriptorId,
      name: 'Age over 18',
      purpose: 'Issuer-signed age_over_18 boolean',
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: [`$.${AGE_OVER_18_EXPLORATION.claim}`],
            filter: { type: 'boolean', const: true },
          },
        ],
      },
    },
  ],
};

interface ProfileSpec {
  id: ActiveProfileId;
  definitionId: string;
  descriptorId: string;
  vct: string;
  claim: string;
  accepts: (value: unknown) => boolean;
}

const PROFILES: readonly ProfileSpec[] = [
  {
    id: 'askmi-numeric-age-v0',
    definitionId: 'pd-age-verification',
    descriptorId: 'age-credential',
    vct: ASKMI_SCENARIO_VCT['liquor-store'],
    claim: 'age',
    accepts: (v) => typeof v === 'number' && Number.isFinite(v) && v >= 18,
  },
  {
    id: AGE_OVER_18_EXPLORATION.profileId,
    definitionId: AGE_OVER_18_EXPLORATION.definitionId,
    descriptorId: AGE_OVER_18_EXPLORATION.descriptorId,
    vct: AGE_OVER_18_EXPLORATION.vct,
    claim: AGE_OVER_18_EXPLORATION.claim,
    // Strict: the JSON boolean true only. "true", 1 and false are rejected.
    accepts: (v) => v === true,
  },
];

/**
 * Returns the matching active profile, or null (fail closed).
 * Call only after issuer signature, disclosures and holder binding have passed.
 * The profile is selected by the verifier's own stored request, never by the wallet.
 */
export function matchActiveProfile(
  request: AuthorizationRequest,
  submission: unknown,
  verifiedIssuerJwt: string,
  claims: Record<string, unknown>
): ActiveProfileId | null {
  const spec = PROFILES.find((p) => p.definitionId === request.presentation_definition.id);
  if (!spec) return null;
  if (!submission || typeof submission !== 'object') return null;
  const candidate = submission as Record<string, unknown>;
  if (candidate.definition_id !== spec.definitionId) return null;
  if (!Array.isArray(candidate.descriptor_map) || candidate.descriptor_map.length !== 1)
    return null;
  const descriptor = candidate.descriptor_map[0];
  if (
    !descriptor ||
    descriptor.id !== spec.descriptorId ||
    descriptor.format !== 'sd-jwt' ||
    descriptor.path !== '$' ||
    descriptor.path_nested !== undefined
  )
    return null;
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(verifiedIssuerJwt.split('.')[1], 'base64url').toString());
  } catch {
    return null;
  }
  if (payload.vct !== spec.vct) return null;
  const keys = Object.keys(claims);
  if (keys.length !== 1 || keys[0] !== spec.claim) return null;
  return spec.accepts(claims[spec.claim]) ? spec.id : null;
}
