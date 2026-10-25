import type { AuthorizationRequest } from '@askmi/oid4vp';
import { ASKMI_SCENARIO_VCT } from '@askmi/shared-types';

const AGE_VCT = ASKMI_SCENARIO_VCT['liquor-store'];

export function ageRequest(bindings: {
  verifierDid: string;
  audience: string;
  nonce: string;
  sessionId: string;
}): AuthorizationRequest {
  return {
    response_type: 'vp_token',
    client_id: bindings.verifierDid,
    redirect_uri: bindings.audience,
    nonce: bindings.nonce,
    state: bindings.sessionId,
    response_mode: 'direct_post',
    presentation_definition: {
      id: 'askmi-connect',
      name: 'Age eligibility',
      input_descriptors: [
        {
          id: 'age-credential',
          constraints: {
            limit_disclosure: 'required',
            fields: [{ path: ['$.age'], filter: { type: 'number', minimum: 18 } }],
          },
        },
      ],
    },
  };
}

export function matchesSubmission(submission: unknown, request: AuthorizationRequest): boolean {
  if (!submission || typeof submission !== 'object') return false;
  const value = submission as Record<string, unknown>;
  if (
    value.definition_id !== request.presentation_definition.id ||
    !Array.isArray(value.descriptor_map) ||
    value.descriptor_map.length !== 1
  )
    return false;
  const descriptor = value.descriptor_map[0];
  return (
    descriptor?.id === 'age-credential' &&
    descriptor.format === 'sd-jwt' &&
    descriptor.path === '$' &&
    descriptor.path_nested === undefined
  );
}

/** Call after cryptographic validation; this checks the authenticated issuer payload. */
export function matchesCredentialType(vpToken: string): boolean {
  try {
    const segment = vpToken.split('~')[0].split('.')[1];
    const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')));
    return payload.vct === AGE_VCT;
  } catch {
    return false;
  }
}
