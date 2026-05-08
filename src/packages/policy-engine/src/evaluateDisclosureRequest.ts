import { REASON_CODES, type PolicyReasonCode } from './reasonCodes';
import type { Decision, DisclosureRequest, Policy } from './types';

function buildDecision(
  request: DisclosureRequest,
  policy: Policy,
  verdict: Decision['verdict'],
  responseMode: Decision['responseMode'],
  reasonCodes: PolicyReasonCode[],
  deniedClaims: string[],
  allowedDisclosure?: Decision['allowedDisclosure']
): Decision {
  return {
    verdict,
    responseMode,
    policyId: policy.id,
    requestId: request.requestId,
    allowedDisclosure,
    deniedClaims,
    reasonCodes,
    rawClaimsDisclosed: false,
  };
}

function matchesVerifierPattern(verifierDid: string, verifierPattern: string): boolean {
  if (verifierDid === verifierPattern) {
    return true;
  }

  if (!verifierPattern.includes('*')) {
    return false;
  }

  const wildcardToken = '*';
  const wildcardIndex = verifierPattern.indexOf(wildcardToken);
  if (wildcardIndex === -1) {
    return false;
  }

  const prefix = verifierPattern.slice(0, wildcardIndex);
  const suffix = verifierPattern.slice(wildcardIndex + wildcardToken.length);

  if (!verifierDid.startsWith(prefix) || !verifierDid.endsWith(suffix)) {
    return false;
  }

  const middle = verifierDid.slice(prefix.length, verifierDid.length - suffix.length);
  return middle.length > 0 && !middle.includes('.');
}

export function evaluateDisclosureRequest(request: DisclosureRequest, policy: Policy): Decision {
  if (request.purpose !== policy.scope.purpose) {
    return buildDecision(request, policy, 'DENY', 'NONE', [REASON_CODES.PURPOSE_MISMATCH, REASON_CODES.FAIL_CLOSED], []);
  }

  if (!matchesVerifierPattern(request.verifierDid, policy.scope.verifierPattern)) {
    return buildDecision(request, policy, 'DENY', 'NONE', [REASON_CODES.VERIFIER_PATTERN_MISMATCH, REASON_CODES.FAIL_CLOSED], []);
  }

  if (policy.linkabilityControls.nonceRequired && !request.nonce) {
    return buildDecision(request, policy, 'DENY', 'NONE', [REASON_CODES.NONCE_REQUIRED, REASON_CODES.FAIL_CLOSED], []);
  }

  if (policy.linkabilityControls.audienceBindingRequired && !request.audience) {
    return buildDecision(
      request,
      policy,
      'DENY',
      'NONE',
      [REASON_CODES.AUDIENCE_BINDING_REQUIRED, REASON_CODES.FAIL_CLOSED],
      []
    );
  }

  const reasonCodes: PolicyReasonCode[] = [REASON_CODES.PURPOSE_VALID, REASON_CODES.VERIFIER_PATTERN_MATCHED];
  const deniedClaims = request.requestedClaims.filter((claim) => policy.deniedClaims.some((denied) => denied.claim === claim));

  if (deniedClaims.length > 0) {
    reasonCodes.push(REASON_CODES.RAW_ATTRIBUTE_NOT_PROPORTIONAL);
  }

  const matchingPredicate = request.requestedPredicates.find((requested) =>
    policy.allowedPredicates.some(
      (allowed) =>
        allowed.claim === requested.claim &&
        allowed.operation === requested.operation &&
        allowed.value === requested.value &&
        allowed.responseMode === 'PREDICATE_PROOF'
    )
  );

  if (!matchingPredicate && deniedClaims.length > 0 && policy.allowedClaims.length === 0) {
    return buildDecision(
      request,
      policy,
      'DENY',
      'NONE',
      [...reasonCodes, REASON_CODES.NO_ALLOWED_DISCLOSURE_PATH, REASON_CODES.FAIL_CLOSED],
      deniedClaims
    );
  }

  if (!matchingPredicate && policy.allowedClaims.length === 0) {
    return buildDecision(
      request,
      policy,
      'DENY',
      'NONE',
      [...reasonCodes, REASON_CODES.NO_ALLOWED_DISCLOSURE_PATH, REASON_CODES.FAIL_CLOSED],
      deniedClaims
    );
  }

  const allowedDisclosure = matchingPredicate
    ? {
        type: 'predicate' as const,
        claim: matchingPredicate.claim,
        operation: matchingPredicate.operation,
        value: matchingPredicate.value,
      }
    : undefined;

  if (policy.defaults.requiresUserConsent || policy.defaults.requiresPresence) {
    const promptReasons: PolicyReasonCode[] = [...reasonCodes, REASON_CODES.MINIMAL_DISCLOSURE_REQUIRED];
    if (policy.defaults.requiresUserConsent) {
      promptReasons.push(REASON_CODES.USER_CONSENT_REQUIRED);
    }
    if (policy.defaults.requiresPresence) {
      promptReasons.push(REASON_CODES.PRESENCE_REQUIRED);
    }

    return buildDecision(request, policy, 'PROMPT', matchingPredicate ? 'PREDICATE_PROOF' : 'NONE', promptReasons, deniedClaims, allowedDisclosure);
  }

  return buildDecision(request, policy, 'ALLOW', matchingPredicate ? 'PREDICATE_PROOF' : 'NONE', reasonCodes, deniedClaims, allowedDisclosure);
}

export { matchesVerifierPattern };
