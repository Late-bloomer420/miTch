import type { Decision, DisclosureRequest, Policy } from './types';
import type { PolicyReasonCode } from './reasonCodes';

export interface DecisionCapsule {
  capsuleId: string;
  decisionId: string;
  policyId: string;
  policyVersion: string;
  requestId: string;
  verdict: 'ALLOW' | 'DENY' | 'PROMPT';
  responseMode: Decision['responseMode'];
  reasonCodes: PolicyReasonCode[];
  deniedClaims: string[];
  allowedDisclosureType?: 'predicate' | 'none';
  allowedPredicateId?: string;
  verifierRef: string;
  purpose: string;
  inputHash: string;
  policyHash: string;
  timestamp: string;
  rawClaimsStored: false;
  proofMaterialStored: false;
}

interface CreateDecisionCapsuleInput {
  decision: Decision;
  policy: Policy;
  request: DisclosureRequest;
  timestamp: string;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`).join(',')}}`;
}

function sha256Hex(data: string): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require('node:crypto') as typeof import('node:crypto');
  return createHash('sha256').update(data).digest('hex');
}

function hashRef(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}

function buildMinimizedRequestRepresentation(request: DisclosureRequest): Record<string, unknown> {
  return {
    requestId: request.requestId,
    purpose: request.purpose,
    requestedClaims: [...request.requestedClaims].sort(),
    requestedPredicates: request.requestedPredicates
      .map((predicate) => ({
        claim: predicate.claim,
        operation: predicate.operation,
        value: predicate.value,
      }))
      .sort((left, right) => stableStringify(left).localeCompare(stableStringify(right))),
    audienceRef: request.audience ? hashRef(request.audience) : undefined,
    verifierRef: hashRef(request.verifierDid),
    noncePresent: Boolean(request.nonce),
  };
}

function findAllowedPredicateId(decision: Decision, policy: Policy): string | undefined {
  const disclosure = decision.allowedDisclosure;
  if (!disclosure || disclosure.type !== 'predicate') {
    return undefined;
  }

  const match = policy.allowedPredicates.find((predicate) => {
    return (
      predicate.claim === disclosure.claim
      && predicate.operation === disclosure.operation
      && stableStringify(predicate.value) === stableStringify(disclosure.value)
    );
  });

  return match?.id;
}

export function createDecisionCapsule(input: CreateDecisionCapsuleInput): DecisionCapsule {
  const { decision, policy, request, timestamp } = input;

  const minimizedRequest = buildMinimizedRequestRepresentation(request);
  const inputHash = sha256Hex(stableStringify(minimizedRequest));
  const policyHash = sha256Hex(stableStringify(policy));
  const decisionId = sha256Hex(stableStringify({
    policyId: policy.id,
    requestId: request.requestId,
    verdict: decision.verdict,
    responseMode: decision.responseMode,
    reasonCodes: [...decision.reasonCodes].sort(),
    deniedClaims: [...decision.deniedClaims].sort(),
  }));

  const allowedPredicateId = findAllowedPredicateId(decision, policy);
  const allowedDisclosureType = decision.allowedDisclosure?.type === 'predicate' ? 'predicate' : 'none';

  const capsuleId = sha256Hex(stableStringify({
    decisionId,
    inputHash,
    policyHash,
    timestamp,
  }));

  return {
    capsuleId,
    decisionId,
    policyId: policy.id,
    policyVersion: policy.version,
    requestId: request.requestId,
    verdict: decision.verdict,
    responseMode: decision.responseMode,
    reasonCodes: [...decision.reasonCodes],
    deniedClaims: [...decision.deniedClaims],
    allowedDisclosureType,
    allowedPredicateId,
    verifierRef: hashRef(request.verifierDid),
    purpose: request.purpose,
    inputHash,
    policyHash,
    timestamp,
    rawClaimsStored: false,
    proofMaterialStored: false,
  };
}
