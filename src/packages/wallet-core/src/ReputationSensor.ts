import type { VerifierRequest, VerifierReportCard, DecisionCapsule } from '@askmi/shared-types';

/**
 * ReputationSensor: Evaluates verifier behavior and generates anonymous report cards.
 * This is the VRN watchdog component for Epic 3.
 */
export class ReputationSensor {
  private static normalizeClaim(claim: string): string {
    return claim.toLowerCase().replace(/[\s_-]/g, '');
  }

  private static collectRequestedClaims(request: VerifierRequest): string[] {
    const fromRequirements =
      request.requirements?.flatMap((requirement) => requirement.requestedClaims) ?? [];
    return [...(request.requestedClaims ?? []), ...fromRequirements];
  }

  private static collectProvenClaims(
    request: VerifierRequest,
    capsule?: DecisionCapsule
  ): string[] {
    const requestProofs = request.requestedProvenClaims ?? [];
    const requirementProofs =
      request.requirements?.flatMap((requirement) => requirement.requestedProvenClaims ?? []) ?? [];
    const capsuleProofs =
      capsule?.authorized_requirements?.flatMap((requirement) => requirement.proven_claims ?? []) ??
      [];
    return [...requestProofs, ...requirementProofs, ...capsuleProofs];
  }

  /**
   * Generates a reputation report based on an interaction.
   */
  static generateReport(
    request: VerifierRequest,
    capsule: DecisionCapsule | undefined,
    trackersDetected: number
  ): VerifierReportCard {
    // 1. Detect Over-Requesting (Heuristic)
    // e.g. asking for birthDate/dateOfBirth while an age predicate would do.
    const requested = ReputationSensor.collectRequestedClaims(request);
    const proven = ReputationSensor.collectProvenClaims(request, capsule);
    const normalizedRequested = requested.map(ReputationSensor.normalizeClaim);
    const normalizedProven = proven.map(ReputationSensor.normalizeClaim);

    const requestsBirthDate = normalizedRequested.some((claim) =>
      ['birthdate', 'dateofbirth', 'dob'].includes(claim)
    );
    const acceptsAgeProof = normalizedProven.some(
      (claim) =>
        claim.includes('age>=18') || claim.includes('ageover18') || claim.includes('isover18')
    );
    const overRequestingDetected = requestsBirthDate && !acceptsAgeProof;

    // 2. Calculate Local Privacy Score
    let score = 1.0;
    if (trackersDetected > 5) score -= 0.2;
    if (trackersDetected > 15) score -= 0.3;
    if (overRequestingDetected) score -= 0.4;

    const verifierId = request.verifierId || request.origin || 'Unknown';

    return {
      verifierId,
      timestamp: new Date().toISOString(),
      metrics: {
        claimsRequestedCount: requested.length + proven.length,
        zkpAccepted: proven.length > 0,
        trackerCount: trackersDetected,
        overRequestingDetected,
        isTrustedIssuer: false, // Placeholder for TSL check
      },
      localPrivacyScore: Math.max(0, score),
    };
  }
}
