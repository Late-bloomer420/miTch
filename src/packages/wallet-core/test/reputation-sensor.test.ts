import { describe, it, expect } from 'vitest';
import type { VerifierRequest } from '@askmi/shared-types';
import { ReputationSensor } from '../src/ReputationSensor';

const baseRequest = (overrides: Partial<VerifierRequest> = {}): VerifierRequest => ({
  verifierId: 'did:web:verifier.example',
  requestedClaims: [],
  requestedProvenClaims: [],
  ...overrides,
});

describe('ReputationSensor.generateReport', () => {
  it('flags over-requesting when dateOfBirth is asked without an age>=18 proof', () => {
    const report = ReputationSensor.generateReport(
      baseRequest({ requestedClaims: ['birthDate'] }),
      undefined,
      0
    );
    expect(report.metrics.overRequestingDetected).toBe(true);
    // 1.0 baseline - 0.4 over-requesting penalty
    expect(report.localPrivacyScore).toBeCloseTo(0.6);
  });

  it('does not flag over-requesting when age>=18 is proven via ZKP', () => {
    const report = ReputationSensor.generateReport(
      baseRequest({ requestedProvenClaims: ['age >= 18'] }),
      undefined,
      0
    );
    expect(report.metrics.overRequestingDetected).toBe(false);
    expect(report.metrics.zkpAccepted).toBe(true);
    expect(report.localPrivacyScore).toBeCloseTo(1.0);
  });

  it('applies tracker penalties at the >5 and >15 thresholds', () => {
    expect(
      ReputationSensor.generateReport(baseRequest(), undefined, 6).localPrivacyScore
    ).toBeCloseTo(0.8); // -0.2
    expect(
      ReputationSensor.generateReport(baseRequest(), undefined, 16).localPrivacyScore
    ).toBeCloseTo(0.5); // -0.2 -0.3
  });

  it('combines penalties and never drops below 0', () => {
    const report = ReputationSensor.generateReport(
      baseRequest({ requestedClaims: ['dateOfBirth'] }),
      undefined,
      16
    );
    // 1.0 - 0.4 - 0.2 - 0.3 = 0.1
    expect(report.localPrivacyScore).toBeCloseTo(0.1);
    expect(report.localPrivacyScore).toBeGreaterThanOrEqual(0);
  });

  it('counts both requested and proven claims and falls back to origin for the id', () => {
    const report = ReputationSensor.generateReport(
      baseRequest({
        verifierId: '',
        origin: 'https://shop.example',
        requestedClaims: ['name', 'email'],
        requestedProvenClaims: ['age >= 18'],
      }),
      undefined,
      0
    );
    expect(report.metrics.claimsRequestedCount).toBe(3);
    expect(report.verifierId).toBe('https://shop.example');
    expect(report.metrics.isTrustedIssuer).toBe(false);
  });

  it('evaluates nested multi-credential requirements', () => {
    const report = ReputationSensor.generateReport(
      baseRequest({
        requirements: [
          {
            credentialType: 'AgeCredential',
            requestedClaims: ['dateOfBirth'],
            requestedProvenClaims: [],
          },
          {
            credentialType: 'EmploymentCredential',
            requestedClaims: ['role'],
            requestedProvenClaims: ['isOver18'],
          },
        ],
      }),
      undefined,
      0
    );

    expect(report.metrics.claimsRequestedCount).toBe(3);
    expect(report.metrics.overRequestingDetected).toBe(false);
    expect(report.metrics.zkpAccepted).toBe(true);
  });
});
