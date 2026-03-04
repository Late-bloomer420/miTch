import { describe, it, expect } from 'vitest';
import { DenyReasonCode } from '../deny-reason-codes';
import { negotiateCapabilities, type CapabilityFlags } from '../capability-negotiation';

const secureCaps: CapabilityFlags = {
  layer0: true,
  layer1: true,
  'revocation-online': true,
  'revocation-offline': false,
  'replay-protection': true,
  'step-up': true,
};

describe('Capability negotiation v1', () => {
  it('DENY: older verifier and newer wallet major version mismatch', () => {
    const result = negotiateCapabilities({
      wallet: { protocolVersion: '2.0.0', capabilities: secureCaps },
      verifier: { protocolVersion: '1.3.0', capabilities: secureCaps },
    });

    expect(result.verdict).toBe('DENY');
    expect(result.reasonCode).toBe(DenyReasonCode.POLICY_UNSUPPORTED_VERSION);
  });

  it('DENY: security-critical flag mismatch', () => {
    const result = negotiateCapabilities({
      wallet: { protocolVersion: '1.0.0', capabilities: secureCaps },
      verifier: {
        protocolVersion: '1.0.0',
        capabilities: { ...secureCaps, 'replay-protection': false },
      },
    });

    expect(result.verdict).toBe('DENY');
    expect(result.reasonCode).toBe(DenyReasonCode.POLICY_MISMATCH);
  });

  it('DENY: unsafe downgrade attempt is rejected and reason code is emitted', () => {
    const result = negotiateCapabilities({
      wallet: { protocolVersion: '1.0.0', capabilities: secureCaps },
      verifier: { protocolVersion: '1.0.0', capabilities: secureCaps },
      requestedProfile: { 'replay-protection': false },
    });

    expect(result.verdict).toBe('DENY');
    expect(result.reasonCode).toBe(DenyReasonCode.DOWNGRADE_ATTACK);
  });
});
