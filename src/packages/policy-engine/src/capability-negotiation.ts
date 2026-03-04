import { DenyReasonCode } from './deny-reason-codes';

export type CapabilityVerdict = 'ALLOW' | 'DENY' | 'PROMPT';

export interface CapabilityFlags {
  layer0: boolean;
  layer1: boolean;
  'revocation-online': boolean;
  'revocation-offline': boolean;
  'replay-protection': boolean;
  'step-up': boolean;
}

export interface CapabilityHandshake {
  protocolVersion: string;
  capabilities: CapabilityFlags;
}

export interface CapabilityNegotiationInput {
  wallet: CapabilityHandshake;
  verifier: CapabilityHandshake;
  requestedProfile?: Partial<CapabilityFlags>;
}

export interface CapabilityNegotiationResult {
  verdict: CapabilityVerdict;
  reasonCode?: DenyReasonCode;
  agreedCapabilities?: CapabilityFlags;
}

const SECURITY_CRITICAL_FLAGS: Array<keyof CapabilityFlags> = ['layer0', 'revocation-online', 'replay-protection'];

function parseMajor(version: string): number {
  const major = Number(version.split('.')[0]);
  return Number.isFinite(major) ? major : -1;
}

export function negotiateCapabilities(input: CapabilityNegotiationInput): CapabilityNegotiationResult {
  const walletMajor = parseMajor(input.wallet.protocolVersion);
  const verifierMajor = parseMajor(input.verifier.protocolVersion);

  if (walletMajor < 0 || verifierMajor < 0) {
    return { verdict: 'DENY', reasonCode: DenyReasonCode.POLICY_MISMATCH };
  }

  if (walletMajor !== verifierMajor) {
    return { verdict: 'DENY', reasonCode: DenyReasonCode.POLICY_UNSUPPORTED_VERSION };
  }

  for (const flag of SECURITY_CRITICAL_FLAGS) {
    if (!input.wallet.capabilities[flag] || !input.verifier.capabilities[flag]) {
      return { verdict: 'DENY', reasonCode: DenyReasonCode.POLICY_MISMATCH };
    }
  }

  if (input.requestedProfile) {
    for (const [flag, value] of Object.entries(input.requestedProfile) as Array<[keyof CapabilityFlags, boolean]>) {
      if (!value && input.wallet.capabilities[flag] && input.verifier.capabilities[flag]) {
        return { verdict: 'DENY', reasonCode: DenyReasonCode.DOWNGRADE_ATTACK };
      }
    }
  }

  return {
    verdict: 'ALLOW',
    agreedCapabilities: {
      layer0: input.wallet.capabilities.layer0 && input.verifier.capabilities.layer0,
      layer1: input.wallet.capabilities.layer1 && input.verifier.capabilities.layer1,
      'revocation-online': input.wallet.capabilities['revocation-online'] && input.verifier.capabilities['revocation-online'],
      'revocation-offline': input.wallet.capabilities['revocation-offline'] && input.verifier.capabilities['revocation-offline'],
      'replay-protection': input.wallet.capabilities['replay-protection'] && input.verifier.capabilities['replay-protection'],
      'step-up': input.wallet.capabilities['step-up'] && input.verifier.capabilities['step-up'],
    },
  };
}
