import type { PolicyManifest } from '@askmi/shared-types';
import { ProtectionLayer } from '@askmi/layer-resolver';
import { DEMO_POLICY } from './DemoPolicy';

// The existing Connect contract discloses numeric age to its verifier. This
// explicit sandbox policy must never replace the existing predicate-only policy.
export const ISOLATED_DEMO_POLICY: PolicyManifest = {
  ...DEMO_POLICY,
  version: '1.4-demo-connect',
  trustedIssuers: [
    ...DEMO_POLICY.trustedIssuers,
    {
      did: 'did:web:localhost%3A3005',
      name: 'Local mock issuer (test only)',
      credentialTypes: ['AgeCredential'],
    },
  ],
  rules: DEMO_POLICY.rules.map((rule) =>
    rule.id === 'rule-age-proof-01'
      ? {
          ...rule,
          context: 'Demo Connect: disclose numeric age to the local verifier after consent',
          allowedClaims: ['age'],
          minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
          provenClaims: [],
          requiresUserConsent: true,
        }
      : rule
  ),
};
