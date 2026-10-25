import type { EvidenceCategory, EvidenceClaim } from './types';

const CATEGORIES: EvidenceCategory[] = ['stride', 'fail-closed', 'gdpr', 'eudi-cir', 'unlinkability'];

export function validateManifest(claims: EvidenceClaim[]): void {
  const seen = new Set<string>();
  for (const c of claims) {
    if (!c.id) throw new Error('manifest: claim missing id');
    if (seen.has(c.id)) throw new Error(`manifest: duplicate id ${c.id}`);
    seen.add(c.id);
    if (!c.claim) throw new Error(`manifest: ${c.id} missing claim text`);
    if (!CATEGORIES.includes(c.category)) throw new Error(`manifest: ${c.id} unknown category ${c.category}`);
    if (c.residual) continue; // residual claims intentionally have empty test fields
    if (!c.pnpmFilter) throw new Error(`manifest: ${c.id} missing pnpmFilter`);
    if (!c.packageDir) throw new Error(`manifest: ${c.id} missing packageDir`);
    if (!c.testFile) throw new Error(`manifest: ${c.id} missing testFile`);
  }
}

export const EVIDENCE_CLAIMS: EvidenceClaim[] = [
  // — SECURE-1 fail-closed fixes —
  { id: 'SECURE1-F03', claim: 'WebAuthn verifyPresence stub fails closed (no false presence proof)', category: 'fail-closed',
    pnpmFilter: '@askmi/shared-crypto', packageDir: 'src/packages/shared-crypto', testFile: 'test/webauthn-fail-closed.test.ts' },
  { id: 'SECURE1-F04', claim: 'Geo-scope denies on undetermined country / unknown scope (fail-closed)', category: 'fail-closed',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/ehds-geo-scope.test.ts' },
  { id: 'SECURE1-F16-18', claim: 'Passkey/identity-key metadata save failures fail closed (rethrow)', category: 'fail-closed',
    pnpmFilter: '@askmi/shared-crypto', packageDir: 'src/packages/shared-crypto', testFile: 'test/webauthn-save-failclosed.test.ts' },
  { id: 'SECURE1-F14', claim: 'OID4VP verifier cryptographically verifies SD-JWT VC + KB-JWT (fail-closed)', category: 'fail-closed',
    pnpmFilter: '@askmi/oid4vp-verifier', packageDir: 'src/packages/oid4vp-verifier', testFile: 'src/__tests__/response-verifier.crypto.test.ts' },
  { id: 'SECURE1-GAP3', claim: 'Anti-oracle DENY-path timing variance bounded (no secret-dependent branch)', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/anti-oracle.test.ts' },
  // — Core STRIDE controls (ADR-009, existing tests) —
  { id: 'STRIDE-T1', claim: 'Claim-name injection rejected (whitelist input validation)', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/input-validation.test.ts' },
  { id: 'STRIDE-T2', claim: 'Unsafe capability downgrade denied', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/capability-negotiation.test.ts' },
  { id: 'STRIDE-T5', claim: 'Audit-chain tampering detected (hash chain + signatures)', category: 'stride',
    pnpmFilter: '@askmi/audit-log', packageDir: 'src/packages/audit-log', testFile: 'test/adversarial_audit.test.ts' },
  { id: 'STRIDE-I2', claim: 'Cross-verifier correlation prevented (pairwise-ephemeral DIDs)', category: 'unlinkability',
    pnpmFilter: '@askmi/shared-crypto', packageDir: 'src/packages/shared-crypto', testFile: 'test/unlinkability.test.ts' },
  { id: 'STRIDE-I1', claim: 'Anti-oracle: verifier cannot distinguish deny reasons (≤4 buckets)', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/anti-oracle.test.ts' },
  // — Residuals (intentionally NOT proven by a test) —
  { id: 'GAP-1', claim: 'Physical RAM wipe unattainable in browser JS/V8 (TEE deferred)', category: 'fail-closed',
    pnpmFilter: '', packageDir: '', testFile: '', residual: { reason: 'Browser runtime limit; TEE integration deferred (ADR-010).' } },
  { id: 'GAP-4', claim: 'External security review not yet performed', category: 'fail-closed',
    pnpmFilter: '', packageDir: '', testFile: '', residual: { reason: 'Human precondition; this pack prepares for it (SECURE-2), not the review itself.' } },
];
