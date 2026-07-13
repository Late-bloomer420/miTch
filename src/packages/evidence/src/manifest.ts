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

// Seeded in Task 5 with the real SECURE-1 + STRIDE + residual claims.
export const EVIDENCE_CLAIMS: EvidenceClaim[] = [];
