export type EvidenceStatus = 'PASS' | 'FAIL' | 'ERROR' | 'RESIDUAL';
export type EvidenceCategory = 'stride' | 'fail-closed' | 'gdpr' | 'eudi-cir' | 'unlinkability';

export interface EvidenceClaim {
  id: string;
  claim: string;
  category: EvidenceCategory;
  pnpmFilter: string;   // e.g. '@askmi/policy-engine' (empty for residual)
  packageDir: string;   // repo-relative, e.g. 'src/packages/policy-engine' (empty for residual)
  testFile: string;     // package-relative, e.g. 'src/__tests__/x.test.ts' (empty for residual)
  testNamePattern?: string;
  residual?: { reason: string };
}

export interface EvidenceResult {
  id: string;
  claim: string;
  category: EvidenceCategory;
  status: EvidenceStatus;
  detail: string;
}

export interface ReportOptions {
  timestamp: Date;
  toolVersions?: Record<string, string>;
  sign?: (bytes: Uint8Array) => Promise<string>;
}
