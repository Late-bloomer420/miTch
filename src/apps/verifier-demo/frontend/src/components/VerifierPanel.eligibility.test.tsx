import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { SCENARIOS } from '../data/scenarios';

vi.mock('react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react')>();
  return {
    ...actual,
    useState: (initial: unknown) => [
      initial === 'waiting'
        ? 'verified'
        : {
            status: 'VERIFIED',
            result: { eligible: true },
            disclosedClaims: null,
          },
      vi.fn(),
    ],
  };
});

import { VerifierPanel } from './VerifierPanel';

describe('verified numeric-age result', () => {
  it('renders eligibility and the actual disclosure boundary without proof-only or erasure claims', () => {
    const html = renderToStaticMarkup(
      <VerifierPanel
        scenario={SCENARIOS['liquor-store']}
        backendUrl="http://localhost:3004"
        sessionId="test"
        runNonce={1}
      />
    );
    expect(html).toContain('Age eligibility: confirmed (18+)');
    expect(html).toContain('received and checked numeric age');
    expect(html).not.toContain('proof only');
    expect(html).not.toContain('keys shredded');
    expect(html).not.toContain('age: 24');
  });
});
