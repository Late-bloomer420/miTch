import { it, expect } from 'vitest';
import { writeFileSync } from 'node:fs';

it('passes with spaces', () => {
  if (process.env.EVIDENCE_FIXTURE_MARKER) {
    writeFileSync(process.env.EVIDENCE_FIXTURE_MARKER, 'executed');
  }
  expect(1).toBe(1);
});
