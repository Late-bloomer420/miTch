import { describe, it, expect } from 'vitest';
const describeWhenSpawned = process.env.ASKMI_EVIDENCE_FIXTURE_RUN === '1' ? describe : describe.skip;
describeWhenSpawned('fixture', () => { it('passes', () => { expect(1).toBe(1); }); });
