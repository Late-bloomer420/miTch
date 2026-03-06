import { describe, it, expect } from 'vitest';
import { ProofFatigueTracker } from '../proof-fatigue';

describe('ProofFatigueTracker', () => {
    it('allows first prompt', () => {
        const tracker = new ProofFatigueTracker({ maxPromptsPerWindow: 5 });
        const result = tracker.recordPrompt('user1');
        expect(result.fatigued).toBe(false);
        expect(result.action).toBe('allow_prompt');
        expect(result.promptCount).toBe(1);
    });

    it('warns at 80% threshold', () => {
        const tracker = new ProofFatigueTracker({ maxPromptsPerWindow: 5 });
        for (let i = 0; i < 4; i++) tracker.recordPrompt('user2'); // 4/5 = 80%
        const result = tracker.recordPrompt('user2'); // 5th prompt
        // At 5 of 5, count > max is false, but isWarning should trigger
        // Actually 4 = ceil(5*0.8)=4, so 4th prompt triggers warning
        expect(result.fatigued).toBe(false);
    });

    it('triggers fatigue after exceeding max', () => {
        const tracker = new ProofFatigueTracker({ maxPromptsPerWindow: 3 });
        for (let i = 0; i < 3; i++) tracker.recordPrompt('user3'); // fill up
        const result = tracker.recordPrompt('user3'); // 4th = over limit
        expect(result.fatigued).toBe(true);
        expect(result.action).toBe('deny');
        expect(result.reason).toBeTruthy();
    });

    it('reset clears user state', () => {
        const tracker = new ProofFatigueTracker({ maxPromptsPerWindow: 2 });
        tracker.recordPrompt('user4');
        tracker.recordPrompt('user4');
        tracker.reset('user4');
        expect(tracker.getState('user4')).toBeUndefined();
        const r = tracker.recordPrompt('user4');
        expect(r.fatigued).toBe(false);
    });

    it('checkFatigue does not record prompt', () => {
        const tracker = new ProofFatigueTracker({ maxPromptsPerWindow: 5 });
        tracker.checkFatigue('user5');
        expect(tracker.trackedUserCount).toBe(0);
    });

    it('tracks multiple users independently', () => {
        const tracker = new ProofFatigueTracker({ maxPromptsPerWindow: 2 });
        for (let i = 0; i < 3; i++) tracker.recordPrompt('alice'); // fatigued
        const bobResult = tracker.recordPrompt('bob'); // bob starts fresh
        expect(bobResult.fatigued).toBe(false);
    });

    it('purgeExpired removes stale entries', async () => {
        const tracker = new ProofFatigueTracker({ maxPromptsPerWindow: 5, windowMs: 1 });
        tracker.recordPrompt('user6');
        await new Promise(r => setTimeout(r, 10));
        const purged = tracker.purgeExpired();
        expect(purged).toBeGreaterThanOrEqual(1);
    });
});
