import { describe, it, expect } from 'vitest';
import { PersonalDataVault } from '../vault/PersonalDataVault';

describe('PersonalDataVault', () => {
    it('returns age for known user', () => {
        const vault = new PersonalDataVault();
        expect(vault.retrieveDataByCategory('user_001', 'age')).toBe(27);
    });

    it('returns email for known user', () => {
        const vault = new PersonalDataVault();
        expect(vault.retrieveDataByCategory('user_001', 'email')).toBe('user@example.local');
    });

    it('returns null for unknown user', () => {
        const vault = new PersonalDataVault();
        expect(vault.retrieveDataByCategory('nonexistent', 'age')).toBeNull();
    });

    it('returns null for unknown category', () => {
        const vault = new PersonalDataVault();
        expect(vault.retrieveDataByCategory('user_001', 'ssn')).toBeNull();
    });

    it('getUserDataSummary shows present categories', () => {
        const vault = new PersonalDataVault();
        const summary = vault.getUserDataSummary('user_001');
        expect(summary).toHaveLength(2);
        expect(summary.every(s => s.present)).toBe(true);
    });

    it('getUserDataSummary returns empty for unknown user', () => {
        const vault = new PersonalDataVault();
        expect(vault.getUserDataSummary('ghost')).toHaveLength(0);
    });
});
