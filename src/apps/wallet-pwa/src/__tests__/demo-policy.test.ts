import { describe, expect, it, vi } from 'vitest';
vi.mock('../runtime', () => ({
  isDemoRuntime: true,
  walletDatabaseName: 'askmi_demo_policy_test',
  holderDatabaseName: 'askmi_demo_holder_test',
}));
import { WalletService } from '../services/WalletService';
import { DEMO_POLICY } from '../data/DemoPolicy';
import { SecureStorage } from '@askmi/secure-storage';

describe('isolated Connect demo policy', () => {
  it('initializing and resetting the demo service preserves existing wallet credentials', async () => {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
    const existing = await SecureStorage.init(key);
    await existing.save(
      'existing-sentinel',
      { value: 'keep' },
      { issuer: 'test', type: ['Test'], claims: ['value'], issuedAt: '2026-11-13' }
    );
    const demo = new WalletService();
    await demo.initialize('test-pin', 'demo-policy-test');
    expect(
      (await demo.getCredentials()).some((credential) => credential.id === 'existing-sentinel')
    ).toBe(false);
    await demo.resetWallet();
    expect(await existing.load('existing-sentinel')).toEqual({ value: 'keep' });
  });
  it('requires consent for numeric age without changing the existing predicate policy', async () => {
    const wallet = new WalletService();
    await wallet.initialize('test-pin', 'demo-policy-test');
    const evaluate = (verifierId: string, requestedClaims: string[]) =>
      wallet.evaluateRequest(
        {
          verifierId,
          requestedClaims,
          requestedProvenClaims: [],
          origin: 'http://localhost:3104',
          nonce: crypto.randomUUID(),
        },
        { timestamp: Date.now(), userDID: 'did:example:test' }
      );
    expect((await evaluate('did:askmi:verifier-liquor-store', ['age'])).verdict).toBe('PROMPT');
    expect((await evaluate('did:askmi:verifier-liquor-store', ['age', 'birthDate'])).verdict).toBe(
      'DENY'
    );
    expect((await evaluate('did:example:unknown', ['age'])).verdict).toBe('DENY');
    expect(
      DEMO_POLICY.rules.find((rule) => rule.id === 'rule-age-proof-01')?.allowedClaims
    ).toEqual([]);
  });
});
