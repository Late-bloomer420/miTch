import { expect, it } from 'vitest';
import { BrowserIndexedDBAdapter, SecureStorage } from '../src/index';

it('demo issuance and reset leave the default wallet intact, even on the same origin', async () => {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const existing = await SecureStorage.init(key);
  const demoAdapter = new BrowserIndexedDBAdapter('askmi_demo_wallet_v1');
  const demo = await SecureStorage.init(key, demoAdapter);
  const metadata = { issuer: 'test', type: ['Test'], claims: ['value'], issuedAt: '2026-11-13' };
  await existing.save('isolation-sentinel', { value: 'existing' }, metadata);
  expect(await demo.load('isolation-sentinel')).toBeNull();
  await demo.save('isolation-sentinel', { value: 'demo' }, metadata);
  expect(await existing.load('isolation-sentinel')).toEqual({ value: 'existing' });
  await demoAdapter.clear();
  expect(await existing.load('isolation-sentinel')).toEqual({ value: 'existing' });
  const freshDemo = await SecureStorage.init(
    key,
    new BrowserIndexedDBAdapter('askmi_demo_wallet_v1')
  );
  expect(await freshDemo.load('isolation-sentinel')).toBeNull();
});
