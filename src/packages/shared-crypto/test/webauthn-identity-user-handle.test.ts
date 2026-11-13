import { afterEach, describe, expect, it, vi } from 'vitest';
import { WebAuthnService } from '../src/webauthn';

// An authenticator keeps one resident credential per RP ID and user handle. Wallets
// that share a hostname must be able to register under different handles.
async function userHandleSentBy(register: () => Promise<unknown>): Promise<string> {
  let options: PublicKeyCredentialCreationOptions | undefined;
  vi.stubGlobal('PublicKeyCredential', class {});
  vi.stubGlobal('navigator', {
    credentials: {
      get: vi.fn(),
      create: vi.fn(async (request: CredentialCreationOptions) => {
        options = request.publicKey;
        throw new Error('stop after capturing the request');
      }),
    },
  });
  await expect(register()).rejects.toThrow('stop after capturing the request');
  return new TextDecoder().decode(options!.user.id as ArrayBuffer);
}

describe('registerIdentityKey user handle', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('keeps the existing handle by default', async () => {
    expect(await userHandleSentBy(() => WebAuthnService.registerIdentityKey('localhost'))).toBe(
      'AskMI-identity-key-v1'
    );
  });

  it('registers under the handle the caller passes', async () => {
    expect(
      await userHandleSentBy(() =>
        WebAuthnService.registerIdentityKey('localhost', 'AskMI-demo-identity-key-v1')
      )
    ).toBe('AskMI-demo-identity-key-v1');
  });
});
