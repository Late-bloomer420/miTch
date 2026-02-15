import { KeyProtectionLevel } from './types/KeyProtectionLevel';
import type { KeyGuardian, KeyCreationResult } from './interfaces/KeyGuardian';

export class SoftwareKeyGuardian implements KeyGuardian {
  private keys = new Map<string, CryptoKeyPair>();

  async getLevel(): Promise<KeyProtectionLevel> {
    return KeyProtectionLevel.SOFTWARE_EPHEMERAL;
  }

  async createKey(opts: { userId: string }): Promise<KeyCreationResult> {
    // Generate an ECDSA P-256 keypair, keep private in-memory only
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, // private key non-extractable
      ['sign', 'verify']
    );

    const keyId = `kg-${opts.userId}-${Date.now()}`;
    this.keys.set(keyId, keyPair);

    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    return {
      level: KeyProtectionLevel.SOFTWARE_EPHEMERAL,
      publicKeyJwk,
      keyId,
    };
  }

  async sign(opts: { keyId: string; challenge: Uint8Array }): Promise<Uint8Array> {
    const keyPair = this.keys.get(opts.keyId);
    if (!keyPair) {
      throw new Error(`Key not found: ${opts.keyId}`);
    }

    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      opts.challenge
    );
    return new Uint8Array(sig);
  }
}

export default SoftwareKeyGuardian;
