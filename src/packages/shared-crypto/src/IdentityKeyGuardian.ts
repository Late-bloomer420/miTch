import { KeyProtectionLevel } from './types/KeyProtectionLevel';
import { SoftwareKeyGuardian } from './SoftwareKeyGuardian';
import { WebAuthnService } from './webauthn';
import type { KeyCreationResult, KeyGuardian, EncryptionKeyCreationResult } from './interfaces/KeyGuardian';

export type IdentityAttestationMethod = 'webauthn' | 'software-fallback';
export type IdentityAttestationEncoding = 'base64' | 'hex';

export interface IdentitySignatureResult {
  signature: string;
  level: KeyProtectionLevel;
  method: IdentityAttestationMethod;
  encoding: IdentityAttestationEncoding;
}

const DEFAULT_SOFTWARE_KEY_ID = 'askmi-wallet-software-identity-v1';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function textBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * IdentityKeyGuardian is the concrete runtime bridge between the WalletService
 * and the strongest identity key available on this device.
 *
 * Rule: when WebAuthn is available, a missing passkey is a hard failure. The
 * software key exists only for Node/test/legacy runtimes where no WebAuthn
 * ceremony can run at all.
 */
export class IdentityKeyGuardian implements KeyGuardian {
  private readonly software = new SoftwareKeyGuardian();
  private softwareKeyId: string | null = null;
  private softwarePublicKeyJwk: JsonWebKey | null = null;

  async isHardwareAvailable(): Promise<boolean> {
    return WebAuthnService.isAvailable();
  }

  async getLevel(): Promise<KeyProtectionLevel> {
    if (await WebAuthnService.isIdentityRegistered()) {
      return KeyProtectionLevel.HARDWARE_BOUND;
    }
    return KeyProtectionLevel.SOFTWARE_EPHEMERAL;
  }

  async createKey(opts: { userId: string }): Promise<KeyCreationResult> {
    if (await this.isHardwareAvailable()) {
      const registration = await WebAuthnService.registerIdentityKey();
      return {
        level: KeyProtectionLevel.HARDWARE_BOUND,
        publicKeyJwk: registration.publicKeyJwk ?? {
          kty: 'EC',
          crv: 'P-256',
          x: '',
          y: '',
          alg: 'ES256',
          ext: true,
        },
        keyId: opts.userId,
        credentialId: registration.credentialId,
      };
    }

    const created = await this.software.createKey({ userId: opts.userId });
    this.softwareKeyId = created.keyId;
    this.softwarePublicKeyJwk = created.publicKeyJwk;
    return created;
  }

  async ensureSoftwareKey(userId: string = DEFAULT_SOFTWARE_KEY_ID): Promise<JsonWebKey> {
    if (!this.softwareKeyId || !this.softwarePublicKeyJwk) {
      const created = await this.software.createKey({ userId });
      this.softwareKeyId = created.keyId;
      this.softwarePublicKeyJwk = created.publicKeyJwk;
    }
    return this.softwarePublicKeyJwk;
  }

  async sign(opts: { keyId: string; challenge: Uint8Array }): Promise<Uint8Array> {
    if (await WebAuthnService.isIdentityRegistered()) {
      const signature = await WebAuthnService.signWithIdentityKey(new TextDecoder().decode(opts.challenge));
      return Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
    }

    if (await this.isHardwareAvailable()) {
      throw new Error(
        'HARDWARE_IDENTITY_REQUIRED: WebAuthn is available, but no hardware identity key is registered.'
      );
    }

    await this.ensureSoftwareKey();
    return this.software.sign({ keyId: this.softwareKeyId!, challenge: opts.challenge });
  }

  async signIdentityPayload(payload: string): Promise<IdentitySignatureResult> {
    if (await WebAuthnService.isIdentityRegistered()) {
      return {
        signature: await WebAuthnService.signWithIdentityKey(payload),
        level: KeyProtectionLevel.HARDWARE_BOUND,
        method: 'webauthn',
        encoding: 'base64',
      };
    }

    if (await this.isHardwareAvailable()) {
      throw new Error(
        'HARDWARE_IDENTITY_REQUIRED: WebAuthn is available, but no hardware identity key is registered.'
      );
    }

    await this.ensureSoftwareKey();
    const signatureBytes = await this.software.sign({
      keyId: this.softwareKeyId!,
      challenge: textBytes(payload),
    });
    return {
      signature: bytesToHex(signatureBytes),
      level: KeyProtectionLevel.SOFTWARE_EPHEMERAL,
      method: 'software-fallback',
      encoding: 'hex',
    };
  }

  async getSoftwarePublicKey(): Promise<CryptoKey | null> {
    if (!this.softwarePublicKeyJwk) return null;
    return crypto.subtle.importKey(
      'jwk',
      this.softwarePublicKeyJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  }

  createEncryptionKey(opts: { userId: string }): Promise<EncryptionKeyCreationResult> {
    return this.software.createEncryptionKey(opts);
  }

  deriveSharedSecret(opts: { encKeyId: string; senderPublicKeyJwk: JsonWebKey }): Promise<CryptoKey> {
    return this.software.deriveSharedSecret(opts);
  }
}

export default IdentityKeyGuardian;
