import { KeyProtectionLevel } from "../types/KeyProtectionLevel";

export type KeyCreationResult =
  | {
      level: KeyProtectionLevel.SOFTWARE_EPHEMERAL | KeyProtectionLevel.SOFTWARE_PERSISTED;
      publicKeyJwk: JsonWebKey;
      keyId: string;
    }
  | {
      level: KeyProtectionLevel.HARDWARE_BOUND;
      publicKeyJwk: JsonWebKey;
      keyId: string;
      credentialId: string;
    };

export interface KeyGuardian {
  getLevel(): Promise<KeyProtectionLevel>;
  createKey(opts: { userId: string }): Promise<KeyCreationResult>;
  sign(opts: { keyId: string; challenge: Uint8Array }): Promise<Uint8Array>;
}
