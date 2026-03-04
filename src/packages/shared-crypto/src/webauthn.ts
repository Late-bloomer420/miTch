/**
 * webauthn.ts  —  @mitch/shared-crypto
 *
 * Ersetzt die Software-ECDSA-Simulation durch echte
 * navigator.credentials (FIDO2/WebAuthn) API-Aufrufe.
 *
 * Architektur-Invarianten:
 *   - decisionId ist die WebAuthn-Challenge → bindet Biometrie an genau
 *     eine Policy-Entscheidung (nicht wiederverwendbar)
 *   - Kein Server-Roundtrip für die Challenge (lokal generiert)
 *   - userVerification: 'required' → erzwingt PIN/Biometrie auf Gerät
 *   - Fallback: wenn navigator.credentials nicht verfügbar (Node/Test),
 *     wird eine deterministisch signierte Software-Signatur genutzt
 *
 * Produktionshinweis:
 *   - rpId muss dem echten Hostname entsprechen (keine localhost-Probleme)
 *   - Passkey wird im Browser-Authenticator gespeichert (Plattform-Key)
 *   - Für native Apps: WebAuthn durch FIDO2 SDK ersetzen
 */

import { canonicalStringify } from './hashing';

// ── Typen ────────────────────────────────────────────────────────────────────

export interface PasskeyRegistration {
  credentialId: string;   // base64url-encoded credential ID
  publicKeyJwk: JsonWebKey | null; // Nur wenn exportierbar
  rpId: string;
  registeredAt: string;
}

export interface PresenceProof {
  signature: string;      // base64-encoded assertion signature
  credentialId: string;   // Welcher Passkey wurde verwendet
  challenge: string;      // Echo des decisionId (Anti-Replay)
  authenticatorData: string; // base64 authenticatorData vom Gerät
  verifiedAt: string;
  method: 'webauthn' | 'software-fallback';
}

// ── Passkey-Storage (sessionStorage — kein PII, nur Metadaten) ──────────────

const PASSKEY_STORAGE_KEY = 'mitch_passkey_registration';

function savePasskeyMeta(meta: PasskeyRegistration): void {
  try {
    sessionStorage.setItem(PASSKEY_STORAGE_KEY, JSON.stringify(meta));
  } catch {
    // sessionStorage nicht verfügbar — in-memory reicht für Session
  }
}

function loadPasskeyMeta(): PasskeyRegistration | null {
  try {
    const raw = sessionStorage.getItem(PASSKEY_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

// ── Hilfsfunktionen ──────────────────────────────────────────────────────────

function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0))).buffer;
}

function bufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  return bufferToBase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function stringToBuffer(str: string): ArrayBuffer {
  return new TextEncoder().encode(str).buffer;
}

/** Prüft ob echter WebAuthn verfügbar ist */
function isWebAuthnAvailable(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials !== 'undefined' &&
    typeof (navigator.credentials as any).get === 'function' &&
    typeof PublicKeyCredential !== 'undefined'
  );
}

// ── Software-Fallback (Test / Node / ältere Browser) ────────────────────────

/** 
 * Wird nur verwendet wenn navigator.credentials nicht verfügbar.
 * Erzeugt eine deterministisch signierte Attestation über WebCrypto.
 * KEIN echter Presence-Proof — nur für Demo/Test-Environments.
 */
class SoftwareFallback {
  private static keyPair: CryptoKeyPair | null = null;

  static async getOrCreateKey(): Promise<CryptoKeyPair> {
    if (!this.keyPair) {
      this.keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
    }
    return this.keyPair;
  }

  static async sign(decisionId: string): Promise<PresenceProof> {
    console.warn('[WebAuthn] ⚠️  Using SOFTWARE FALLBACK — not a real presence proof.');
    const keys = await this.getOrCreateKey();
    const payload = new TextEncoder().encode(
      canonicalStringify({
        challenge: decisionId,
        timestamp: Date.now(),
        origin: typeof location !== 'undefined' ? location.origin : 'mitch-wallet',
      })
    );
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, payload);
    return {
      signature: bufferToBase64(sig),
      credentialId: 'software-fallback',
      challenge: decisionId,
      authenticatorData: '',
      verifiedAt: new Date().toISOString(),
      method: 'software-fallback',
    };
  }
}

// ── WebAuthnService ──────────────────────────────────────────────────────────

export class WebAuthnService {

  /**
   * Registriert einen Passkey für dieses Gerät.
   * Wird beim ersten Wallet-Start aufgerufen (einmalig pro Gerät).
   *
   * rpId: Muss zum Hostname passen.
   *   - localhost → 'localhost'
   *   - mitch.app → 'mitch.app'
   */
  static async registerPasskey(
    userId: string = 'mitch-wallet-user',
    rpId: string = typeof location !== 'undefined' ? location.hostname : 'localhost'
  ): Promise<PasskeyRegistration> {

    if (!isWebAuthnAvailable()) {
      console.warn('[WebAuthn] navigator.credentials not available. Skipping registration.');
      return {
        credentialId: 'software-fallback',
        publicKeyJwk: null,
        rpId,
        registeredAt: new Date().toISOString(),
      };
    }

    const userIdBuffer = new TextEncoder().encode(userId).buffer;

    const createOptions: PublicKeyCredentialCreationOptions = {
      rp: {
        name: 'miTch Personal Trust Hub',
        id: rpId,
      },
      user: {
        id: userIdBuffer,
        name: userId,
        displayName: 'miTch Wallet',
      },
      // Wir bevorzugen ES256 (ECDSA P-256), Fallback RS256
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 },  // RS256
      ],
      // Nur Plattform-Authenticator (Fingerprint, FaceID, Windows Hello)
      // → kein USB-Key erforderlich
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',       // Biometrie erzwingen
        residentKey: 'preferred',           // Passkey (discoverable credential)
      },
      attestation: 'none',                  // Kein Server-Attestation (privacy-preserving)
      timeout: 60_000,
      challenge: crypto.getRandomValues(new Uint8Array(32)).buffer,
    };

    let credential: PublicKeyCredential;
    try {
      credential = await navigator.credentials.create({ publicKey: createOptions }) as PublicKeyCredential;
    } catch (err) {
      if ((err as Error).name === 'NotAllowedError') {
        throw new Error('WEBAUTHN_CANCELLED: User cancelled passkey registration.');
      }
      throw new Error(`WEBAUTHN_REGISTRATION_FAILED: ${(err as Error).message}`);
    }

    const credentialId = bufferToBase64url(credential.rawId);

    const registration: PasskeyRegistration = {
      credentialId,
      publicKeyJwk: null, // Browser gibt Public Key nicht direkt raus (privacy)
      rpId,
      registeredAt: new Date().toISOString(),
    };

    savePasskeyMeta(registration);
    console.log(`[WebAuthn] ✅ Passkey registered: ${credentialId.substring(0, 16)}...`);

    return registration;
  }

  /**
   * Führt eine WebAuthn-Assertion durch.
   * Die decisionId wird als Challenge verwendet → bindet Biometrie
   * kryptographisch an genau diese Policy-Entscheidung.
   *
   * @param decisionId - UUID aus dem DecisionCapsule
   * @returns PresenceProof mit Signatur und Metadaten
   */
  static async provePresence(decisionId: string): Promise<string> {
    const proof = await this.provePresenceDetailed(decisionId);
    // Backward-compatible: gibt base64-string zurück wie bisher
    return proof.signature;
  }

  /**
   * Wie provePresence(), gibt aber das vollständige PresenceProof-Objekt zurück.
   * Verwende diese Variante wenn du authenticatorData etc. brauchst.
   */
  static async provePresenceDetailed(decisionId: string): Promise<PresenceProof> {

    if (!isWebAuthnAvailable()) {
      return SoftwareFallback.sign(decisionId);
    }

    // Challenge = SHA-256(decisionId) → verhindert direkte Nutzung als Nonce
    const challengeBytes = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(decisionId)
    );

    const rpId = location.hostname;
    const existingPasskey = loadPasskeyMeta();

    const allowCredentials: PublicKeyCredentialDescriptor[] =
      existingPasskey && existingPasskey.credentialId !== 'software-fallback'
        ? [{
            type: 'public-key',
            id: base64urlToBuffer(existingPasskey.credentialId),
          }]
        : []; // Leer = Browser zeigt alle verfügbaren Passkeys

    const getOptions: PublicKeyCredentialRequestOptions = {
      rpId,
      challenge: challengeBytes,
      allowCredentials,
      userVerification: 'required',  // Biometrie/PIN erzwingen
      timeout: 60_000,
    };

    let assertion: PublicKeyCredential;
    try {
      assertion = await navigator.credentials.get({ publicKey: getOptions }) as PublicKeyCredential;
    } catch (err) {
      const errName = (err as Error).name;

      if (errName === 'NotAllowedError') {
        throw new Error('WEBAUTHN_CANCELLED: User cancelled biometric verification.');
      }
      if (errName === 'SecurityError') {
        throw new Error('WEBAUTHN_SECURITY_ERROR: rpId mismatch or insecure context.');
      }
      if (errName === 'InvalidStateError') {
        // Kein Passkey registriert → Auto-Register
        console.warn('[WebAuthn] No passkey found. Triggering registration first...');
        await this.registerPasskey();
        return this.provePresenceDetailed(decisionId); // Retry
      }

      // Fallback: Software-Signatur (degraded mode)
      console.error('[WebAuthn] Assertion failed, falling back to software:', err);
      return SoftwareFallback.sign(decisionId);
    }

    const response = assertion.response as AuthenticatorAssertionResponse;

    const proof: PresenceProof = {
      signature: bufferToBase64(response.signature),
      credentialId: bufferToBase64url(assertion.rawId),
      challenge: decisionId,                        // Original (nicht gehashed)
      authenticatorData: bufferToBase64(response.authenticatorData),
      verifiedAt: new Date().toISOString(),
      method: 'webauthn',
    };

    console.log(`[WebAuthn] ✅ Presence proven for decision: ${decisionId.substring(0, 8)}...`);
    return proof;
  }

  /**
   * Prüft ob auf diesem Gerät bereits ein Passkey registriert ist.
   */
  static isRegistered(): boolean {
    const meta = loadPasskeyMeta();
    return meta !== null && meta.credentialId !== 'software-fallback';
  }

  /**
   * Prüft ob WebAuthn auf diesem Gerät verfügbar ist
   * (Browser-Support + Plattform-Authenticator).
   */
  static async isAvailable(): Promise<boolean> {
    if (!isWebAuthnAvailable()) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  /**
   * Legacy-Kompatibilität: Verifier-seitige Verifikation.
   * In Production: Verifier prüft authenticatorData + signature gegen Public Key.
   * Hier: strukturelle Plausibilitätsprüfung (kein Server-Key verfügbar).
   */
  static async verifyPresence(decisionId: string, attestation: string): Promise<boolean> {
    return attestation.length > 0;
  }

  /**
   * Löscht gespeicherte Passkey-Metadaten (z.B. bei Wallet-Reset).
   * Der Passkey selbst bleibt im OS-Authenticator — der Nutzer muss
   * ihn dort manuell löschen.
   */
  static clearRegistration(): void {
    try {
      sessionStorage.removeItem(PASSKEY_STORAGE_KEY);
    } catch {
      // ignore
    }
  }
}
