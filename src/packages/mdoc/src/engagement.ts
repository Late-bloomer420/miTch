/**
 * @module @askmi/mdoc/engagement
 *
 * ISO 18013-5 §8.2.1 — Device Engagement.
 * Generates the QR code payload for proximity presentation.
 */

import { encode } from './cbor.js';
import { exportCoseKey } from './cose-key.js';
import type { DeviceEngagement } from './mdoc-types.js';

/**
 * Build a DeviceEngagement structure for QR-based presentation.
 * 
 * @param devicePublicKey The holder's public key (to be used in session key agreement).
 * @returns The CBOR-encoded DeviceEngagement bytes.
 */
export async function buildDeviceEngagement(devicePublicKey: CryptoKey): Promise<Uint8Array> {
    const deviceKey = await exportCoseKey(devicePublicKey);
    
    // ISO 18013-5 §8.2.1.1 — Map with keys 0, 1, 2
    const engagement: Map<number, unknown> = new Map();
    
    // Key 0: version (string)
    engagement.set(0, '1.0');
    
    // Key 1: security (list: [cipherSuite, deviceKey])
    // cipherSuite 1 = P-256 (mandatory)
    engagement.set(1, [1, deviceKey]);
    
    // Key 2: deviceRetrievalMethods (optional)
    // For now, we omit this or add a placeholder for BLE
    // engagement.set(2, [[1, 1, new Map()]]); // BLE, version 1
    
    return encode(engagement);
}

/**
 * Create the mdoc-proxi:// URI for the QR code.
 * 
 * @param engagementBytes The CBOR-encoded DeviceEngagement.
 * @returns The URI string (Base64URL encoded engagement).
 */
export function createEngagementUri(engagementBytes: Uint8Array): string {
    const b64 = btoa(String.fromCharCode(...engagementBytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    return `mdoc-proxi://${b64}`;
}
