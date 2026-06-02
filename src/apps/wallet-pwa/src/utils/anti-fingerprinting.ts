/**
 * U-22: Anti-Fingerprinting Utilities
 * 
 * Ensures wallet anonymity and uniformity by:
 * 1. Normalizing request headers and JSON structures.
 * 2. Padding payloads to prevent traffic analysis based on size.
 */

/**
 * Normalizes a JSON object by sorting its keys alphabetically.
 */
export function canonicalizeJson(obj: unknown): string {
    return JSON.stringify(obj, Object.keys(obj as any).sort());
}

/**
 * Pads a payload to a fixed size by wrapping it in a JSON object with a 'padding' field.
 * Works with both strings (like JWE) and objects.
 */
export function padPayload(data: string | Record<string, any>, blockSize: number = 4096): string {
    let basePayload: string;
    let obj: Record<string, any>;

    if (typeof data === 'string') {
        try {
            obj = JSON.parse(data);
        } catch {
            // If it's a raw JWE string, wrap it
            obj = { ciphertext: data };
        }
    } else {
        obj = data;
    }

    basePayload = JSON.stringify(obj);
    
    if (basePayload.length >= blockSize) {
        blockSize = Math.ceil((basePayload.length + 512) / 1024) * 1024;
    }

    const currentSize = basePayload.length;
    const paddingSize = blockSize - currentSize - 25; // buffer for "padding": "..."
    
    const noise = Array.from({ length: Math.max(0, paddingSize) }, () => 
        Math.floor(Math.random() * 36).toString(36)).join('');
        
    const paddedData = {
        ...obj,
        padding: noise
    };

    // Use canonicalizeJson to ensure header order uniformity
    return canonicalizeJson(paddedData);
}

/**
 * Fixed set of headers to prevent browser fingerprinting via header order/case.
 */
export const UNIFORM_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
};
