/**
 * U-22: Anti-Fingerprinting Utilities
 * 
 * Ensures wallet anonymity and uniformity by:
 * 1. Normalizing request headers and JSON structures.
 * 2. Padding payloads to prevent traffic analysis based on size.
 */

/**
 * Normalizes JSON by recursively sorting object keys alphabetically.
 */
export function canonicalizeJson(obj: unknown): string {
  const serialized = JSON.stringify(sortJsonValue(obj));
  return serialized ?? 'null';
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }

  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};

    for (const key of Object.keys(record).sort()) {
      sorted[key] = sortJsonValue(record[key]);
    }

    return sorted;
  }

  return value;
}

/**
 * Pads a payload to a fixed size by wrapping it in a JSON object with a 'padding' field.
 * Works with both strings (like JWE) and objects.
 */
export function padPayload(data: string | Record<string, unknown>, blockSize: number = 4096): string {
  let obj: Record<string, unknown>;

  if (typeof data === 'string') {
    try {
      obj = JSON.parse(data) as Record<string, unknown>;
    } catch {
      // If it's a raw JWE string, wrap it
      obj = { ciphertext: data };
    }
  } else {
    obj = data;
  }

  const basePayload = JSON.stringify(obj);

  if (basePayload.length >= blockSize) {
    blockSize = Math.ceil((basePayload.length + 512) / 1024) * 1024;
  }

  const currentSize = basePayload.length;
  const paddingSize = blockSize - currentSize - 25; // buffer for "padding": "..."

  const noise = Array.from({ length: Math.max(0, paddingSize) }, () =>
    Math.floor(Math.random() * 36).toString(36)
  ).join('');

  const paddedData = {
    ...obj,
    padding: noise,
  };

  // Use canonicalizeJson to ensure header order uniformity
  return canonicalizeJson(paddedData);
}

/**
 * Fixed set of headers to prevent browser fingerprinting via header order/case.
 */
export const UNIFORM_HEADERS = {
  Accept: 'application/json',
  'Content-Type': 'application/json',
};

/**
 * U-23: Network Timing Jitter
 * Adds a random delay (e.g. 20-100ms) to network requests to prevent 
 * timing side-channel attacks that might reveal credential complexity.
 */
export async function applyJitter(minMs: number = 20, maxMs: number = 100): Promise<void> {
  const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  return new Promise((resolve) => setTimeout(resolve, delay));
}
