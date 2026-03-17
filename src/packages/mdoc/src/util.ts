/**
 * @module @mitch/mdoc/util
 *
 * Shared utilities for the mdoc package.
 */

/**
 * Safely retrieve a value from a Map or plain object.
 * CBOR decode returns plain objects (not Maps), so we handle both.
 */
export function mapGet<V>(
  mapOrObj: Map<string | number, V> | Record<string | number, V>,
  key: string | number
): V | undefined {
  if (mapOrObj instanceof Map) return mapOrObj.get(key);
  return (mapOrObj as Record<string | number, V>)[key];
}

/** Copy Uint8Array to a clean ArrayBuffer (avoids SharedArrayBuffer TS issues). */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}
