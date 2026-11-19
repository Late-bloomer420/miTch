/**
 * Strict issuer-key selection from a fetched JWKS (#240, remaining `kid` item).
 *
 * Only public P-256 signing keys are candidates. With a `kid` in the credential's
 * protected header, exactly one candidate must carry that `kid`. Without one, the
 * key is only unambiguous when the JWKS has exactly one candidate. Anything else
 * returns null so the caller denies (fail closed). This selects among keys of an
 * already trusted issuer; it is not itself a trust decision.
 */
export function selectIssuerJwk(keys: unknown, kid: string | undefined): JsonWebKey | null {
  if (!Array.isArray(keys)) return null;
  const candidates = keys.filter((k): k is JsonWebKey & { kid?: unknown } => {
    if (!k || typeof k !== 'object') return false;
    const jwk = k as Record<string, unknown>;
    if ('d' in jwk) return false; // never accept private key material
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') return false;
    if (jwk.use !== undefined && jwk.use !== 'sig') return false;
    if (jwk.alg !== undefined && jwk.alg !== 'ES256') return false;
    return typeof jwk.x === 'string' && typeof jwk.y === 'string';
  });
  if (kid !== undefined) {
    const matches = candidates.filter((k) => k.kid === kid);
    return matches.length === 1 ? matches[0] : null;
  }
  return candidates.length === 1 ? candidates[0] : null;
}

/** Reads `kid` from a compact JWS protected header; undefined if absent or not a string. */
export function protectedHeaderKid(compactJws: string): string | undefined {
  try {
    const header = JSON.parse(
      Buffer.from(compactJws.split('.')[0] ?? '', 'base64url').toString()
    ) as Record<string, unknown>;
    return typeof header.kid === 'string' ? header.kid : undefined;
  } catch {
    return undefined;
  }
}
