import type { TrustedIssuer } from '@askmi/shared-types';

/**
 * True only when the policy trust list names this issuer for at least one of the
 * credential's types and the entry has not expired. Anything unclear counts as
 * not trusted, so the card never claims more trust than the policy grants.
 */
export function isIssuerTrustedFor(
  trustedIssuers: readonly TrustedIssuer[] | undefined,
  issuer: string,
  credentialTypes: readonly string[],
  now: Date = new Date()
): boolean {
  return (trustedIssuers ?? []).some((entry) => {
    if (entry.did !== issuer) return false;
    if (!entry.credentialTypes.some((type) => credentialTypes.includes(type))) return false;
    if (entry.validUntil === undefined) return true;
    const until = Date.parse(entry.validUntil);
    return Number.isFinite(until) && until > now.getTime();
  });
}
