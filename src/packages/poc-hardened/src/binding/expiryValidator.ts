export function isExpired(expiresAtIso: string, now = new Date(), skewSeconds = 90): boolean {
  const expiresAt = new Date(expiresAtIso);
  if (Number.isNaN(expiresAt.getTime())) return true;
  const diffMs = now.getTime() - expiresAt.getTime();
  return diffMs > skewSeconds * 1000;
}
