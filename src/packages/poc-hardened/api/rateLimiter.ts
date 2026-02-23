const hits = new Map<string, number[]>();
let globalHits: number[] = [];

export interface RateLimitConfig {
  windowSeconds: number;
  maxRequestsPerRequester: number;
  maxRequestsGlobal?: number;
}

export function checkRateLimit(requesterId: string, cfg: RateLimitConfig): boolean {
  const now = Date.now();
  const windowMs = cfg.windowSeconds * 1000;

  // global budget check (swarm mitigation baseline)
  globalHits = globalHits.filter((t) => now - t <= windowMs);
  if (typeof cfg.maxRequestsGlobal === "number" && globalHits.length >= cfg.maxRequestsGlobal) {
    return false;
  }

  const arr = hits.get(requesterId) ?? [];
  const kept = arr.filter((t) => now - t <= windowMs);
  if (kept.length >= cfg.maxRequestsPerRequester) {
    hits.set(requesterId, kept);
    return false;
  }

  kept.push(now);
  hits.set(requesterId, kept);
  globalHits.push(now);
  return true;
}

export function resetRateLimiter(): void {
  hits.clear();
  globalHits = [];
}
