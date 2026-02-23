export type CredentialStatusCheck =
  | { ok: true; revoked: boolean }
  | { ok: false; reason: "credential_status_unavailable" | "credential_status_invalid" };

const revokedCacheById = new Map<string, number>();
const revokedCacheByIndex = new Map<string, number>();

const cacheMetrics = {
  revokedCacheHits: 0,
  revokedCacheStores: 0,
};

function parseRevokedIds(value?: string): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

function getRevokedCacheTtlMs(): number {
  return Number(process.env.CREDENTIAL_STATUS_REVOKED_CACHE_TTL_MS ?? 10000);
}

function isValidStatusListUrl(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol === "https:") return true;
    if (process.env.ALLOW_INSECURE_STATUS_URL === "1" && u.protocol === "http:") return true;
    return false;
  } catch {
    return false;
  }
}

function isValidStatusListIndex(index: string): boolean {
  return /^\d+$/.test(index);
}

function getRevokedCacheMaxEntries(): number {
  return Number(process.env.CREDENTIAL_STATUS_REVOKED_CACHE_MAX_ENTRIES ?? 1000);
}

function nowMs(): number {
  return Date.now();
}

function pruneRevokedCache(map: Map<string, number>): void {
  const now = nowMs();
  for (const [k, expiresAt] of map.entries()) {
    if (expiresAt <= now) map.delete(k);
  }

  const max = getRevokedCacheMaxEntries();
  while (map.size > max) {
    const firstKey = map.keys().next().value;
    if (!firstKey) break;
    map.delete(firstKey);
  }
}

function isRevokedCached(credentialId: string, statusListIndex: string): boolean {
  pruneRevokedCache(revokedCacheById);
  pruneRevokedCache(revokedCacheByIndex);

  const now = nowMs();
  const idExpiry = credentialId ? revokedCacheById.get(credentialId) : undefined;
  if (typeof idExpiry === "number" && idExpiry > now) {
    cacheMetrics.revokedCacheHits += 1;
    return true;
  }

  const idxExpiry = statusListIndex ? revokedCacheByIndex.get(statusListIndex) : undefined;
  if (typeof idxExpiry === "number" && idxExpiry > now) {
    cacheMetrics.revokedCacheHits += 1;
    return true;
  }

  return false;
}

function cacheRevokedSignals(credentialId: string, statusListIndex: string): void {
  const ttl = getRevokedCacheTtlMs();
  if (ttl <= 0) return;

  const expiresAt = nowMs() + ttl;
  if (credentialId) revokedCacheById.set(credentialId, expiresAt);
  if (statusListIndex) revokedCacheByIndex.set(statusListIndex, expiresAt);
  cacheMetrics.revokedCacheStores += 1;

  pruneRevokedCache(revokedCacheById);
  pruneRevokedCache(revokedCacheByIndex);
}

async function checkHttpStatus(
  credentialId: string,
  statusListIndex?: string
): Promise<CredentialStatusCheck> {
  const url = (process.env.CREDENTIAL_STATUS_URL ?? "").trim();
  if (!url) return { ok: false, reason: "credential_status_unavailable" };

  const timeoutMs = Number(process.env.CREDENTIAL_STATUS_TIMEOUT_MS ?? 1500);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return { ok: false, reason: "credential_status_unavailable" };
    const contentType = (res.headers.get("content-type") ?? "").toLowerCase();
    if (!contentType.includes("application/json")) {
      return { ok: false, reason: "credential_status_unavailable" };
    }

    const maxBytes = Number(process.env.CREDENTIAL_STATUS_MAX_BYTES ?? 65536);
    const contentLength = Number(res.headers.get("content-length") ?? "0");
    if (contentLength > 0 && contentLength > maxBytes) {
      return { ok: false, reason: "credential_status_unavailable" };
    }

    const raw = await res.text();
    if (Buffer.byteLength(raw, "utf8") > maxBytes) {
      return { ok: false, reason: "credential_status_unavailable" };
    }

    const data = JSON.parse(raw) as { revokedCredentialIds?: unknown; revokedIndexes?: unknown };

    const hasRevokedIds = Object.prototype.hasOwnProperty.call(data, "revokedCredentialIds");
    const hasRevokedIndexes = Object.prototype.hasOwnProperty.call(data, "revokedIndexes");
    if (!hasRevokedIds && !hasRevokedIndexes) return { ok: false, reason: "credential_status_unavailable" };

    if (hasRevokedIds && !Array.isArray(data.revokedCredentialIds)) {
      return { ok: false, reason: "credential_status_unavailable" };
    }
    if (hasRevokedIndexes && !Array.isArray(data.revokedIndexes)) {
      return { ok: false, reason: "credential_status_unavailable" };
    }

    const revokedIds = Array.isArray(data.revokedCredentialIds)
      ? new Set(data.revokedCredentialIds.map((s) => String(s).trim()).filter(Boolean))
      : new Set<string>();
    const revokedIndexes = Array.isArray(data.revokedIndexes)
      ? new Set(data.revokedIndexes.map((s) => String(s).trim()).filter(Boolean))
      : new Set<string>();
    const isRevokedById = revokedIds.has(credentialId);
    const isRevokedByIndex = !!statusListIndex && revokedIndexes.has(statusListIndex);
    return { ok: true, revoked: isRevokedById || isRevokedByIndex };
  } catch {
    return { ok: false, reason: "credential_status_unavailable" };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkCredentialRevocation(
  credentialId?: string,
  credentialStatus?: { type?: string; statusListCredential?: string; statusListIndex?: string }
): Promise<CredentialStatusCheck> {
  if (!credentialId && !credentialStatus) return { ok: true, revoked: false };

  // StatusList2021 light validation (shape + reference sanity)
  if (credentialStatus) {
    if (
      credentialStatus.type !== "StatusList2021Entry" ||
      !credentialStatus.statusListCredential ||
      !credentialStatus.statusListIndex
    ) {
      return { ok: false, reason: "credential_status_invalid" };
    }

    if (!isValidStatusListUrl(credentialStatus.statusListCredential)) {
      return { ok: false, reason: "credential_status_invalid" };
    }

    if (!isValidStatusListIndex(credentialStatus.statusListIndex)) {
      return { ok: false, reason: "credential_status_invalid" };
    }
  }

  const mode = (process.env.CREDENTIAL_STATUS_MODE ?? "env").trim().toLowerCase();

  const effectiveCredentialId = credentialId ?? "";
  const effectiveStatusIndex = credentialStatus?.statusListIndex?.trim() ?? "";

  // security-conservative local cache: revoked=true only, never cache allow
  if (isRevokedCached(effectiveCredentialId, effectiveStatusIndex)) {
    return { ok: true, revoked: true };
  }

  // baseline env mode
  const envRevoked = parseRevokedIds(process.env.REVOKED_CREDENTIAL_IDS);
  const envRevokedIndexes = parseRevokedIds(process.env.REVOKED_STATUS_LIST_INDEXES);
  if (mode === "env") {
    const revokedById = effectiveCredentialId ? envRevoked.has(effectiveCredentialId) : false;
    const revokedByIndex = effectiveStatusIndex ? envRevokedIndexes.has(effectiveStatusIndex) : false;
    const revoked = revokedById || revokedByIndex;
    if (revoked) cacheRevokedSignals(effectiveCredentialId, effectiveStatusIndex);
    return { ok: true, revoked };
  }

  // optional http mode scaffold
  if (mode === "http") {
    if (!effectiveCredentialId) return { ok: false, reason: "credential_status_unavailable" };
    // local list still applies as immediate deny list
    if (envRevoked.has(effectiveCredentialId)) {
      cacheRevokedSignals(effectiveCredentialId, effectiveStatusIndex);
      return { ok: true, revoked: true };
    }
    if (effectiveStatusIndex && envRevokedIndexes.has(effectiveStatusIndex)) {
      cacheRevokedSignals(effectiveCredentialId, effectiveStatusIndex);
      return { ok: true, revoked: true };
    }

    const remote = await checkHttpStatus(effectiveCredentialId, effectiveStatusIndex || undefined);
    if (remote.ok && remote.revoked) {
      cacheRevokedSignals(effectiveCredentialId, effectiveStatusIndex);
    }
    return remote;
  }

  return { ok: false, reason: "credential_status_unavailable" };
}

export function getCredentialStatusCacheMetrics(): { revoked_cache_hit_total: number; revoked_cache_store_total: number } {
  return {
    revoked_cache_hit_total: cacheMetrics.revokedCacheHits,
    revoked_cache_store_total: cacheMetrics.revokedCacheStores,
  };
}
