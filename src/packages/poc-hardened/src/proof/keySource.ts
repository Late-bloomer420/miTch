export interface KeySource {
  getPublicKeyPem(keyId: string): Promise<string | null>;
}

export class EnvKeySource implements KeySource {
  async getPublicKeyPem(keyId: string): Promise<string | null> {
    try {
      const raw = process.env.PUBLIC_KEYS_JSON ?? "{}";
      const parsed = JSON.parse(raw) as Record<string, string>;
      const pem = parsed[keyId];
      return typeof pem === "string" && pem.length > 0 ? pem : null;
    } catch {
      return null;
    }
  }
}

export function createKeySource(): KeySource {
  const mode = (process.env.KEY_SOURCE_MODE ?? "env").toLowerCase();
  if (mode === "file") {
    // lazy require to avoid circular imports in compile order
    const { FileKeySource } = require("./fileKeySource") as typeof import("./fileKeySource");
    return new FileKeySource(process.env.KEY_SOURCE_FILE ?? "./data/public-keys.json");
  }
  if (mode === "http") {
    const { HttpKeySource } = require("./httpKeySource") as typeof import("./httpKeySource");
    const urls = (process.env.KEY_SOURCE_URLS ?? process.env.KEY_SOURCE_URL ?? "http://localhost:8090/keys")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const timeoutMs = Number(process.env.KEY_SOURCE_TIMEOUT_MS ?? 1500);
    const quorum = Number(process.env.KEY_SOURCE_QUORUM ?? 1);
    return new HttpKeySource(urls, timeoutMs, quorum);
  }
  return new EnvKeySource();
}
