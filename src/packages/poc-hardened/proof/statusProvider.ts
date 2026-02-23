export type KeyStatus = "active" | "revoked" | "missing" | "unavailable";

export interface KeyStatusProvider {
  getStatus(keyId?: string): Promise<KeyStatus>;
}

export class StaticStatusProvider implements KeyStatusProvider {
  async getStatus(keyId?: string): Promise<KeyStatus> {
    if (process.env.STATUS_PROVIDER_UNAVAILABLE === "1") return "unavailable";
    if (!keyId) return "missing";
    return process.env.REVOKED_KEY_IDS?.split(",").map((s) => s.trim()).includes(keyId)
      ? "revoked"
      : "active";
  }
}
