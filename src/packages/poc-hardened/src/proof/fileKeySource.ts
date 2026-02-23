import { existsSync, readFileSync } from "fs";
import { KeySource } from "./keySource";

export class FileKeySource implements KeySource {
  constructor(private readonly path: string) {}

  async getPublicKeyPem(keyId: string): Promise<string | null> {
    if (!existsSync(this.path)) return null;
    try {
      const raw = readFileSync(this.path, "utf8");
      const parsed = JSON.parse(raw) as Record<string, string>;
      const pem = parsed[keyId];
      return typeof pem === "string" && pem.length > 0 ? pem : null;
    } catch {
      return null;
    }
  }
}
