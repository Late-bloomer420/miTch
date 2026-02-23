type NonceKey = string;

export interface INonceStore {
  consumeOnce(audience: string, nonce: string, ttlSec: number): Promise<"ok" | "replay">;
}

export class InMemoryNonceStore implements INonceStore {
  private readonly seen = new Map<NonceKey, number>();

  async consumeOnce(audience: string, nonce: string, ttlSec: number): Promise<"ok" | "replay"> {
    const key = `${audience}::${nonce}`;
    const now = Date.now();
    const exp = this.seen.get(key);

    if (exp && exp > now) return "replay";

    this.seen.set(key, now + ttlSec * 1000);
    this.sweep(now);
    return "ok";
  }

  private sweep(now: number): void {
    for (const [k, exp] of this.seen.entries()) {
      if (exp <= now) this.seen.delete(k);
    }
  }
}
