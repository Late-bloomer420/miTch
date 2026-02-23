import { request as httpRequest } from "http";
import { request as httpsRequest } from "https";
import { URL } from "url";
import { KeySource } from "./keySource";

const resolverTelemetry = {
  queriesTotal: 0,
  quorumFailures: 0,
  inconsistentResponses: 0,
};

const lastResolverOutcomeByKey = new Map<string, "ok" | "missing" | "quorum_failed">();

function fetchJson(urlStr: string, timeoutMs: number): Promise<Record<string, string> | null> {
  return new Promise((resolve) => {
    try {
      const url = new URL(urlStr);
      const lib = url.protocol === "https:" ? httpsRequest : httpRequest;
      const req = lib(
        url,
        { method: "GET", timeout: timeoutMs },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(Buffer.from(c)));
          res.on("end", () => {
            try {
              const body = Buffer.concat(chunks).toString("utf8");
              const parsed = JSON.parse(body) as Record<string, string>;
              resolve(parsed);
            } catch {
              resolve(null);
            }
          });
        }
      );
      req.on("timeout", () => {
        req.destroy();
        resolve(null);
      });
      req.on("error", () => resolve(null));
      req.end();
    } catch {
      resolve(null);
    }
  });
}

export class HttpKeySource implements KeySource {
  constructor(
    private readonly urls: string[],
    private readonly timeoutMs = 1500,
    private readonly quorum = 1
  ) {}

  async getPublicKeyPem(keyId: string): Promise<string | null> {
    resolverTelemetry.queriesTotal += 1;

    const maps = await Promise.all(this.urls.map((u) => fetchJson(u, this.timeoutMs)));

    const counts = new Map<string, number>();
    for (const map of maps) {
      if (!map) continue;
      const pem = map[keyId];
      if (typeof pem !== "string" || pem.length === 0) continue;
      counts.set(pem, (counts.get(pem) ?? 0) + 1);
    }

    if (counts.size > 1) {
      resolverTelemetry.inconsistentResponses += 1;
    }

    let winner: string | null = null;
    let winnerCount = 0;
    for (const [pem, c] of counts.entries()) {
      if (c > winnerCount) {
        winner = pem;
        winnerCount = c;
      }
    }

    const ok = winner && winnerCount >= this.quorum;
    if (!ok) {
      if (counts.size > 0) {
        resolverTelemetry.quorumFailures += 1;
        lastResolverOutcomeByKey.set(keyId, "quorum_failed");
      } else {
        lastResolverOutcomeByKey.set(keyId, "missing");
      }
      return null;
    }

    lastResolverOutcomeByKey.set(keyId, "ok");
    return winner;
  }
}

export function getResolverTelemetry(): {
  resolver_queries_total: number;
  resolver_quorum_failures_total: number;
  resolver_inconsistent_responses_total: number;
} {
  return {
    resolver_queries_total: resolverTelemetry.queriesTotal,
    resolver_quorum_failures_total: resolverTelemetry.quorumFailures,
    resolver_inconsistent_responses_total: resolverTelemetry.inconsistentResponses,
  };
}

export function getLastResolverOutcome(keyId: string): "ok" | "missing" | "quorum_failed" | null {
  return lastResolverOutcomeByKey.get(keyId) ?? null;
}
