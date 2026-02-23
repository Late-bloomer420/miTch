import { loadMetrics, saveMetrics } from "./metricsStore";

export interface ServiceMetrics {
  startedAt: string;
  totals: {
    requests: number;
    allow: number;
    deny: number;
  };
  denyByCode: Record<string, number>;
  recentDecisions: Array<{
    at: string;
    requestId: string;
    decision: "ALLOW" | "DENY";
    decisionCode: string;
  }>;
}

const loaded = loadMetrics();
const metrics: ServiceMetrics = loaded
  ? {
      startedAt: loaded.startedAt ?? new Date().toISOString(),
      totals: {
        requests: loaded.totals?.requests ?? 0,
        allow: loaded.totals?.allow ?? 0,
        deny: loaded.totals?.deny ?? 0,
      },
      denyByCode: loaded.denyByCode ?? {},
      recentDecisions: loaded.recentDecisions ?? [],
    }
  : {
      startedAt: new Date().toISOString(),
      totals: {
        requests: 0,
        allow: 0,
        deny: 0,
      },
      denyByCode: {},
      recentDecisions: [],
    };

export function recordDecision(
  decision: "ALLOW" | "DENY",
  decisionCode: string,
  requestId = "unknown"
): void {
  metrics.totals.requests += 1;

  metrics.recentDecisions.unshift({
    at: new Date().toISOString(),
    requestId,
    decision,
    decisionCode,
  });
  metrics.recentDecisions = metrics.recentDecisions.slice(0, 10);

  if (decision === "ALLOW") {
    metrics.totals.allow += 1;
    saveMetrics(metrics);
    return;
  }

  metrics.totals.deny += 1;
  metrics.denyByCode[decisionCode] = (metrics.denyByCode[decisionCode] ?? 0) + 1;
  saveMetrics(metrics);
}

export function getMetricsSnapshot(): ServiceMetrics {
  return {
    startedAt: metrics.startedAt,
    totals: { ...metrics.totals },
    denyByCode: { ...metrics.denyByCode },
    recentDecisions: [...metrics.recentDecisions],
  };
}

export function resetMetrics(): ServiceMetrics {
  metrics.startedAt = new Date().toISOString();
  metrics.totals.requests = 0;
  metrics.totals.allow = 0;
  metrics.totals.deny = 0;
  metrics.denyByCode = {};
  metrics.recentDecisions = [];
  saveMetrics(metrics);
  return getMetricsSnapshot();
}
