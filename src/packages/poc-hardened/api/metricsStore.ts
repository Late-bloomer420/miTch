import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname } from "path";
import { ServiceMetrics } from "./metrics";

const METRICS_PATH = "./data/metrics.json";

function ensureDir(): void {
  const dir = dirname(METRICS_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function loadMetrics(): ServiceMetrics | null {
  try {
    if (!existsSync(METRICS_PATH)) return null;
    const raw = readFileSync(METRICS_PATH, "utf8");
    return JSON.parse(raw) as ServiceMetrics;
  } catch {
    return null;
  }
}

export function saveMetrics(metrics: ServiceMetrics): void {
  ensureDir();
  writeFileSync(METRICS_PATH, JSON.stringify(metrics, null, 2), "utf8");
}
