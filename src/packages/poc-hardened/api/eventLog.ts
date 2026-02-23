import { appendFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import { createHash } from "crypto";
import { dirname } from "path";

export type EventType =
  | "request_received"
  | "decision_made"
  | "request_rejected_auth"
  | "request_rejected_schema"
  | "decision_override"
  | "adjudication_recorded";

export interface AuditEvent {
  at: string;
  eventType: EventType;
  correlationId: string;
  requestId?: string;
  rpId?: string;
  decision?: "ALLOW" | "DENY";
  decisionCode?: string;
  latencyMs?: number;
  details?: Record<string, string | number | boolean>;
}

interface StoredAuditEvent extends AuditEvent {
  schemaVersion: "v1";
  prevHash: string;
  hash: string;
}

const EVENTS_PATH = "./data/events.jsonl";

function ensureDir(): void {
  const dir = dirname(EVENTS_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function computeHash(event: Omit<StoredAuditEvent, "hash">): string {
  return createHash("sha256").update(JSON.stringify(event), "utf8").digest("hex");
}

function getLastHash(): string {
  if (!existsSync(EVENTS_PATH)) return "GENESIS";
  const raw = readFileSync(EVENTS_PATH, "utf8").trim();
  if (!raw) return "GENESIS";
  const lines = raw.split("\n");
  const last = lines[lines.length - 1];
  if (!last) return "GENESIS";
  try {
    const parsed = JSON.parse(last) as { hash?: string };
    return parsed.hash ?? "GENESIS";
  } catch {
    return "GENESIS";
  }
}

export function appendEvent(event: AuditEvent): void {
  ensureDir();
  const prevHash = getLastHash();
  const base: Omit<StoredAuditEvent, "hash"> = {
    ...event,
    schemaVersion: "v1",
    prevHash,
  };
  const stored: StoredAuditEvent = {
    ...base,
    hash: computeHash(base),
  };
  appendFileSync(EVENTS_PATH, JSON.stringify(stored) + "\n", "utf8");
}
