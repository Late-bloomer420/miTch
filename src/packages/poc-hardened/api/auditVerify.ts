import { existsSync, readFileSync } from "fs";
import { createHash } from "crypto";

const EVENTS_PATH = "./data/events.jsonl";

interface StoredAuditEvent {
  schemaVersion: "v1";
  prevHash: string;
  hash: string;
  [k: string]: unknown;
}

function computeHash(eventWithoutHash: Omit<StoredAuditEvent, "hash">): string {
  return createHash("sha256").update(JSON.stringify(eventWithoutHash), "utf8").digest("hex");
}

export function verifyAuditChain(): {
  ok: boolean;
  checked: number;
  error?: string;
  brokenAt?: number;
} {
  if (!existsSync(EVENTS_PATH)) return { ok: true, checked: 0 };

  const raw = readFileSync(EVENTS_PATH, "utf8").trim();
  if (!raw) return { ok: true, checked: 0 };

  const lines = raw.split("\n");
  let expectedPrev = "GENESIS";

  for (let i = 0; i < lines.length; i++) {
    let parsed: StoredAuditEvent;
    try {
      parsed = JSON.parse(lines[i]) as StoredAuditEvent;
    } catch {
      return { ok: false, checked: i, error: "invalid_json", brokenAt: i + 1 };
    }

    if (!parsed.hash || !parsed.prevHash || parsed.schemaVersion !== "v1") {
      return { ok: true, checked: i, error: "legacy_events_present" };
    }

    if (parsed.prevHash !== expectedPrev) {
      return { ok: false, checked: i, error: "prev_hash_mismatch", brokenAt: i + 1 };
    }

    const { hash, ...rest } = parsed;
    const computed = computeHash(rest as Omit<StoredAuditEvent, "hash">);
    if (computed !== hash) {
      return { ok: false, checked: i, error: "hash_mismatch", brokenAt: i + 1 };
    }

    expectedPrev = hash;
  }

  return { ok: true, checked: lines.length };
}
