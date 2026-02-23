import { readFileSync } from "fs";
import { join } from "path";
import { VerificationRequestV0 } from "../types/api";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const requestSchemaPath = join(process.cwd(), "src", "api", "schemas", "request.v0.schema.json");
const requestSchema = JSON.parse(readFileSync(requestSchemaPath, "utf8")) as {
  required?: string[];
  properties?: Record<string, unknown>;
};

export function validateRequestShape(input: unknown): { ok: true; value: VerificationRequestV0 } | { ok: false; code: string } {
  if (!isObject(input)) return { ok: false, code: "DENY_SCHEMA_TYPE_MISMATCH" };

  const required = requestSchema.required ?? [];
  for (const key of required) {
    if (!(key in input)) return { ok: false, code: "DENY_SCHEMA_MISSING_FIELD" };
  }

  const allowedKeys = new Set(Object.keys(requestSchema.properties ?? {}));
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) return { ok: false, code: "DENY_SCHEMA_UNKNOWN_FIELD" };
  }

  if (input.version !== "v0") return { ok: false, code: "DENY_POLICY_UNSUPPORTED_VERSION" };

  return { ok: true, value: input as unknown as VerificationRequestV0 };
}
