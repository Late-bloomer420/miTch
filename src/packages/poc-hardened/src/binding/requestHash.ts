import { createHash } from "crypto";
import { VerificationRequestV0 } from "../types/api";
import { canonicalizeRequest } from "./canonicalize";

function toBase64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function computeRequestHash(request: VerificationRequestV0): string {
  const canonical = canonicalizeRequest(request);
  const digest = createHash("sha256").update(canonical, "utf8").digest();
  return toBase64Url(digest);
}
