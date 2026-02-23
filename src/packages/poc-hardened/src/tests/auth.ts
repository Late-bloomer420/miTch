import assert from "assert";
import { isAuthorized } from "../config/auth";

function run(): void {
  // NOTE: module reads env at import time in current design.
  // This test checks current process env assumptions for quick guardrail.
  const required = process.env.AUTH_TOKEN_REQUIRED === "1";

  if (!required) {
    assert.equal(isAuthorized(undefined), true);
    console.log("auth tests passed (auth disabled)");
    return;
  }

  const token = process.env.AUTH_TOKEN ?? "";
  const next = process.env.AUTH_TOKEN_NEXT;

  if (token) assert.equal(isAuthorized(`Bearer ${token}`), true);
  if (next) assert.equal(isAuthorized(`Bearer ${next}`), true);
  assert.equal(isAuthorized("Bearer invalid"), false);
  console.log("auth tests passed");
}

run();
