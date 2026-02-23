import { recordAdjudication } from "../api/operations";

function usage(): never {
  console.error("Usage: node dist/tools/adjudicateCli.js <requestId> <outcome:legit|false_deny|false_allow>");
  process.exit(1);
}

const [, , requestId, outcome] = process.argv;

if (!requestId || !outcome) usage();
if (!["legit", "false_deny", "false_allow"].includes(outcome)) usage();

recordAdjudication({
  correlationId: `manual-${Date.now()}`,
  requestId,
  outcome: outcome as "legit" | "false_deny" | "false_allow",
});

console.log(JSON.stringify({ status: "ok", requestId, outcome }, null, 2));
