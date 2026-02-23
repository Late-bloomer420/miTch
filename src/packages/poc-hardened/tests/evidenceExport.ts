import { mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { runEvidenceScenarios } from "./evidence";
import { getKpiSnapshot } from "../api/kpi";
import { verifyAuditChain } from "../api/auditVerify";
import { getMetricsSnapshot } from "../api/metrics";

function stamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

async function run(): Promise<void> {
  const id = stamp();
  const outDir = join(process.cwd(), "data", "evidence", id);
  mkdirSync(outDir, { recursive: true });

  const evidence = await runEvidenceScenarios();
  const kpi = getKpiSnapshot();
  const audit = verifyAuditChain();
  const metrics = getMetricsSnapshot();

  writeFileSync(join(outDir, "evidence.json"), JSON.stringify(evidence, null, 2), "utf8");
  writeFileSync(join(outDir, "kpi.json"), JSON.stringify(kpi, null, 2), "utf8");
  writeFileSync(join(outDir, "audit_verify.json"), JSON.stringify(audit, null, 2), "utf8");
  writeFileSync(join(outDir, "metrics.json"), JSON.stringify(metrics, null, 2), "utf8");

  console.log(JSON.stringify({ outDir, files: ["evidence.json", "kpi.json", "audit_verify.json", "metrics.json"] }, null, 2));
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
