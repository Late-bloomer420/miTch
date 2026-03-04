import { createServer, IncomingMessage, ServerResponse } from "http";
import { verifyRequest } from "./api/verifierRoutes";
import { PolicyManifestV0 } from "./types/policy";
import { ResolveKey } from "./proof/keyResolver";
import { createSignedLocalRequest, localResolveKey } from "./api/testRequestFactory";
import { getMetricsSnapshot, recordDecision, resetMetrics } from "./api/metrics";
import { isAuthorized } from "./config/auth";
import { envResolveKey } from "./proof/envKeyResolver";
import { createDIDKeyResolver } from "./proof/didKeyResolver";
import { appendEvent } from "./api/eventLog";
import { getKpiSnapshot } from "./api/kpi";
import { recordAdjudication, recordOverride } from "./api/operations";
import { verifyAuditChain } from "./api/auditVerify";

const PORT = Number(process.env.PORT ?? 8080);
const RUNTIME_AUDIENCE = process.env.RUNTIME_AUDIENCE ?? "rp.example";
const IS_PROD = process.env.NODE_ENV === "production";
const ALLOW_DEV_RESET = !IS_PROD && process.env.ALLOW_DEV_RESET === "1";
const ALLOW_TEST_KEYS = !IS_PROD && process.env.LOCAL_TEST_KEYS === "1";
const ALLOW_METRICS = !IS_PROD || process.env.ALLOW_METRICS === "1";
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES ?? 262144);

const defaultPolicy: PolicyManifestV0 = {
  version: "v0",
  id: "policy-v0-age",
  purposes: ["age_gate_checkout"],
  predicates: [{ name: "age_gte", allowed: true }],
  failClosed: true,
};

// DID-based key resolver with fallback to env/test resolver
const baseResolver: ResolveKey = ALLOW_TEST_KEYS ? localResolveKey : envResolveKey;
const resolveKey: ResolveKey = createDIDKeyResolver(baseResolver);

function sendJson(res: ServerResponse, statusCode: number, body: unknown, correlationId?: string): void {
  const json = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json),
    ...(correlationId ? { "x-correlation-id": correlationId } : {}),
  });
  res.end(json);
}

function sendCsv(res: ServerResponse, statusCode: number, csv: string, correlationId?: string): void {
  res.writeHead(statusCode, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Length": Buffer.byteLength(csv),
    ...(correlationId ? { "x-correlation-id": correlationId } : {}),
  });
  res.end(csv);
}

function sendHtml(res: ServerResponse, statusCode: number, html: string, correlationId?: string): void {
  res.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    ...(correlationId ? { "x-correlation-id": correlationId } : {}),
  });
  res.end(html);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk) => {
      const buf = Buffer.from(chunk);
      total += buf.length;
      if (total > MAX_BODY_BYTES) {
        req.destroy(new Error("payload_too_large"));
        return;
      }
      chunks.push(buf);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = createServer(async (req, res) => {
  const correlationId = req.headers["x-correlation-id"]?.toString() ?? `corr-${Date.now()}`;

  if (!req.url || !req.method) {
    return sendJson(res, 400, { error: "bad_request" }, correlationId);
  }

  if (req.method === "GET" && req.url === "/") {
    return sendJson(
      res,
      200,
      {
        service: "miTch verifier",
        endpoints: ["GET /", "GET /health", "GET /dashboard", "GET /metrics", "GET /metrics.csv", "GET /kpi", "GET /audit/verify", "GET /metrics/reset (ALLOW_DEV_RESET=1)", "GET /test-request (LOCAL_TEST_KEYS=1)", "POST /verify", "POST /override", "POST /adjudicate"],
      },
      correlationId
    );
  }

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, { status: "ok" }, correlationId);
  }

  if (req.method === "GET" && req.url === "/dashboard") {
    if (IS_PROD) return sendJson(res, 404, { error: "not_found" }, correlationId);
    const m = getMetricsSnapshot();
    const k = getKpiSnapshot();

    const percent = (v: number): string => `${(v * 100).toFixed(1)}%`;
    const euro = (v: number): string => `${v.toFixed(3)} €`;

    const successRate = Number(k.verification_success_rate ?? 0);
    const falseDenyRate = Number(k.false_deny_rate ?? 0);
    const overrideRate = Number(k.policy_override_rate ?? 0);
    const replayBlockRate = Number(k.replay_block_rate ?? 1);
    const securityScore = Number(k.security_profile_score ?? 0);

    const modeledBaselineCost = Number(process.env.BASELINE_COST_PER_VERIFICATION_EUR ?? 0.12);
    const mitchCost = Number(k.estimated_cost_per_verification_eur ?? 0);
    const costSavingPerVerification = Math.max(0, modeledBaselineCost - mitchCost);
    const costSavingRate = modeledBaselineCost > 0 ? costSavingPerVerification / modeledBaselineCost : 0;

    const issuerCurrent = Number(process.env.DIRECT_PARTNER_ISSUER_CURRENT ?? 0);
    const issuerTarget = Number(process.env.DIRECT_PARTNER_ISSUER_TARGET ?? 1);
    const rpCurrent = Number(process.env.DIRECT_PARTNER_RP_CURRENT ?? 0);
    const rpTarget = Number(process.env.DIRECT_PARTNER_RP_TARGET ?? 2);

    const issuerProgress = issuerTarget > 0 ? Math.min(1, issuerCurrent / issuerTarget) : 0;
    const rpProgress = rpTarget > 0 ? Math.min(1, rpCurrent / rpTarget) : 0;

    const denyBars = Object.entries(m.denyByCode)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([code, count]) => {
        const width = m.totals.deny > 0 ? Math.max(3, Math.round((count / m.totals.deny) * 100)) : 0;
        return `<div class="bar-row"><span class="label">${code}</span><div class="bar"><span style="width:${width}%"></span></div><span class="value">${count}</span></div>`;
      })
      .join("");

    const recentRows = m.recentDecisions
      .map(
        (d) => `<tr><td>${d.at}</td><td>${d.requestId}</td><td>${d.decision}</td><td>${d.decisionCode}</td></tr>`
      )
      .join("");

    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>miTch Dashboard</title>
  <style>
    :root{--bg:#0b1020;--panel:#111832;--line:#2a3358;--muted:#9aa6cc;--txt:#f5f7ff;--ok:#36d399;--warn:#fbbf24;--bad:#f87171;--accent:#7aa2ff}
    *{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 10% 0%, #182347 0%, #0b1020 55%);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif}
    .wrap{max-width:1160px;margin:22px auto;padding:0 16px}
    .head{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;margin-bottom:14px}
    .muted{color:var(--muted);font-size:13px}
    .grid{display:grid;gap:12px}
    .grid.kpis{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:12px}
    .grid.main{grid-template-columns:2fr 1.1fr}
    .card{background:linear-gradient(180deg,#121b39,#0f1732);border:1px solid var(--line);border-radius:14px;padding:14px;box-shadow:0 8px 30px rgba(0,0,0,.25)}
    .k{font-size:12px;color:var(--muted);margin-bottom:6px}.v{font-size:26px;font-weight:700;letter-spacing:.2px}
    .chip{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 8px;font-size:12px;color:var(--muted)}
    .bar-row{display:grid;grid-template-columns:1.4fr 2fr auto;gap:8px;align-items:center;margin:8px 0}
    .bar{height:8px;background:#1b264a;border-radius:999px;overflow:hidden}.bar span{display:block;height:100%;background:linear-gradient(90deg,#7aa2ff,#59d1ff)}
    .label{font-size:12px;color:#cfd8ff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.value{font-size:12px;color:#cfd8ff}
    table{width:100%;border-collapse:collapse;margin-top:8px} th,td{font-size:12px;padding:7px 8px;border-bottom:1px solid #223058;text-align:left}
    th{color:var(--muted);font-weight:600}
    .pill-ok{color:#a7f3d0}.pill-warn{color:#fde68a}.pill-bad{color:#fecaca}
    .targets li{margin:6px 0;color:#d5dcff}
    .footer{margin-top:10px;font-size:12px;color:var(--muted)}
    @media (max-width:980px){.grid.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.grid.main{grid-template-columns:1fr}}
  </style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <div>
      <h1 style="margin:0 0 4px 0;font-size:26px">miTch Pilot Dashboard</h1>
      <div class="muted">Started ${m.startedAt} · Fokus: Security + Adoption ohne Overload</div>
    </div>
    <div class="chip">Security Score ${securityScore}/100</div>
  </div>

  <div class="grid kpis">
    <div class="card"><div class="k">Verification Success</div><div class="v">${percent(successRate)}</div><div class="muted">Ziel ≥ 99%</div></div>
    <div class="card"><div class="k">Replay Block Rate</div><div class="v">${percent(replayBlockRate)}</div><div class="muted">Ziel 100%</div></div>
    <div class="card"><div class="k">Kosten / Verifikation</div><div class="v">${euro(mitchCost)}</div><div class="muted">Modelled Baseline ${euro(modeledBaselineCost)}</div></div>
    <div class="card"><div class="k">Ersparnis ggü. Baseline</div><div class="v">${percent(costSavingRate)}</div><div class="muted">${euro(costSavingPerVerification)} pro Check</div></div>
  </div>

  <div class="grid main">
    <div class="card">
      <h3 style="margin:0 0 8px 0">Security + Quality Verlauf</h3>
      <div class="bar-row"><span class="label">False Deny Rate</span><div class="bar"><span style="width:${Math.min(100, Math.round(falseDenyRate * 100))}%"></span></div><span class="value">${percent(falseDenyRate)}</span></div>
      <div class="bar-row"><span class="label">Policy Override Rate</span><div class="bar"><span style="width:${Math.min(100, Math.round(overrideRate * 100))}%"></span></div><span class="value">${percent(overrideRate)}</span></div>
      <div class="bar-row"><span class="label">Deny Status Source Unavailable</span><div class="bar"><span style="width:${Math.min(100, Math.round(Number(k.deny_status_source_unavailable_rate ?? 0) * 100))}%"></span></div><span class="value">${percent(Number(k.deny_status_source_unavailable_rate ?? 0))}</span></div>

      <h4 style="margin:12px 0 6px 0">Top Deny Codes</h4>
      ${denyBars || "<div class='muted'>Noch keine Deny-Daten vorhanden.</div>"}

      <h4 style="margin:12px 0 6px 0">Recent Decisions</h4>
      <table>
        <thead><tr><th>Zeit</th><th>Request</th><th>Decision</th><th>Code</th></tr></thead>
        <tbody>${recentRows || "<tr><td colspan='4'><i>No decisions yet</i></td></tr>"}</tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin:0 0 8px 0">Marktanalyse · Direkt-Partner</h3>
      <div class="muted" style="margin-bottom:8px">Klein starten: 1 Issuer + 2 RPs als Proof-Markt.</div>

      <div class="bar-row"><span class="label">Issuer Funnel</span><div class="bar"><span style="width:${Math.round(issuerProgress * 100)}%"></span></div><span class="value">${issuerCurrent}/${issuerTarget}</span></div>
      <div class="bar-row"><span class="label">RP Funnel</span><div class="bar"><span style="width:${Math.round(rpProgress * 100)}%"></span></div><span class="value">${rpCurrent}/${rpTarget}</span></div>

      <h4 style="margin:12px 0 6px 0">Zielgruppe (ICP)</h4>
      <ul class="targets" style="padding-left:18px;margin:0">
        <li>EU-regulierte Plattformen mit Alters-/Eligibility-Prüfung</li>
        <li>RPs mit Compliance-Druck und hoher Haftung</li>
        <li>Teams, die Integration in &lt;2 Tagen brauchen</li>
      </ul>

      <h4 style="margin:12px 0 6px 0">Warum günstiger?</h4>
      <ul class="targets" style="padding-left:18px;margin:0">
        <li>Weniger Datenhaltung beim RP → geringerer Audit- und Breach-Impact</li>
        <li>Drop-in Verifier statt Eigenbau/Operations-Overhead</li>
        <li>Deny-Code + Evidence-Flow reduziert manuelle Incident-Zeit</li>
      </ul>

      <h4 style="margin:12px 0 6px 0">Konkurrenz-Matrix (kompakt)</h4>
      <table>
        <thead><tr><th>Option</th><th>Go-live</th><th>Data-Min</th><th>Audit</th></tr></thead>
        <tbody>
          <tr><td><b>miTch</b></td><td class="pill-ok">Schnell</td><td class="pill-ok">Hoch</td><td class="pill-ok">Hoch</td></tr>
          <tr><td>KYC Suite (breit)</td><td class="pill-warn">Mittel</td><td class="pill-warn">Mittel</td><td class="pill-ok">Hoch</td></tr>
          <tr><td>AV Spezialist</td><td class="pill-ok">Schnell</td><td class="pill-warn">Mittel</td><td class="pill-warn">Mittel</td></tr>
          <tr><td>Inhouse Build</td><td class="pill-bad">Langsam</td><td class="pill-warn">Variabel</td><td class="pill-warn">Variabel</td></tr>
        </tbody>
      </table>

      <div class="footer">
        Hinweis: Kostenvergleich nutzt modellierte Baseline (BASELINE_COST_PER_VERIFICATION_EUR).
        Für echte Marktzahlen im Pilot mit Realdaten kalibrieren.
      </div>
    </div>
  </div>

  <div class="footer">
    Quellen: <a href="/metrics" style="color:#bcd1ff">/metrics</a> · <a href="/kpi" style="color:#bcd1ff">/kpi</a> · <a href="/metrics.csv" style="color:#bcd1ff">/metrics.csv</a> · <a href="/audit/verify" style="color:#bcd1ff">/audit/verify</a>
  </div>
</div>
</body>
</html>`;
    return sendHtml(res, 200, html, correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics") {
    if (!ALLOW_METRICS) return sendJson(res, 404, { error: "not_found" }, correlationId);
    return sendJson(res, 200, getMetricsSnapshot(), correlationId);
  }

  if (req.method === "GET" && req.url === "/kpi") {
    if (!ALLOW_METRICS) return sendJson(res, 404, { error: "not_found" }, correlationId);
    return sendJson(res, 200, getKpiSnapshot(), correlationId);
  }

  if (req.method === "GET" && req.url === "/audit/verify") {
    if (!ALLOW_METRICS) return sendJson(res, 404, { error: "not_found" }, correlationId);
    return sendJson(res, 200, verifyAuditChain(), correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics/reset") {
    if (!ALLOW_DEV_RESET) return sendJson(res, 403, { error: "dev_reset_disabled" }, correlationId);
    const reset = resetMetrics();
    return sendJson(res, 200, reset, correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics.csv") {
    if (!ALLOW_METRICS) return sendJson(res, 404, { error: "not_found" }, correlationId);
    const m = getMetricsSnapshot();
    const rows = [
      "metric,value",
      `startedAt,${m.startedAt}`,
      `requests_total,${m.totals.requests}`,
      `allow_total,${m.totals.allow}`,
      `deny_total,${m.totals.deny}`,
      ...Object.entries(m.denyByCode).map(([k, v]) => `deny_code_${k},${v}`),
    ];
    return sendCsv(res, 200, rows.join("\n"), correlationId);
  }

  if (req.method === "GET" && req.url === "/test-request") {
    if (!ALLOW_TEST_KEYS) {
      return sendJson(res, 403, { error: "test_keys_disabled" }, correlationId);
    }
    const sample = createSignedLocalRequest(RUNTIME_AUDIENCE);
    return sendJson(res, 200, sample, correlationId);
  }

  if (req.method === "POST" && req.url === "/override") {
    if (!isAuthorized(req.headers.authorization?.toString())) {
      return sendJson(res, 401, { error: "unauthorized" }, correlationId);
    }
    try {
      const body = JSON.parse(await readBody(req)) as {
        requestId?: string;
        previousDecisionCode?: string;
        newDecision?: "ALLOW" | "DENY";
        reason?: string;
      };
      if (!body.requestId || !body.previousDecisionCode || !body.newDecision || !body.reason) {
        return sendJson(res, 400, { error: "bad_request" }, correlationId);
      }
      recordOverride({
        correlationId,
        requestId: body.requestId,
        previousDecisionCode: body.previousDecisionCode,
        newDecision: body.newDecision,
        reason: body.reason,
      });
      return sendJson(res, 200, { status: "ok" }, correlationId);
    } catch {
      return sendJson(res, 400, { error: "bad_request" }, correlationId);
    }
  }

  if (req.method === "POST" && req.url === "/adjudicate") {
    if (!isAuthorized(req.headers.authorization?.toString())) {
      return sendJson(res, 401, { error: "unauthorized" }, correlationId);
    }
    try {
      const body = JSON.parse(await readBody(req)) as {
        requestId?: string;
        outcome?: "legit" | "false_deny" | "false_allow";
      };
      if (!body.requestId || !body.outcome) return sendJson(res, 400, { error: "bad_request" }, correlationId);
      recordAdjudication({ correlationId, requestId: body.requestId, outcome: body.outcome });
      return sendJson(res, 200, { status: "ok" }, correlationId);
    } catch {
      return sendJson(res, 400, { error: "bad_request" }, correlationId);
    }
  }

  if (req.method === "POST" && req.url === "/verify") {
    const started = Date.now();

    if (!isAuthorized(req.headers.authorization?.toString())) {
      appendEvent({
        at: new Date().toISOString(),
        eventType: "request_rejected_auth",
        correlationId,
      });
      return sendJson(res, 401, { error: "unauthorized" }, correlationId);
    }

    try {
      const raw = await readBody(req);
      const parsed: unknown = raw ? JSON.parse(raw) : {};

      appendEvent({
        at: new Date().toISOString(),
        eventType: "request_received",
        correlationId,
        requestId: typeof parsed === "object" && parsed && "requestId" in parsed ? String((parsed as { requestId?: string }).requestId ?? "unknown") : "unknown",
        rpId: typeof parsed === "object" && parsed && "rp" in parsed ? String(((parsed as { rp?: { id?: string } }).rp?.id ?? "unknown")) : "unknown",
      });

      const result = await verifyRequest(parsed, defaultPolicy, RUNTIME_AUDIENCE, resolveKey);
      recordDecision(result.decision, result.decisionCode, result.requestId);
      appendEvent({
        at: new Date().toISOString(),
        eventType: "decision_made",
        correlationId,
        requestId: result.requestId,
        decision: result.decision,
        decisionCode: result.decisionCode,
        latencyMs: Date.now() - started,
      });
      const status = result.decision === "ALLOW" ? 200 : 403;
      return sendJson(res, status, result, correlationId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "";
      const code = msg.includes("payload_too_large")
        ? "DENY_SCHEMA_TYPE_MISMATCH"
        : "DENY_INTERNAL_SAFE_FAILURE";
      const status = msg.includes("payload_too_large") ? 413 : 400;

      appendEvent({
        at: new Date().toISOString(),
        eventType: "request_rejected_schema",
        correlationId,
        decision: "DENY",
        decisionCode: code,
        latencyMs: Date.now() - started,
      });

      return sendJson(res, status, {
        version: "v0",
        requestId: "unknown",
        decision: "DENY",
        decisionCode: code,
        claimsSatisfied: [],
        receiptRef: "aqdr:pending",
        verifiedAt: new Date().toISOString(),
      }, correlationId);
    }
  }

  return sendJson(res, 404, { error: "not_found" }, correlationId);
});

server.listen(PORT, () => {
  console.log(`miTch verifier listening on http://localhost:${PORT}`);
});
