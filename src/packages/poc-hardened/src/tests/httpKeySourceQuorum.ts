import assert from "assert";
import { createServer, Server } from "http";
import { HttpKeySource, getResolverTelemetry } from "../proof/httpKeySource";

function startServer(port: number, payload: Record<string, string>): Promise<Server> {
  const srv = createServer((_, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  });
  return new Promise((resolve) => srv.listen(port, () => resolve(srv)));
}

function closeServer(srv: Server): Promise<void> {
  return new Promise((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
}

async function run(): Promise<void> {
  const s1 = await startServer(18101, { "kid-1": "PEM_A" });
  const s2 = await startServer(18102, { "kid-1": "PEM_A" });
  const s3 = await startServer(18103, { "kid-1": "PEM_B" });

  try {
    const source = new HttpKeySource(
      ["http://127.0.0.1:18101/keys", "http://127.0.0.1:18102/keys", "http://127.0.0.1:18103/keys"],
      1000,
      2
    );

    const pem = await source.getPublicKeyPem("kid-1");
    assert.equal(pem, "PEM_A", "Expected quorum winner PEM_A");

    const strict = new HttpKeySource(
      ["http://127.0.0.1:18101/keys", "http://127.0.0.1:18102/keys", "http://127.0.0.1:18103/keys"],
      1000,
      3
    );
    const pemStrict = await strict.getPublicKeyPem("kid-1");
    assert.equal(pemStrict, null, "Expected null when quorum cannot be met");

    // no-silent-allow assertion: mismatch/no-quorum must never produce a key
    const noSilentAllow = await strict.getPublicKeyPem("kid-1");
    assert.equal(noSilentAllow, null, "No silent allow on repeated mismatch/no-quorum");

    const telemetry = getResolverTelemetry();
    assert.ok(telemetry.resolver_queries_total >= 2, "Expected resolver query telemetry increments");
    assert.ok(telemetry.resolver_inconsistent_responses_total >= 1, "Expected inconsistency telemetry increment");
    assert.ok(telemetry.resolver_quorum_failures_total >= 1, "Expected quorum failure telemetry increment");

    console.log("http key source quorum tests passed");
  } finally {
    await closeServer(s1);
    await closeServer(s2);
    await closeServer(s3);
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
