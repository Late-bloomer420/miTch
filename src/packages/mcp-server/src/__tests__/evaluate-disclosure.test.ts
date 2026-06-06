import { describe, it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../index.js';
import { MOCK_VERIFIERS, MOCK_ISSUER_DID, MOCK_CREDENTIALS } from '../server-scope.js';

async function createConnectedClient(): Promise<Client> {
  const server = createServer();
  const client = new Client({ name: 'test-client', version: '0.0.1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

type TextBlock = { type: string; text: string };

function callInput(verifierId: string, claims: string[] = ['age_over_18']) {
  return {
    verifier_request: {
      verifier_id: verifierId,
      requested_claims: claims,
      purpose: 'Age verification for alcohol purchase (GDPR Art. 6(1)(c))',
      nonce: 'test-nonce-abc123',
    },
    context: { user_did: 'did:peer:2.Ez6LStest' },
  };
}

async function evaluate(client: Client, verifierId: string, claims?: string[]) {
  const result = await client.callTool({
    name: 'askmi_evaluate_disclosure',
    arguments: callInput(verifierId, claims),
  });
  const block = (result.content as TextBlock[])[0];
  return { result, block, capsule: JSON.parse(block.text) as Record<string, unknown> };
}

describe('askmi_evaluate_disclosure (wired to policy-engine, mock scope)', () => {
  it('is listed in the tool inventory', async () => {
    const client = await createConnectedClient();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('askmi_evaluate_disclosure');
    await client.close();
  });

  it('ALLOWs a known auto-approve verifier (liquor store)', async () => {
    const client = await createConnectedClient();
    const { result, capsule } = await evaluate(client, MOCK_VERIFIERS.liquorStore);
    expect(result.isError).toBeFalsy();
    expect(capsule.verdict).toBe('ALLOW');
    expect(capsule.scope).toBe('mock');
    expect(capsule.disclosed_claims).toContain('age_over_18');
    await client.close();
  });

  it('PROMPTs a verifier whose rule requires user consent (hospital)', async () => {
    const client = await createConnectedClient();
    const { capsule } = await evaluate(client, MOCK_VERIFIERS.hospital);
    expect(capsule.verdict).toBe('PROMPT');
    expect(capsule.reason_codes).toContain('CONSENT_REQUIRED');
    await client.close();
  });

  it('DENYs an unknown verifier fail-closed', async () => {
    const client = await createConnectedClient();
    const { capsule } = await evaluate(client, 'did:web:unknown-shady.example.com');
    expect(capsule.verdict).toBe('DENY');
    expect(capsule.reason_codes).toContain('UNKNOWN_VERIFIER');
    expect(capsule.disclosed_claims).toEqual([]);
    await client.close();
  });

  it('returns a well-formed decision_id and is tagged scope:"mock"', async () => {
    const client = await createConnectedClient();
    const { capsule } = await evaluate(client, MOCK_VERIFIERS.liquorStore);
    expect(capsule.decision_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(capsule.scope).toBe('mock');
    expect(typeof capsule.evaluated_at).toBe('string');
    await client.close();
  });

  it('exposes structuredContent mirroring the JSON verdict', async () => {
    const client = await createConnectedClient();
    const result = await client.callTool({
      name: 'askmi_evaluate_disclosure',
      arguments: callInput(MOCK_VERIFIERS.liquorStore),
    });
    expect(result.structuredContent).toMatchObject({ verdict: 'ALLOW', scope: 'mock' });
    await client.close();
  });

  it('Controlled Insight: never leaks credential ids, issuer DIDs or internal fields', async () => {
    const client = await createConnectedClient();
    // ALLOW path is where a capsule with credential metadata exists — the
    // highest-risk case for leakage.
    const { block, capsule } = await evaluate(client, MOCK_VERIFIERS.liquorStore);
    const raw = block.text;

    // No linkable identifiers from the mock inventory may appear anywhere.
    expect(raw).not.toContain(MOCK_CREDENTIALS[0].id);
    expect(raw).not.toContain(MOCK_ISSUER_DID);

    // No internal engine/capsule fields may bleed through the whitelist.
    for (const forbidden of [
      'selected_credential_id',
      'issuer_trust_refs',
      'request_hash',
      'wallet_attestation',
      'pairwise_did',
      'authorized_requirements',
    ]) {
      expect(Object.keys(capsule)).not.toContain(forbidden);
      expect(raw).not.toContain(forbidden);
    }

    // The agent only ever sees this exact, whitelisted key set.
    expect(Object.keys(capsule).sort()).toEqual(
      [
        'decision_id',
        'disclosed_claims',
        'evaluated_at',
        'policy_hash',
        'proven_claims',
        'reason_codes',
        'scope',
        'verdict',
      ].sort(),
    );
    await client.close();
  });

  it('renders Markdown when response_format=markdown', async () => {
    const client = await createConnectedClient();
    const result = await client.callTool({
      name: 'askmi_evaluate_disclosure',
      arguments: { ...callInput(MOCK_VERIFIERS.liquorStore), response_format: 'markdown' },
    });
    const block = (result.content as TextBlock[])[0];
    expect(block.text).toContain('Disclosure verdict');
    expect(block.text).toContain('ALLOW');
    await client.close();
  });

  it('rejects input with too-short nonce (fail-closed validation)', async () => {
    const client = await createConnectedClient();
    const result = await client.callTool({
      name: 'askmi_evaluate_disclosure',
      arguments: {
        ...callInput(MOCK_VERIFIERS.liquorStore),
        verifier_request: { ...callInput(MOCK_VERIFIERS.liquorStore).verifier_request, nonce: 'short' },
      },
    });
    expect(result.isError).toBe(true);
    await client.close();
  });
});
