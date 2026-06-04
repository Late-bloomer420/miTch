import { describe, it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../index.js';

async function createConnectedClient(): Promise<Client> {
  const server = createServer();
  const client = new Client({ name: 'test-client', version: '0.0.1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

const VALID_INPUT = {
  verifier_request: {
    verifier_id: 'did:web:rp.example',
    requested_claims: ['dateOfBirth'],
    purpose: 'Age verification for alcohol purchase (GDPR Art. 6(1)(c))',
    nonce: 'test-nonce-abc123',
  },
  context: { user_did: 'did:peer:2.Ez6LStest' },
};

describe('askmi_evaluate_disclosure (stub)', () => {
  it('is listed in the tool inventory', async () => {
    const client = await createConnectedClient();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('askmi_evaluate_disclosure');
    await client.close();
  });

  it('returns a well-formed stub DecisionCapsule', async () => {
    const client = await createConnectedClient();
    const result = await client.callTool({ name: 'askmi_evaluate_disclosure', arguments: VALID_INPUT });
    expect(result.isError).toBeFalsy();
    const block = result.content[0] as { type: string; text: string };
    expect(block.type).toBe('text');
    const capsule = JSON.parse(block.text) as Record<string, unknown>;
    expect(capsule.verdict).toBe('DENY');
    expect(capsule.reason_codes).toContain('NOT_IMPLEMENTED');
    expect(capsule.decision_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(capsule.stub).toBe(true);
    await client.close();
  });

  it('returns unique decision_id per call', async () => {
    const client = await createConnectedClient();
    const [r1, r2] = await Promise.all([
      client.callTool({ name: 'askmi_evaluate_disclosure', arguments: VALID_INPUT }),
      client.callTool({ name: 'askmi_evaluate_disclosure', arguments: VALID_INPUT }),
    ]);
    const id1 = JSON.parse((r1.content[0] as { type: string; text: string }).text).decision_id;
    const id2 = JSON.parse((r2.content[0] as { type: string; text: string }).text).decision_id;
    expect(id1).not.toBe(id2);
    await client.close();
  });

  it('rejects input with too-short nonce', async () => {
    const client = await createConnectedClient();
    const result = await client.callTool({
      name: 'askmi_evaluate_disclosure',
      arguments: { ...VALID_INPUT, verifier_request: { ...VALID_INPUT.verifier_request, nonce: 'short' } },
    });
    expect(result.isError).toBe(true);
    await client.close();
  });
});
