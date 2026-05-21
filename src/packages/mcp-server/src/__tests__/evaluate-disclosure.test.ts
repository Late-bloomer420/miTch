/**
 * Tests for mitch_evaluate_disclosure (stub phase)
 *
 * These tests verify the tool wiring and stub output structure.
 * Once the policy engine is wired, extend these tests with real verdict assertions.
 */

import { describe, it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../index.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

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
  context: {
    user_did: 'did:peer:2.Ez6LStest',
  },
};

// ── Tests ────────────────────────────────────────────────────────────────────

describe('mitch_evaluate_disclosure (stub)', () => {
  it('is listed in the tool inventory', async () => {
    const client = await createConnectedClient();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain('mitch_evaluate_disclosure');
    await client.close();
  });

  it('returns a well-formed stub response', async () => {
    const client = await createConnectedClient();

    const result = await client.callTool({
      name: 'mitch_evaluate_disclosure',
      arguments: VALID_INPUT,
    });

    expect(result.isError).toBeFalsy();
    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');

    const capsule = JSON.parse((result.content[0] as { type: 'text'; text: string }).text);

    // Stub must always DENY (fail-closed)
    expect(capsule.verdict).toBe('DENY');
    expect(capsule.reason_codes).toContain('NOT_IMPLEMENTED');
    expect(typeof capsule.decision_id).toBe('string');
    expect(capsule.decision_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(capsule.stub).toBe(true);
    expect(typeof capsule.stub_message).toBe('string');

    await client.close();
  });

  it('returns unique decision_id per call (no replay)', async () => {
    const client = await createConnectedClient();

    const [r1, r2] = await Promise.all([
      client.callTool({ name: 'mitch_evaluate_disclosure', arguments: VALID_INPUT }),
      client.callTool({ name: 'mitch_evaluate_disclosure', arguments: VALID_INPUT }),
    ]);

    const id1 = JSON.parse((r1.content[0] as { type: 'text'; text: string }).text).decision_id;
    const id2 = JSON.parse((r2.content[0] as { type: 'text'; text: string }).text).decision_id;
    expect(id1).not.toBe(id2);

    await client.close();
  });

  it('rejects input with missing nonce', async () => {
    const client = await createConnectedClient();

    const badInput = {
      ...VALID_INPUT,
      verifier_request: {
        ...VALID_INPUT.verifier_request,
        nonce: 'short', // < 8 chars — should fail Zod validation
      },
    };

    const result = await client.callTool({
      name: 'mitch_evaluate_disclosure',
      arguments: badInput,
    });

    // SDK returns isError: true for schema validation failures
    expect(result.isError).toBe(true);

    await client.close();
  });
});
