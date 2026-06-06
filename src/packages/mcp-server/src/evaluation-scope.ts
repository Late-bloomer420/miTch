/**
 * Evaluation scope loader for the MCP server.
 *
 * Default remains the non-authoritative mock scope. If MITCH_WALLET_DB is set,
 * the server treats it as an explicit local JSON evaluation-scope file for v1:
 * policy + credential metadata, never raw credentials.
 *
 * Invalid configured scope is fail-closed. We deliberately do not fall back to
 * mock when the operator asked for a local scope.
 */

import { readFile } from 'node:fs/promises';
import type { PolicyManifest, StoredCredentialMetadata } from '@askmi/shared-types';
import { MOCK_CREDENTIALS, MOCK_POLICY, MOCK_USER_DID } from './server-scope.js';

export type EvaluationScopeKind = 'mock' | 'local';

export interface EvaluationScope {
  kind: EvaluationScopeKind;
  policy: PolicyManifest;
  credentials: StoredCredentialMetadata[];
  userDid: string;
}

type ScopeFile = {
  policy?: unknown;
  credentials?: unknown;
  user_did?: unknown;
  userDid?: unknown;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function assertPolicyManifest(value: unknown): asserts value is PolicyManifest {
  if (!isRecord(value)) {
    throw new Error('scope policy must be an object');
  }
  if (typeof value.version !== 'string' || value.version.length === 0) {
    throw new Error('scope policy.version must be a non-empty string');
  }
  if (!Array.isArray(value.trustedIssuers)) {
    throw new Error('scope policy.trustedIssuers must be an array');
  }
  if (!Array.isArray(value.rules)) {
    throw new Error('scope policy.rules must be an array');
  }
}

function assertStoredCredential(value: unknown): asserts value is StoredCredentialMetadata {
  if (!isRecord(value)) {
    throw new Error('scope credential must be an object');
  }
  if (typeof value.id !== 'string' || value.id.length === 0) {
    throw new Error('scope credential.id must be a non-empty string');
  }
  if (typeof value.issuer !== 'string' || value.issuer.length === 0) {
    throw new Error('scope credential.issuer must be a non-empty string');
  }
  if (!isStringArray(value.type) || value.type.length === 0) {
    throw new Error('scope credential.type must be a non-empty string array');
  }
  if (typeof value.issuedAt !== 'string' || value.issuedAt.length === 0) {
    throw new Error('scope credential.issuedAt must be a non-empty string');
  }
  if (!isStringArray(value.claims)) {
    throw new Error('scope credential.claims must be a string array');
  }
}

function assertScopeFile(value: unknown): asserts value is ScopeFile {
  if (!isRecord(value)) {
    throw new Error('evaluation scope file must contain a JSON object');
  }
  assertPolicyManifest(value.policy);
  if (!Array.isArray(value.credentials)) {
    throw new Error('scope credentials must be an array');
  }
  for (const credential of value.credentials) {
    assertStoredCredential(credential);
  }
}

export async function loadEvaluationScope(): Promise<EvaluationScope> {
  const configuredPath = process.env.MITCH_WALLET_DB?.trim();

  if (!configuredPath) {
    return {
      kind: 'mock',
      policy: MOCK_POLICY,
      credentials: MOCK_CREDENTIALS,
      userDid: MOCK_USER_DID,
    };
  }

  const raw = await readFile(configuredPath, 'utf8');
  const parsed = JSON.parse(raw) as unknown;
  assertScopeFile(parsed);
  const policy = parsed.policy as PolicyManifest;
  const credentials = parsed.credentials as StoredCredentialMetadata[];

  const userDid =
    typeof parsed.user_did === 'string' && parsed.user_did.length > 0
      ? parsed.user_did
      : typeof parsed.userDid === 'string' && parsed.userDid.length > 0
        ? parsed.userDid
        : 'did:example:local-wallet';

  return {
    kind: 'local',
    policy,
    credentials,
    userDid,
  };
}
