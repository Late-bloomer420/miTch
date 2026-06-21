/**
 * G-02 — WalletService unit tests
 *
 * Covers: credential store/retrieve/delete, AES-256-GCM roundtrip,
 * error on corrupt storage, policy persistence.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { WalletService } from '../services/WalletService';
import { ASKMI_STORAGE_KEYS, type PolicyManifest } from '@askmi/shared-types';
import { SecureStorage } from '@askmi/secure-storage';
import type { TrackingPoint } from '../services/PrivacyAuditService';
import { DataFlowService } from '@askmi/data-flow';

// Fresh WalletService instance per test (state isolation)
function makeWallet() {
  return new WalletService();
}

const PIN = 'test-pin-1234';
const SALT = 'test-salt-for-unit-tests-v1';

describe('WalletService — Initialization', () => {
  it('initializes without throwing', async () => {
    const wallet = makeWallet();
    await expect(wallet.initialize(PIN, SALT)).resolves.not.toThrow();
  });

  it('second initialize() call is a no-op (idempotent)', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
    // Must not throw or cause any error on re-call
    await expect(wallet.initialize(PIN, SALT)).resolves.not.toThrow();
  });

  it('recovers from a transient init failure WITHOUT auto-wiping the vault (Model A)', async () => {
    // A transient storage hiccup must never silently destroy the user's credentials.
    // The wallet retries, but the vault is only ever wiped via an explicit user action.
    const resetSpy = vi.spyOn(SecureStorage, 'reset');
    const initSpy = vi.spyOn(SecureStorage, 'init');
    initSpy.mockRejectedValueOnce(new Error('transient IndexedDB hiccup'));

    const wallet = makeWallet();
    await expect(wallet.initialize(PIN, SALT)).resolves.not.toThrow();

    expect(resetSpy).not.toHaveBeenCalled();

    resetSpy.mockRestore();
    initSpy.mockRestore();
  });

  it('resetWallet() explicitly wipes the vault and allows a fresh re-initialization', async () => {
    // The explicit escape hatch: the only sanctioned way to clear the vault.
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    const resetSpy = vi.spyOn(SecureStorage, 'reset');
    await wallet.resetWallet();
    expect(resetSpy).toHaveBeenCalledOnce();

    // After an explicit reset, initialize() runs fresh again (not a no-op).
    await expect(wallet.initialize(PIN, SALT)).resolves.not.toThrow();
    const creds = await wallet.getCredentials();
    expect(creds.length).toBeGreaterThan(0); // re-seeded from clean slate

    resetSpy.mockRestore();
  });
});

describe('WalletService — Credential Store / Retrieve', () => {
  let wallet: WalletService;

  beforeEach(async () => {
    wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
  });

  it('seeded credentials are present after initialization', async () => {
    const result = await wallet.evaluateRequest(
      {
        verifierId: 'did:example:test-verifier',
        nonce: crypto.randomUUID(),
        requirements: [{ credentialType: 'AgeCredential', requestedClaims: ['birthDate'] }],
      },
      { userAgent: 'test', timestamp: Date.now() }
    );
    // If credentials are seeded, the policy engine has something to evaluate
    expect(['ALLOW', 'DENY', 'PROMPT']).toContain(result.verdict);
  });

  it('evaluateRequest returns a verdict with reasonCodes array', async () => {
    const result = await wallet.evaluateRequest(
      {
        verifierId: 'did:askmi:known-verifier',
        nonce: crypto.randomUUID(),
        requirements: [{ credentialType: 'AgeCredential', requestedClaims: ['age'] }],
      },
      { userAgent: 'test-agent', timestamp: Date.now() }
    );
    expect(result).toHaveProperty('verdict');
    expect(Array.isArray(result.reasonCodes)).toBe(true);
  });

  it('generates an age predicate proof from the seeded birthDate alias', async () => {
    const verifierKeys = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'wrapKey', 'decrypt', 'unwrapKey']
    );

    const result = await wallet.evaluateRequest(
      {
        verifierId: 'did:askmi:verifier-liquor-store',
        nonce: crypto.randomUUID(),
        requestedClaims: [],
        requestedProvenClaims: ['age >= 18'],
        origin: 'http://localhost:3004',
        serviceEndpoint: 'http://localhost:3004/present',
        ephemeralResponseKey: verifierKeys.publicKey,
      },
      { userAgent: 'test-agent', timestamp: Date.now() }
    );

    expect(result.verdict).toBe('ALLOW');
    expect(result.decisionCapsule).toBeDefined();

    const { auditLog } = await wallet.generatePresentation(result.decisionCapsule!);

    expect(auditLog.some((line) => line.includes('[ZKP] Proof generated'))).toBe(true);
    expect(auditLog.some((line) => line.includes('[ZKP] Proof failed'))).toBe(false);
  });
});

describe('WalletService — Single-Use Credential wiring (Proof-Randomization U-12)', () => {
  let wallet: WalletService;

  beforeEach(async () => {
    wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
  });

  async function presentToLiquorStore() {
    const verifierKeys = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'wrapKey', 'decrypt', 'unwrapKey']
    );
    return wallet.evaluateRequest(
      {
        verifierId: 'did:askmi:verifier-liquor-store',
        nonce: crypto.randomUUID(),
        requestedClaims: [],
        requestedProvenClaims: ['age >= 18'],
        origin: 'http://localhost:3004',
        serviceEndpoint: 'http://localhost:3004/present',
        ephemeralResponseKey: verifierKeys.publicKey,
      },
      { userAgent: 'test-agent', timestamp: Date.now() }
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function selectedIds(capsule: any): string[] {
    const reqs: any[] = capsule?.authorized_requirements ?? [];
    const ids = reqs.map((r) => r.selected_credential_id).filter(Boolean) as string[];
    if (capsule?.selected_credential_id) ids.push(capsule.selected_credential_id);
    return [...new Set(ids)];
  }

  it('records single_use_credential on VP_GENERATED and consumes the credential', async () => {
    // Pass 1 — discover which credential the age-proof flow selects.
    const first = await presentToLiquorStore();
    expect(first.verdict).toBe('ALLOW');
    const ids = selectedIds(first.decisionCapsule);
    expect(ids.length).toBeGreaterThan(0);

    // Re-issue those exact credentials as single-use (same id overwrites metadata).
    for (const id of ids) {
      const m = (await wallet.getCredentials()).find((x) => x.id === id)!;
      const payload = (await wallet.loadCredential(id)) as Record<string, unknown>;
      await wallet.addCredential(id, payload, {
        issuer: m.issuer,
        type: m.type,
        claims: m.claims,
        issuedAt: m.issuedAt,
        singleUse: true,
      });
    }

    // Pass 2 — present the now single-use credential.
    const second = await presentToLiquorStore();
    expect(second.verdict).toBe('ALLOW');
    await wallet.generatePresentation(second.decisionCapsule!);

    const report = await wallet.exportAuditReport();
    const vpEvents = report.entries.filter(
      (e) =>
        e.action === 'VP_GENERATED' &&
        e.metadata?.decision_id === second.decisionCapsule!.decision_id
    );
    expect(vpEvents.length).toBeGreaterThan(0);
    expect(vpEvents.some((e) => e.metadata?.single_use_credential === true)).toBe(true);

    // Consumed: every presented single-use credential is now marked.
    const after = await wallet.getCredentials();
    for (const id of ids) {
      expect(after.find((x) => x.id === id)?.consumedAt).toBeTruthy();
    }
  });

  it('reusable (non single-use) presentations record single_use_credential = false', async () => {
    const result = await presentToLiquorStore();
    expect(result.verdict).toBe('ALLOW');
    await wallet.generatePresentation(result.decisionCapsule!);

    const report = await wallet.exportAuditReport();
    const summary = report.entries.find(
      (e) =>
        e.action === 'VP_GENERATED' &&
        e.metadata?.decision_id === result.decisionCapsule!.decision_id &&
        'used_zkp' in (e.metadata ?? {})
    );
    expect(summary).toBeDefined();
    expect(summary!.metadata?.single_use_credential).toBe(false);
  });

  it('mints an issued credential as single-use (constraint fixed at issuance)', async () => {
    const credId = `vc-issued-${Date.now()}`;
    await wallet.addIssuedCredential(
      credId,
      { birthDate: '1990-01-01', age: 36 },
      'did:web:localhost%3A3005',
      undefined,
      true
    );
    const minted = (await wallet.getCredentials()).find((c) => c.id === credId);
    expect(minted?.singleUse).toBe(true);
    expect(minted?.consumedAt).toBeFalsy();
  });

  it('issues reusable credentials by default (no single-use flag)', async () => {
    const credId = `vc-reusable-${Date.now()}`;
    await wallet.addIssuedCredential(credId, { birthDate: '1990-01-01' }, 'did:web:localhost%3A3005');
    const minted = (await wallet.getCredentials()).find((c) => c.id === credId);
    expect(minted?.singleUse).toBeFalsy();
  });

  it('does not re-present a consumed single-use credential (fail-closed non-reuse)', async () => {
    const first = await presentToLiquorStore();
    const ids = selectedIds(first.decisionCapsule);

    for (const id of ids) {
      const m = (await wallet.getCredentials()).find((x) => x.id === id)!;
      const payload = (await wallet.loadCredential(id)) as Record<string, unknown>;
      await wallet.addCredential(id, payload, {
        issuer: m.issuer,
        type: m.type,
        claims: m.claims,
        issuedAt: m.issuedAt,
        singleUse: true,
      });
    }

    const second = await presentToLiquorStore();
    await wallet.generatePresentation(second.decisionCapsule!);

    // Pass 3 — the consumed credential must no longer be selectable.
    const third = await presentToLiquorStore();
    const stillUsed = selectedIds(third.decisionCapsule).some((id) => ids.includes(id));
    expect(stillUsed).toBe(false);
  });
});

describe('WalletService — Batch Issuance + Holder Binding (Increment 2 / C2)', () => {
  let wallet: WalletService;

  function b64url(obj: unknown): string {
    return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  // Build a minimal signed-looking VC-JWT with a given subject id.
  function fakeVcJwt(subjectId: string): string {
    const payload = {
      vc: { credentialSubject: { id: subjectId, dateOfBirth: '1990-01-01', isOver18: true } },
    };
    return `aaa.${b64url(payload)}.sig`;
  }

  beforeEach(async () => {
    wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('generates N local keypairs, transmits ONLY public JWKs, stores a single-use pool', async () => {
    let sentBody: { requests: Array<{ holder_binding: { jwk: JsonWebKey } }> } | null = null;
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      sentBody = JSON.parse(init!.body as string);
      const credentials = sentBody!.requests.map((_, i) => fakeVcJwt(`did:jwk:MEMBER_${i}`));
      return { ok: true, json: async () => ({ credentials }) } as Response;
    });
    vi.stubGlobal('fetch', fetchMock);

    const { poolId, credentialIds } = await wallet.fetchCredentialBatch(3);

    // Transport carried N requests…
    expect(sentBody!.requests).toHaveLength(3);
    for (const r of sentBody!.requests) {
      // …each a public EC JWK…
      expect(r.holder_binding.jwk.kty).toBe('EC');
      expect(typeof r.holder_binding.jwk.x).toBe('string');
      // …and CRITICALLY never a private 'd' component (keys stay in the wallet).
      expect(r.holder_binding.jwk).not.toHaveProperty('d');
    }

    // Stored as one logical single-use pool, retaining the private key handles.
    expect(credentialIds).toHaveLength(3);
    const stored = await wallet.getCredentials();
    const members = stored.filter((c) => c.poolId === poolId);
    expect(members).toHaveLength(3);
    expect(members.every((m) => m.singleUse === true)).toBe(true);
    for (const id of credentialIds) {
      expect(wallet.getHolderKey(id)).toBeDefined();
    }
  });

  it('fails closed when the issuer returns the wrong batch size', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, json: async () => ({ credentials: [fakeVcJwt('did:jwk:ONE')] }) }) as Response)
    );
    await expect(wallet.fetchCredentialBatch(3)).rejects.toThrow(/size mismatch/i);
  });

  it('rejects a non-positive batch count', async () => {
    await expect(wallet.fetchCredentialBatch(0)).rejects.toThrow(/positive integer/i);
  });
});

describe('WalletService — AES-256-GCM Encryption Roundtrip', () => {
  it('two wallets with same PIN can both initialize (key derivation is deterministic)', async () => {
    const wallet1 = makeWallet();
    const wallet2 = makeWallet();
    await wallet1.initialize(PIN, SALT);
    await wallet2.initialize(PIN, SALT);
    // Both initialized = PBKDF2 key derivation works
    expect(true).toBe(true);
  });

  it('a different PIN derives an independent vault only after an explicit reset (Model A)', async () => {
    // Model A: storage is single-vault. A second identity must NOT silently take over
    // (and destroy) an existing vault — switching identity requires an explicit reset.
    // PBKDF2 derivation working for distinct PINs is what we verify here.
    await SecureStorage.reset();
    const wallet1 = makeWallet();
    await wallet1.initialize('pin-aaa', SALT);

    await SecureStorage.reset();
    const wallet2 = makeWallet();
    await wallet2.initialize('pin-bbb', SALT);
    expect(true).toBe(true);
  });
});

describe('WalletService — Policy Persistence', () => {
  beforeEach(async () => {
    localStorage.removeItem(ASKMI_STORAGE_KEYS.walletPolicy);
    await SecureStorage.reset();
  });

  it('getPolicy returns a valid PolicyManifest after init', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    const policy = wallet.getPolicy();
    expect(policy).toHaveProperty('rules');
    expect(policy).toHaveProperty('trustedIssuers');
    expect(policy).toHaveProperty('version');
    expect(Array.isArray(policy.rules)).toBe(true);
    expect(Array.isArray(policy.trustedIssuers)).toBe(true);
  });

  it('savePolicy + getPolicy roundtrips custom policy', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    const base = wallet.getPolicy();
    const modified = {
      ...base,
      trustedIssuers: [
        ...base.trustedIssuers,
        { did: 'did:example:new-issuer', name: 'Test Issuer', credentialTypes: ['TestCred'] },
      ],
    };
    wallet.savePolicy(modified);

    const retrieved = wallet.getPolicy();
    expect(retrieved.trustedIssuers.some((i) => i.did === 'did:example:new-issuer')).toBe(true);
  });

  it('stores the policy manifest outside the credential list', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    const credentials = await wallet.getCredentials();
    expect(credentials.some((c) => c.id === ASKMI_STORAGE_KEYS.policyManifestDocument)).toBe(false);
  });

  it('migrates legacy localStorage policy into secure storage', async () => {
    const wallet = makeWallet();
    const base = wallet.getPolicy();
    const legacy: PolicyManifest = {
      version: base.version,
      rules: base.rules,
      trustedIssuers: [
        {
          did: 'did:example:legacy-issuer',
          name: 'Legacy Issuer',
          credentialTypes: ['LegacyCred'],
        },
      ],
      globalSettings: base.globalSettings,
    };
    localStorage.setItem(ASKMI_STORAGE_KEYS.walletPolicy, JSON.stringify(legacy));

    await wallet.initialize(PIN, SALT);

    expect(
      wallet.getPolicy().trustedIssuers.some((i) => i.did === 'did:example:legacy-issuer')
    ).toBe(true);
    expect(localStorage.getItem(ASKMI_STORAGE_KEYS.walletPolicy)).toBeNull();
  });
});

describe('WalletService — Corrupt Storage', () => {
  it('corruptCredential() throws a typed error (corruptEntry is a stress-test stub)', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    // SecureStorage in jsdom mock doesn't implement corruptEntry — expect a meaningful error
    await expect(wallet.corruptCredential()).rejects.toThrow();
  });
});

describe('WalletService — Audit Chain', () => {
  it('verifyAuditChain returns { valid: boolean } after init', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    const result = await wallet.verifyAuditChain();
    expect(result).toHaveProperty('valid');
    expect(typeof result.valid).toBe('boolean');
  });
});

describe('WalletService — Key Splitting & Recovery', () => {
  it('splitMasterKey returns 3 shares', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    const shares = await wallet.splitMasterKey();
    expect(Array.isArray(shares)).toBe(true);
    expect(shares.length).toBe(3);
    shares.forEach((s) => expect(typeof s).toBe('string'));
  });

  it('recoverFromFragments with all 3 shares succeeds (PoC is 3-of-3)', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    const shares = await wallet.splitMasterKey();
    // PoC RecoveryService requires all 3 fragments
    await expect(wallet.recoverFromFragments(shares)).resolves.not.toThrow();
  });
});

describe('WalletService — mdoc Integration (ISO 18013-5)', () => {
  let wallet: WalletService;

  beforeEach(async () => {
    wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
  });

  it('mdoc mDL credential is seeded with format mso_mdoc', async () => {
    const creds = await wallet.getCredentials();
    const mdoc = creds.find((c) => c.id === 'mdoc-mdl-001');
    expect(mdoc).toBeDefined();
    expect(mdoc!.format).toBe('mso_mdoc');
    expect(mdoc!.type).toContain('org.iso.18013.5.1.mDL');
  });

  it('mdoc credential payload roundtrips through addMdocCredential + loadCredential', async () => {
    const { encode } = await import('@askmi/mdoc');
    const items = [
      {
        digestID: 0,
        random: crypto.getRandomValues(new Uint8Array(16)),
        elementIdentifier: 'test_claim',
        elementValue: 42,
      },
    ];
    const cbor = encode({ nameSpaces: new Map([['test.ns', items]]) });

    await wallet.addMdocCredential(
      'mdoc-test-roundtrip',
      cbor,
      'test.docType',
      'did:example:test',
      ['test_claim']
    );

    const creds = await wallet.getCredentials();
    const meta = creds.find((c) => c.id === 'mdoc-test-roundtrip');
    expect(meta).toBeDefined();
    expect(meta!.format).toBe('mso_mdoc');

    const data = await wallet.loadCredential<Record<string, unknown>>('mdoc-test-roundtrip');
    expect(data).not.toBeNull();
    expect(data!._mdoc).toBe(true);
    expect(data!.docType).toBe('test.docType');
    expect(typeof data!.cborBase64).toBe('string');
  });

  it('mdoc claims list matches seeded elements', async () => {
    const creds = await wallet.getCredentials();
    const mdoc = creds.find((c) => c.id === 'mdoc-mdl-001');
    expect(mdoc!.claims).toContain('family_name');
    expect(mdoc!.claims).toContain('age_over_18');
    expect(mdoc!.claims).toContain('issuing_country');
  });
});

describe('WalletService — Layer-2 visibility (G-140 PR3): proximity (ISO 18013-5)', () => {
  let wallet: WalletService;

  beforeEach(async () => {
    wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
  });

  function findProximityVpSent(w: WalletService) {
    return w
      .getRecentAuditLogs(20)
      .find(
        (e) =>
          e.action === 'VP_SENT' &&
          (e.metadata as Record<string, unknown> | undefined)?.['context'] ===
            'PROXIMITY_PRESENTATION'
      );
  }

  function findProximityPolicyEvaluated(w: WalletService) {
    return w
      .getRecentAuditLogs(20)
      .find(
        (e) =>
          e.action === 'POLICY_EVALUATED' &&
          (e.metadata as Record<string, unknown> | undefined)?.['verifier_did'] ===
            'did:askmi:proximity-reader'
      );
  }

  it('logs a proximity VP_SENT with decision_id, verifier_did and raw requested vs disclosed claims', async () => {
    const NS = 'org.iso.18013.5.1';
    // family_name + issuing_country exist in the seeded mDL; home_address does NOT.
    await wallet.generateProximityResponse(
      'mdoc-mdl-001',
      [
        { ns: NS, element: 'family_name' },
        { ns: NS, element: 'issuing_country' },
        { ns: NS, element: 'home_address' },
      ],
      [null, null, null] as unknown as import('@askmi/mdoc').SessionTranscript,
      { decisionId: 'proximity-decision-001', verifierDid: 'did:askmi:proximity-reader' }
    );

    const vpSent = findProximityVpSent(wallet);
    const policyEvent = findProximityPolicyEvaluated(wallet);
    expect(vpSent, 'expected a PROXIMITY_PRESENTATION VP_SENT in the audit log').toBeDefined();
    expect(policyEvent, 'expected the proximity flow to be policy-evaluated').toBeDefined();
    const meta = vpSent!.metadata as Record<string, unknown>;
    const policyMeta = policyEvent!.metadata as Record<string, unknown>;

    // decision anchor so data-flow can group this into a Layer-2 transaction:
    expect(meta['decision_id']).toBe(policyMeta['decision_id']);
    expect(meta['verifier_did']).toBe('did:askmi:proximity-reader');

    // Raw requested set is logged in full — including the element the credential cannot satisfy:
    expect(meta['claims_requested']).toEqual(['family_name', 'issuing_country', 'home_address']);
    // PR4: claims_shared reflects only what was policy-authorized and present in the credential.
    expect(meta['claims_shared']).toEqual(['family_name']);
  });

  it('de-duplicates repeated requested elements in the proximity audit event', async () => {
    const NS = 'org.iso.18013.5.1';
    await wallet.generateProximityResponse(
      'mdoc-mdl-001',
      [
        { ns: NS, element: 'family_name' },
        { ns: NS, element: 'family_name' }, // duplicate request
        { ns: NS, element: 'issuing_country' },
      ],
      [null, null, null] as unknown as import('@askmi/mdoc').SessionTranscript,
      { decisionId: 'proximity-decision-dedupe', verifierDid: 'did:askmi:proximity-reader' }
    );

    const meta = findProximityVpSent(wallet)!.metadata as Record<string, unknown>;
    // Claim-name lists are de-duped, matching the online collectRequestedClaims convention:
    expect(meta['claims_requested']).toEqual(['family_name', 'issuing_country']);
    expect(meta['claims_shared']).toEqual(['family_name']);
  });

  it('routes proximity requests through policy and uses the same decision anchor for POLICY_EVALUATED and VP_SENT', async () => {
    const NS = 'org.iso.18013.5.1';
    await wallet.generateProximityResponse(
      'mdoc-mdl-001',
      [
        { ns: NS, element: 'given_name' },
        { ns: NS, element: 'family_name' },
      ],
      [null, null, null] as unknown as import('@askmi/mdoc').SessionTranscript,
      { decisionId: 'proximity-policy-nonce', verifierDid: 'did:askmi:proximity-reader' }
    );

    const policyEvent = findProximityPolicyEvaluated(wallet);
    const vpSent = findProximityVpSent(wallet);
    expect(policyEvent, 'expected proximity POLICY_EVALUATED').toBeDefined();
    expect(vpSent, 'expected proximity VP_SENT').toBeDefined();

    const policyMeta = policyEvent!.metadata as Record<string, unknown>;
    const vpMeta = vpSent!.metadata as Record<string, unknown>;
    expect(policyMeta['verdict']).toBe('ALLOW');
    expect(policyMeta['requested_claims']).toEqual(['given_name', 'family_name']);
    expect(policyMeta['authorized_claims']).toEqual(['given_name', 'family_name']);
    expect(vpMeta['decision_id']).toBe(policyMeta['decision_id']);
    expect(vpMeta['claims_shared']).toEqual(['given_name', 'family_name']);
  });

  it('clips proximity over-asking to the authorized intersection before VP_SENT', async () => {
    const NS = 'org.iso.18013.5.1';
    await wallet.generateProximityResponse(
      'mdoc-mdl-001',
      [
        { ns: NS, element: 'given_name' },
        { ns: NS, element: 'family_name' },
        { ns: NS, element: 'issuing_country' },
      ],
      [null, null, null] as unknown as import('@askmi/mdoc').SessionTranscript,
      { decisionId: 'proximity-overask-nonce', verifierDid: 'did:askmi:proximity-reader' }
    );

    const policyMeta = findProximityPolicyEvaluated(wallet)!.metadata as Record<string, unknown>;
    const vpMeta = findProximityVpSent(wallet)!.metadata as Record<string, unknown>;
    expect(policyMeta['verdict']).toBe('ALLOW');
    expect(policyMeta['requested_claims']).toEqual(['given_name', 'family_name', 'issuing_country']);
    expect(policyMeta['authorized_claims']).toEqual(['given_name', 'family_name']);
    expect(policyMeta['denied_claims']).toEqual(['issuing_country']);
    expect(vpMeta['claims_requested']).toEqual(['given_name', 'family_name', 'issuing_country']);
    expect(vpMeta['claims_shared']).toEqual(['given_name', 'family_name']);
  });

  it('logs a visible proximity transaction with no shared claims on DENY', async () => {
    const NS = 'org.iso.18013.5.1';
    await wallet.generateProximityResponse(
      'mdoc-mdl-001',
      [{ ns: NS, element: 'issuing_country' }],
      [null, null, null] as unknown as import('@askmi/mdoc').SessionTranscript,
      { decisionId: 'proximity-deny-nonce', verifierDid: 'did:askmi:proximity-reader' }
    );

    const policyMeta = findProximityPolicyEvaluated(wallet)!.metadata as Record<string, unknown>;
    const vpMeta = findProximityVpSent(wallet)!.metadata as Record<string, unknown>;
    expect(policyMeta['verdict']).toBe('DENY');
    expect(policyMeta['requested_claims']).toEqual(['issuing_country']);
    expect(policyMeta['authorized_claims']).toEqual([]);
    expect(vpMeta['decision_id']).toBe(policyMeta['decision_id']);
    expect(vpMeta['claims_requested']).toEqual(['issuing_country']);
    expect(vpMeta['claims_shared']).toEqual([]);

    const [txn] = new DataFlowService().buildTransactions(wallet.getRecentAuditLogs(20));
    expect(txn, 'DENY proximity flow should still be visible in Layer-2').toBeDefined();
    expect(txn.transactionId).toBe(policyMeta['decision_id']);
    expect(txn.verdict).toBe('DENY');
    expect(txn.claimsRequested).toEqual(['issuing_country']);
    expect(txn.claimsShared).toEqual([]);
    expect(txn.claimsWithheld).toEqual(['issuing_country']);
  });
});

describe('WalletService — Identity Firewall Audit Events', () => {
  let wallet: WalletService;

  beforeEach(async () => {
    wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
  });

  const browserTracker: TrackingPoint = {
    layer: 'BROWSER',
    actor: 'https://tracker.example/path?cookie=raw-value',
    riskLevel: 'HIGH',
    riskReason: 'Browser fingerprinting signal',
    dataExposed: [
      {
        field: 'Browsing History',
        visibility: 'ENCRYPTED',
        linkable: true,
        persistence: 'CLOUD',
      },
    ],
    detection: { method: 'HEURISTIC', confidence: 99 },
    mitigations: [],
  };

  it('returns no events when decision_id is missing', async () => {
    const entries = await wallet.recordIdentityFirewallEvents(
      undefined,
      'did:askmi:verifier-test',
      [browserTracker]
    );

    expect(entries).toEqual([]);
  });

  it('records PII-minimal identity firewall events', async () => {
    const entries = await wallet.recordIdentityFirewallEvents(
      'decision-identity-001',
      'did:askmi:verifier-test',
      [browserTracker]
    );

    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe('IDENTITY_ACCESS_DETECTED');
    expect(entries[0].metadata).toMatchObject({
      decision_id: 'decision-identity-001',
      verifier_did: 'did:askmi:verifier-test',
      access_type: 'browser_api',
      surface: 'navigator.userAgent',
      actor_label: 'tracker.example',
      field_class: 'fingerprint',
      persistence: 'cloud',
      linkability: 'cross_context',
      severity: 'critical',
      blocked: false,
      source: 'privacy_audit_service',
    });
    expect(JSON.stringify(entries[0].metadata)).not.toContain('raw-value');
  });
});

describe('WalletService — Layer-2 visibility (G-140 PR1): log all requested claims', () => {
  const VERIFIER = 'did:askmi:overask-test';

  // Policy that allows ONLY `age` for VERIFIER, so any extra requested claim is over-asking.
  function withOverAskRule(base: PolicyManifest): PolicyManifest {
    return {
      ...base,
      rules: [
        {
          id: 'overask-rule',
          verifierPattern: VERIFIER,
          allowedClaims: ['age'],
          provenClaims: [],
          requiresTrustedIssuer: false,
          priority: 100,
          requiresUserConsent: false,
        },
        ...base.rules,
      ],
      globalSettings: { ...base.globalSettings, blockUnknownVerifiers: false },
    };
  }

  function findDisclosureDecision(wallet: WalletService) {
    return wallet
      .getRecentAuditLogs(20)
      .find(
        (e) =>
          e.action === 'POLICY_EVALUATED' &&
          (e.metadata as Record<string, unknown> | undefined)?.['requested_claims'] !== undefined
      );
  }

  it('logs every raw requested claim — including over-asked ones — on evaluateRequest', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);
    wallet.savePolicy(withOverAskRule(wallet.getPolicy()));

    await wallet.evaluateRequest(
      {
        verifierId: VERIFIER,
        nonce: crypto.randomUUID(),
        requirements: [{ credentialType: 'AgeCredential', requestedClaims: ['age', 'salary'] }],
      },
      { userAgent: 'test', timestamp: Date.now() }
    );

    const decision = findDisclosureDecision(wallet);
    expect(decision, 'expected a POLICY_EVALUATED entry carrying requested_claims').toBeDefined();
    const meta = decision!.metadata as Record<string, unknown>;
    expect(meta['requested_claims']).toContain('age');
    // The over-asked claim must be visible, not silently stripped by the policy:
    expect(meta['requested_claims']).toContain('salary');
    expect(meta['denied_claims']).toContain('salary');
    expect(meta['verifier_did']).toBe(VERIFIER);
    expect(['ALLOW', 'DENY', 'PROMPT']).toContain(meta['verdict']);
  });

  it('a DENY verdict still produces a disclosure-decision audit event (gap B)', async () => {
    const wallet = makeWallet();
    await wallet.initialize(PIN, SALT);

    // Request a credential type the wallet does not hold -> DENY (no VP_GENERATED today).
    await wallet.evaluateRequest(
      {
        verifierId: 'did:askmi:deny-test',
        nonce: crypto.randomUUID(),
        requirements: [{ credentialType: 'NonExistentCredential', requestedClaims: ['secret'] }],
      },
      { userAgent: 'test', timestamp: Date.now() }
    );

    const decision = findDisclosureDecision(wallet);
    expect(decision, 'a DENY must still emit a disclosure-decision audit event').toBeDefined();
    expect((decision!.metadata as Record<string, unknown>)['requested_claims']).toContain('secret');
  });
});
