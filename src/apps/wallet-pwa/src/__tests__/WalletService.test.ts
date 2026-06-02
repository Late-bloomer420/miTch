import { describe, it, expect, beforeEach, vi } from 'vitest';
import { WalletService } from '@mitch/wallet-core';
import type { TrackingPoint } from '../services/PrivacyAuditService';

// Mock localStorage
const mockLocalStorage = {
    getItem: vi.fn(),
    setItem: vi.fn(),
    clear: vi.fn()
};
vi.stubGlobal('localStorage', mockLocalStorage);

// Mock @mitch/audit-log to avoid IndexedDB issues in JSDOM
vi.mock('@mitch/audit-log', () => {
    return {
        AuditLog: function() {
            return {
                initialize: vi.fn().mockResolvedValue(undefined),
                setAuditKeys: vi.fn(),
                append: vi.fn().mockResolvedValue({ id: 'log-1', action: 'IDENTITY_ACCESS_DETECTED' }),
                getRecentEntries: vi.fn().mockReturnValue([]),
            };
        }
    };
});

async function makeWallet() {
  return await WalletService.createBrowserWallet('test-pin', 'test-salt');
}

describe('WalletService — Initialization', () => {
  it('initializes without throwing', async () => {
    const wallet = await makeWallet();
    await expect(wallet.initialize()).resolves.not.toThrow();
  });

  it('second initialize() call is a no-op (idempotent)', async () => {
    const wallet = await makeWallet();
    await wallet.initialize();
    await expect(wallet.initialize()).resolves.not.toThrow();
  });
});

describe('WalletService — High Level API', () => {
  let wallet: WalletService;

  beforeEach(async () => {
    wallet = await makeWallet();
    // Mock policy for getPolicy()
    mockLocalStorage.getItem.mockReturnValue(JSON.stringify({
        version: '1.0',
        trustedIssuers: [],
        rules: []
    }));
    await wallet.initialize();
  });

  it('getPolicy returns a valid PolicyManifest after init', () => {
    const policy = wallet.getPolicy();
    expect(policy).toHaveProperty('rules');
    expect(policy).toHaveProperty('trustedIssuers');
  });

  it('getRecentAuditLogs returns entries', async () => {
    const logs = wallet.getRecentAuditLogs(10);
    expect(Array.isArray(logs)).toBe(true);
  });

  it('splitMasterKey returns mock shares', async () => {
    const shares = await wallet.splitMasterKey();
    expect(shares).toHaveLength(3);
  });

  it('records identity firewall events', async () => {
    const tracker: TrackingPoint = {
        layer: 'BROWSER',
        actor: 'https://tracker.example',
        riskLevel: 'HIGH',
        riskReason: 'test',
        dataExposed: [],
        detection: { method: 'HEURISTIC', confidence: 99 },
        mitigations: []
    };

    const entries = await wallet.recordIdentityFirewallEvents(
        'decision-123',
        'did:mitch:verifier',
        [tracker]
    );

    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe('IDENTITY_ACCESS_DETECTED');
  });
});
