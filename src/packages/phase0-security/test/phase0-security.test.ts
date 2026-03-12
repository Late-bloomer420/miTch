/**
 * Phase-0 Security Package Tests
 *
 * Covers:
 * - SplitKeyProtection: GF(2^8) Shamir 2-of-3 SSS
 * - UserDerivedKeyProtection: PBKDF2-600k key derivation
 * - PanicGuard: Emergency wipe
 * - GoogleAppleBypass: Platform trust
 * - VerifierDirectProtocol: Deep link + submission
 * - LocalAuditLog: Hash-chained encrypted audit log (via fake-indexeddb)
 * - EIDASComplianceChecker: 7-point compliance checks
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import FDBFactory from 'fake-indexeddb/lib/FDBFactory';
import FDBKeyRange from 'fake-indexeddb/lib/FDBKeyRange';

// Polyfill IndexedDB globals for Node
(globalThis as any).indexedDB = new FDBFactory();
(globalThis as any).IDBKeyRange = FDBKeyRange;
(globalThis as any).IDBFactory = FDBFactory;

import {
    SplitKeyProtection,
    UserDerivedKeyProtection,
    PanicGuard,
    GoogleAppleBypass,
} from '../src/ADVANCED_SECURITY_HARDENING.js';
import { VerifierDirectProtocol, DIRECT_VERIFIER_DID } from '../src/VerifierDirectProtocol.js';
import { LocalAuditLog } from '../src/LocalAuditLog.js';
import { EIDASComplianceChecker, ComplianceStatus } from '../src/EIDASComplianceChecker.js';

// ─── SplitKeyProtection ──────────────────────────────────────────────────────

describe('SplitKeyProtection — GF(2^8) Shamir 2-of-3', () => {
    it('reconstructs secret from shares 0+1', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const shares = await SplitKeyProtection.splitKey(secret);
        expect(shares).toHaveLength(3);
        const recovered = await SplitKeyProtection.reconstructKey([shares[0], shares[1]]);
        expect(recovered).toEqual(secret);
    });

    it('reconstructs secret from shares 0+2', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const shares = await SplitKeyProtection.splitKey(secret);
        const recovered = await SplitKeyProtection.reconstructKey([shares[0], shares[2]]);
        expect(recovered).toEqual(secret);
    });

    it('reconstructs secret from shares 1+2', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const shares = await SplitKeyProtection.splitKey(secret);
        const recovered = await SplitKeyProtection.reconstructKey([shares[1], shares[2]]);
        expect(recovered).toEqual(secret);
    });

    it('share x-coordinates are 1, 2, 3', async () => {
        const secret = new Uint8Array(16).fill(0xab);
        const shares = await SplitKeyProtection.splitKey(secret);
        expect(shares[0][0]).toBe(1);
        expect(shares[1][0]).toBe(2);
        expect(shares[2][0]).toBe(3);
    });

    it('each share has length secret.length + 1', async () => {
        const secret = crypto.getRandomValues(new Uint8Array(16));
        const shares = await SplitKeyProtection.splitKey(secret);
        for (const share of shares) {
            expect(share.length).toBe(17);
        }
    });

    it('shares differ from each other (non-trivial splitting)', async () => {
        const secret = new Uint8Array(8).fill(0xff);
        const shares = await SplitKeyProtection.splitKey(secret);
        // Shares should not equal each other (unless a1 is all zeros, astronomically unlikely)
        const s0Data = shares[0].slice(1);
        const s1Data = shares[1].slice(1);
        // They should differ in at least 1 byte given random a1
        // (Accept if they happen to be equal, but vanishingly rare)
        expect(s0Data).not.toEqual(s1Data);
    });

    it('recovers AES-256 key material (32 bytes)', async () => {
        const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
        const shares = await SplitKeyProtection.splitKey(keyMaterial);
        const recovered01 = await SplitKeyProtection.reconstructKey([shares[0], shares[1]]);
        const recovered12 = await SplitKeyProtection.reconstructKey([shares[1], shares[2]]);
        expect(recovered01).toEqual(keyMaterial);
        expect(recovered12).toEqual(keyMaterial);
    });

    it('throws when fewer than 2 shares provided', async () => {
        const secret = new Uint8Array(8);
        const shares = await SplitKeyProtection.splitKey(secret);
        await expect(SplitKeyProtection.reconstructKey([shares[0]])).rejects.toThrow();
    });

    it('all-zero secret splits and reconstructs correctly', async () => {
        const secret = new Uint8Array(16); // all zeros
        const shares = await SplitKeyProtection.splitKey(secret);
        const recovered = await SplitKeyProtection.reconstructKey([shares[0], shares[1]]);
        expect(recovered).toEqual(secret);
    });

    it('all-ones secret splits and reconstructs correctly', async () => {
        const secret = new Uint8Array(16).fill(0xff);
        const shares = await SplitKeyProtection.splitKey(secret);
        const recovered = await SplitKeyProtection.reconstructKey([shares[0], shares[2]]);
        expect(recovered).toEqual(secret);
    });

    it('produces different shares across calls (random a1)', async () => {
        const secret = new Uint8Array(16).fill(0x42);
        const sharesA = await SplitKeyProtection.splitKey(secret);
        const sharesB = await SplitKeyProtection.splitKey(secret);
        // x-coordinates are deterministic (1,2,3) but y-values should differ
        expect(sharesA[0].slice(1)).not.toEqual(sharesB[0].slice(1));
    });
});

// ─── UserDerivedKeyProtection ────────────────────────────────────────────────

describe('UserDerivedKeyProtection — PBKDF2', () => {
    it('returns a non-extractable AES-GCM CryptoKey', async () => {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await UserDerivedKeyProtection.deriveKeyFromUser('password123', salt);
        expect(key.type).toBe('secret');
        expect(key.algorithm.name).toBe('AES-GCM');
        expect(key.extractable).toBe(false);
    });

    it('key can encrypt and decrypt data', async () => {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await UserDerivedKeyProtection.deriveKeyFromUser('my-pin', salt);
        const plaintext = new TextEncoder().encode('secret data');
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            plaintext,
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext,
        );

        expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });

    it('same password + salt → same key material (deterministic)', async () => {
        const salt = new Uint8Array(16).fill(0x11);
        const k1 = await UserDerivedKeyProtection.deriveKeyFromUser('same-pin', salt);
        const k2 = await UserDerivedKeyProtection.deriveKeyFromUser('same-pin', salt);

        // Both keys are non-extractable; verify by encrypting with k1 and decrypting with k2
        const iv = new Uint8Array(12).fill(0xaa);
        const plaintext = new TextEncoder().encode('hello');
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k1, plaintext);
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k2, ct);
        expect(new Uint8Array(pt)).toEqual(plaintext);
    });

    it('different password → different key (cannot decrypt)', async () => {
        const salt = new Uint8Array(16).fill(0x22);
        const k1 = await UserDerivedKeyProtection.deriveKeyFromUser('pin-A', salt);
        const k2 = await UserDerivedKeyProtection.deriveKeyFromUser('pin-B', salt);
        const iv = new Uint8Array(12).fill(0xbb);
        const ct = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            k1,
            new TextEncoder().encode('data'),
        );
        await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k2, ct)).rejects.toThrow();
    });

    it('different salt → different key', async () => {
        const saltA = new Uint8Array(16).fill(0x33);
        const saltB = new Uint8Array(16).fill(0x44);
        const k1 = await UserDerivedKeyProtection.deriveKeyFromUser('same-pin', saltA);
        const k2 = await UserDerivedKeyProtection.deriveKeyFromUser('same-pin', saltB);
        const iv = new Uint8Array(12).fill(0xcc);
        const ct = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            k1,
            new TextEncoder().encode('data'),
        );
        await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k2, ct)).rejects.toThrow();
    });

    it('accepts unicode password', async () => {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await UserDerivedKeyProtection.deriveKeyFromUser('Ö𝄞🔑€', salt);
        expect(key.type).toBe('secret');
    });
});

// ─── PanicGuard ──────────────────────────────────────────────────────────────

describe('PanicGuard.shredEverything', () => {
    it('clears localStorage', async () => {
        // Set up storage
        if (typeof globalThis.localStorage === 'undefined') {
            (globalThis as any).localStorage = {
                _data: {} as Record<string, string>,
                clear() { this._data = {}; },
                getItem(k: string) { return this._data[k] ?? null; },
                setItem(k: string, v: string) { this._data[k] = v; },
            };
        }
        if (typeof globalThis.sessionStorage === 'undefined') {
            (globalThis as any).sessionStorage = {
                _data: {} as Record<string, string>,
                clear() { this._data = {}; },
                getItem(k: string) { return this._data[k] ?? null; },
                setItem(k: string, v: string) { this._data[k] = v; },
            };
        }

        globalThis.localStorage.setItem('sensitive', 'value');
        globalThis.sessionStorage.setItem('session-token', 'abc');

        await PanicGuard.shredEverything();

        expect(globalThis.localStorage.getItem('sensitive')).toBeNull();
        expect(globalThis.sessionStorage.getItem('session-token')).toBeNull();
    });

    it('completes without throwing even if indexedDB.databases is unavailable', async () => {
        // indexedDB may not have .databases() in some environments
        const orig = globalThis.indexedDB;
        (globalThis as any).indexedDB = {}; // no .databases property
        await expect(PanicGuard.shredEverything()).resolves.toBeUndefined();
        (globalThis as any).indexedDB = orig;
    });

    it('returns void', async () => {
        const result = await PanicGuard.shredEverything();
        expect(result).toBeUndefined();
    });
});

// ─── GoogleAppleBypass ───────────────────────────────────────────────────────

describe('GoogleAppleBypass', () => {
    it('isPlatformTrusted returns true', () => {
        expect(GoogleAppleBypass.isPlatformTrusted()).toBe(true);
    });
});

// ─── VerifierDirectProtocol ──────────────────────────────────────────────────

describe('VerifierDirectProtocol.createDirectSession', () => {
    it('returns a valid session with sessionId, deepLink, verifierEndpoint', async () => {
        const protocol = new VerifierDirectProtocol();
        const session = await protocol.createDirectSession();
        expect(session.sessionId).toMatch(/^[0-9a-f-]{36}$/);
        expect(session.deepLink).toMatch(/^mitch:\/\/present\?/);
        expect(session.verifierEndpoint).toContain('/present/');
        expect(session.verifierEndpoint).toContain(session.sessionId);
    });

    it('deep link contains verifier DID', async () => {
        const protocol = new VerifierDirectProtocol();
        const session = await protocol.createDirectSession();
        expect(session.deepLink).toContain(encodeURIComponent(DIRECT_VERIFIER_DID));
    });

    it('deep link contains nonce', async () => {
        const protocol = new VerifierDirectProtocol();
        const session = await protocol.createDirectSession();
        const url = new URL(session.deepLink.replace('mitch://', 'https://x/'));
        const nonce = url.searchParams.get('nonce');
        expect(nonce).toBeTruthy();
        expect(nonce!.length).toBeGreaterThan(10);
    });

    it('deep link contains claims', async () => {
        const protocol = new VerifierDirectProtocol();
        const session = await protocol.createDirectSession();
        const url = new URL(session.deepLink.replace('mitch://', 'https://x/'));
        const claims = url.searchParams.get('claims');
        expect(claims).toBeTruthy();
        const parsed = JSON.parse(claims!);
        expect(parsed).toContain('age');
    });

    it('each session has a unique sessionId', async () => {
        const protocol = new VerifierDirectProtocol();
        const s1 = await protocol.createDirectSession();
        const s2 = await protocol.createDirectSession();
        expect(s1.sessionId).not.toBe(s2.sessionId);
    });

    it('accepts custom base URL', async () => {
        const protocol = new VerifierDirectProtocol('https://verifier.example.com');
        const session = await protocol.createDirectSession();
        expect(session.verifierEndpoint).toContain('https://verifier.example.com/present/');
    });

    it('callback param in deep link matches verifierEndpoint', async () => {
        const protocol = new VerifierDirectProtocol();
        const session = await protocol.createDirectSession();
        const url = new URL(session.deepLink.replace('mitch://', 'https://x/'));
        const callback = url.searchParams.get('callback');
        expect(callback).toBe(session.verifierEndpoint);
    });
});

describe('VerifierDirectProtocol.submitDirectPresentation', () => {
    it('returns true on successful HTTP POST', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ verified: true }),
        });
        (globalThis as any).fetch = mockFetch;

        const protocol = new VerifierDirectProtocol();
        const result = await protocol.submitDirectPresentation(
            { vp_token: 'token', presentation_submission: {} },
            'https://verifier.example/present/abc',
        );
        expect(result).toBe(true);
        expect(mockFetch).toHaveBeenCalledOnce();
        expect(mockFetch.mock.calls[0][0]).toBe('https://verifier.example/present/abc');
    });

    it('returns false when server returns non-ok status', async () => {
        (globalThis as any).fetch = vi.fn().mockResolvedValue({
            ok: false,
            statusText: 'Forbidden',
        });
        const protocol = new VerifierDirectProtocol();
        const result = await protocol.submitDirectPresentation({}, 'https://x/present/y');
        expect(result).toBe(false);
    });

    it('returns false on network error', async () => {
        (globalThis as any).fetch = vi.fn().mockRejectedValue(new Error('Network Error'));
        const protocol = new VerifierDirectProtocol();
        const result = await protocol.submitDirectPresentation({}, 'https://x/present/y');
        expect(result).toBe(false);
    });

    it('posts JSON Content-Type header', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
        (globalThis as any).fetch = mockFetch;
        const protocol = new VerifierDirectProtocol();
        await protocol.submitDirectPresentation({ test: true }, 'https://x/present/y');
        const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
        expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
    });

    it('posts the vp as JSON body', async () => {
        const vp = { vp_token: 'my-token', id: 42 };
        const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
        (globalThis as any).fetch = mockFetch;
        const protocol = new VerifierDirectProtocol();
        await protocol.submitDirectPresentation(vp, 'https://x/present/y');
        const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
        expect(JSON.parse(init.body as string)).toEqual(vp);
    });
});

// ─── LocalAuditLog ───────────────────────────────────────────────────────────

describe('LocalAuditLog', () => {
    // Each test gets a fresh IndexedDB via fake-indexeddb re-instantiation
    let log: LocalAuditLog;

    beforeEach(() => {
        // Reset IndexedDB to a fresh instance for each test
        (globalThis as any).indexedDB = new FDBFactory();
        log = new LocalAuditLog();
    });

    it('initializes without throwing', async () => {
        await expect(log.initialize()).resolves.toBeUndefined();
    });

    it('initializing twice is idempotent', async () => {
        await log.initialize();
        await expect(log.initialize()).resolves.toBeUndefined();
    });

    it('appends a single entry with sequence=1 and GENESIS_HASH prevHash', async () => {
        const entry = await log.append({
            timestamp: Date.now(),
            action: 'CREDENTIAL_PRESENTED',
            verifier: 'did:web:shop.test',
            verdict: 'ALLOW',
        });
        expect(entry.sequence).toBe(1);
        expect(entry.prevHash).toBe('GENESIS_HASH');
        expect(entry.hash).toHaveLength(64); // SHA-256 hex
        expect(entry.action).toBe('CREDENTIAL_PRESENTED');
    });

    it('sequences increment correctly', async () => {
        const e1 = await log.append({ timestamp: 1, action: 'KEY_GENERATED' });
        const e2 = await log.append({ timestamp: 2, action: 'CREDENTIAL_ISSUED' });
        const e3 = await log.append({ timestamp: 3, action: 'KEY_DESTROYED' });
        expect(e1.sequence).toBe(1);
        expect(e2.sequence).toBe(2);
        expect(e3.sequence).toBe(3);
    });

    it('each entry prevHash matches previous entry hash (chain)', async () => {
        const e1 = await log.append({ timestamp: 1, action: 'A' });
        const e2 = await log.append({ timestamp: 2, action: 'B' });
        const e3 = await log.append({ timestamp: 3, action: 'C' });
        expect(e2.prevHash).toBe(e1.hash);
        expect(e3.prevHash).toBe(e2.hash);
    });

    it('verifyIntegrity returns valid for empty log', async () => {
        await log.initialize();
        const result = await log.verifyIntegrity();
        expect(result.valid).toBe(true);
    });

    it('verifyIntegrity returns valid after appending entries', async () => {
        await log.append({ timestamp: 1, action: 'A' });
        await log.append({ timestamp: 2, action: 'B' });
        const result = await log.verifyIntegrity();
        expect(result.valid).toBe(true);
    });

    it('getAllEntries returns appended entries in order', async () => {
        await log.append({ timestamp: 100, action: 'CREDENTIAL_PRESENTED', verdict: 'ALLOW' });
        await log.append({ timestamp: 200, action: 'POLICY_EVALUATED', verdict: 'DENY' });
        const entries = await log.getAllEntries();
        expect(entries).toHaveLength(2);
        expect(entries[0].action).toBe('CREDENTIAL_PRESENTED');
        expect(entries[1].action).toBe('POLICY_EVALUATED');
    });

    it('exportForUser returns entries and integrity proof', async () => {
        await log.append({ timestamp: 1000, action: 'KEY_GENERATED' });
        const exported = await log.exportForUser();
        expect(exported.entries).toHaveLength(1);
        expect(exported.integrityProof.totalEntries).toBe(1);
        expect(exported.integrityProof.rootHash).toHaveLength(64);
        expect(exported.integrityProof.firstTimestamp).toBe(1000);
        expect(exported.integrityProof.lastTimestamp).toBe(1000);
    });

    it('exportForUser on empty log returns genesis hash', async () => {
        await log.initialize();
        const exported = await log.exportForUser();
        expect(exported.entries).toHaveLength(0);
        expect(exported.integrityProof.rootHash).toBe('GENESIS_HASH');
        expect(exported.integrityProof.totalEntries).toBe(0);
    });

    it('deleteAll clears all entries', async () => {
        await log.append({ timestamp: 1, action: 'A' });
        await log.append({ timestamp: 2, action: 'B' });
        await log.deleteAll();
        const entries = await log.getAllEntries();
        expect(entries).toHaveLength(0);
    });

    it('can append after deleteAll', async () => {
        await log.append({ timestamp: 1, action: 'A' });
        await log.deleteAll();
        const e = await log.append({ timestamp: 2, action: 'B' });
        expect(e.sequence).toBe(1); // restarted
        expect(e.prevHash).toBe('GENESIS_HASH');
    });
});

// ─── EIDASComplianceChecker ──────────────────────────────────────────────────

describe('EIDASComplianceChecker', () => {
    let log: LocalAuditLog;
    let checker: EIDASComplianceChecker;

    beforeEach(() => {
        (globalThis as any).indexedDB = new FDBFactory();
        (globalThis as any).IDBFactory = FDBFactory;
        log = new LocalAuditLog();
        checker = new EIDASComplianceChecker(log);
    });

    it('runChecks returns 7 checks', async () => {
        const report = await checker.runChecks({
            keyProtection: 'SOFTWARE_EPHEMERAL',
            auditLogLocation: 'LOCAL_INDEXEDDB',
        });
        expect(report.checks).toHaveLength(7);
    });

    it('all checks pass with valid config', async () => {
        const report = await checker.runChecks({
            keyProtection: 'SOFTWARE_EPHEMERAL',
            auditLogLocation: 'LOCAL_INDEXEDDB',
        });
        expect(report.status).toBe(ComplianceStatus.PASS);
        for (const check of report.checks) {
            expect(check.result).not.toBe(ComplianceStatus.FAIL);
        }
    });

    it('STRUCTURAL_NON_EXISTENCE check warns when remoteVerifierUrl is set', async () => {
        const report = await checker.runChecks({
            keyProtection: 'SOFTWARE_EPHEMERAL',
            remoteVerifierUrl: 'https://verifier.example.com',
        });
        const snCheck = report.checks.find(c => c.id === 'STRUCTURAL_NON_EXISTENCE');
        expect(snCheck?.result).toBe(ComplianceStatus.WARN);
    });

    it('STRUCTURAL_NON_EXISTENCE check warns when remoteLoggerUrl is set', async () => {
        const report = await checker.runChecks({
            keyProtection: 'SOFTWARE_EPHEMERAL',
            remoteLoggerUrl: 'https://logger.example.com',
        });
        const snCheck = report.checks.find(c => c.id === 'STRUCTURAL_NON_EXISTENCE');
        expect(snCheck?.result).toBe(ComplianceStatus.WARN);
    });

    it('KEY_EPHEMERALITY check warns when keyProtection is not SOFTWARE_EPHEMERAL', async () => {
        const report = await checker.runChecks({
            keyProtection: 'HARDWARE_SECURE_ELEMENT',
        });
        const keyCheck = report.checks.find(c => c.id === 'KEY_EPHEMERALITY');
        expect(keyCheck?.result).toBe(ComplianceStatus.WARN);
    });

    it('DATA_PORTABILITY check passes (getAllEntries function exists)', async () => {
        const report = await checker.runChecks({ keyProtection: 'SOFTWARE_EPHEMERAL' });
        const portabilityCheck = report.checks.find(c => c.id === 'DATA_PORTABILITY');
        expect(portabilityCheck?.result).toBe(ComplianceStatus.PASS);
    });

    it('AUDIT_ACCESS check passes when IDB is available', async () => {
        const report = await checker.runChecks({ keyProtection: 'SOFTWARE_EPHEMERAL' });
        const auditCheck = report.checks.find(c => c.id === 'AUDIT_ACCESS');
        expect(auditCheck?.result).toBe(ComplianceStatus.PASS);
    });

    it('overall status is WARN when any check warns', async () => {
        const report = await checker.runChecks({
            keyProtection: 'HARDWARE', // triggers KEY_EPHEMERALITY WARN
        });
        expect(report.status).toBe(ComplianceStatus.WARN);
    });

    it('PROCESSING_RECORD check includes entry count in details', async () => {
        await log.append({ timestamp: Date.now(), action: 'CREDENTIAL_PRESENTED' });
        const report = await checker.runChecks({ keyProtection: 'SOFTWARE_EPHEMERAL' });
        const procCheck = report.checks.find(c => c.id === 'PROCESSING_RECORD');
        expect(procCheck?.result).toBe(ComplianceStatus.PASS);
        expect(procCheck?.details).toContain('1 entries');
    });

    it('generateHumanReadableReport returns a string with status line', async () => {
        const report = await checker.generateHumanReadableReport();
        expect(typeof report).toBe('string');
        expect(report).toContain('Overall Status:');
        expect(report).toContain('eIDAS');
    });

    it('check IDs are unique', async () => {
        const report = await checker.runChecks({ keyProtection: 'SOFTWARE_EPHEMERAL' });
        const ids = report.checks.map(c => c.id);
        expect(new Set(ids).size).toBe(ids.length);
    });
});
