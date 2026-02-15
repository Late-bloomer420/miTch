import { describe, test, expect, beforeAll } from 'vitest';
import { AuditLog, verifyAuditReport } from '../src/index';
import { generateKeyPair } from '@mitch/shared-crypto';

describe('Adversarial Tests: Audit Log Tampering (A1-A6)', () => {
    let auditKeys: CryptoKeyPair;

    beforeAll(async () => {
        auditKeys = await generateKeyPair();
    });

    test('A1: Payload Tampering - modifying metadata is detected', async () => {
        const log = new AuditLog('wallet-001');
        log.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        await log.append('KEY_CREATED', 'key-1', { alg: 'AES-GCM-256' });
        const report = await log.exportReport();

        // Attack: Change metadata after export
        report.entries[0].metadata = { alg: 'ROT13-IS-WEAK' };

        const result = await verifyAuditReport(report, auditKeys.publicKey);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/Content hash mismatch/i);
    });

    test('A2: Cherry-Picking - deleting an entry is detected by report signature', async () => {
        const log = new AuditLog('wallet-001');
        log.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        await log.append('KEY_CREATED', 'key-1');
        await log.append('KEY_DESTROYED', 'key-1');

        const report = await log.exportReport();

        // Attack: Delete the middle entry (or any entry)
        report.entries.splice(0, 1);

        const result = await verifyAuditReport(report, auditKeys.publicKey);
        expect(result.valid).toBe(false);
        // Should fail at report hash level because entry list changed
        expect(result.error).toMatch(/Report-level hash mismatch/i);
    });

    test('A3: Reordering - swapping entries is detected by hash chain', async () => {
        const log = new AuditLog('wallet-001');
        log.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        await log.append('KEY_CREATED', 'key-1');
        await log.append('KEY_DESTROYED', 'key-1');

        const report = await log.exportReport();

        // Attack: Swap entries
        [report.entries[0], report.entries[1]] = [report.entries[1], report.entries[0]];

        const result = await verifyAuditReport(report, auditKeys.publicKey);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/Hash chain link broken/i);
    });

    test('A4: Signature Swap - moving signature to different entry is detected', async () => {
        const log = new AuditLog('wallet-001');
        log.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        await log.append('KEY_CREATED', 'key-1');
        await log.append('KEY_USED', 'key-1');

        const report = await log.exportReport();

        // Attack: Copy signature from entry 0 to entry 1
        report.entries[1].signature = report.entries[0].signature;

        const result = await verifyAuditReport(report, auditKeys.publicKey);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/Invalid entry signature/i);
    });

    test('A5: Governance Downgrade - changing kid/sigAlg is detected', async () => {
        const log = new AuditLog('wallet-001');
        log.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        await log.append('KEY_CREATED', 'key-1');
        const report = await log.exportReport();

        // Attack: Change sigAlg to something weak
        report.entries[0].sigAlg = 'DSA_MD5_LOL';

        const result = await verifyAuditReport(report, auditKeys.publicKey);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/Content hash mismatch/i);
    });

    test('A6: Report-Level Integrity Check - re-hashing entries without updating report signature fails', async () => {
        const log = new AuditLog('wallet-001');
        log.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        await log.append('KEY_CREATED', 'key-1');
        const report = await log.exportReport();

        // Attack: Modify an entry AND IT'S HASH (simulating a "cleaner" hack), 
        // but can't forge the report-level signature.
        report.entries[0].action = 'VC_IMPORTED';
        report.entries[0].currentHash = '0'.repeat(64); // Invalid hash but testing report sig

        const result = await verifyAuditReport(report, auditKeys.publicKey);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/Report-level hash mismatch/i);
    });
});
