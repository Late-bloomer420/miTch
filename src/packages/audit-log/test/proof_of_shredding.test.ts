import { describe, test, expect, beforeAll } from 'vitest';
import { AuditLog } from '../src/index';
import { EphemeralKey, generateKeyPair } from '@mitch/shared-crypto';

describe('Proof of Forgetting (Signed Audit Trace)', () => {
    let auditKeys: CryptoKeyPair;

    beforeAll(async () => {
        auditKeys = await generateKeyPair();
    });

    test('Scenario: Cryptographically proving the destruction of an ephemeral key', async () => {
        // 1. Setup Audit Log with Truth Anchor
        const auditLog = new AuditLog('wallet-001');
        auditLog.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        console.log('📝 Audit Log initialized with Signing Keys');

        // 2. Create Ephemeral Key
        const key = await EphemeralKey.create();
        const keyId = 'key-uuid-1234';

        await auditLog.append('KEY_CREATED', keyId, { alg: 'AES-GCM-256' });
        console.log(`🔐 Key created [${keyId}]`);

        // 3. Crypto-Shredding
        console.log('🔥 Initiating Crypto-Shredding...');
        key.shred();

        const receipt = await auditLog.append('KEY_DESTROYED', keyId, {
            reason: 'Session terminal',
            method: 'Hard reference drop'
        });
        console.log('✅ Key shredded & Logged');

        // 4. Verification: System Property
        await expect(key.encrypt('test')).rejects.toThrow('SECURITY VIOLATION');
        console.log('🛡️ Mechanical Protection: Key unusable');

        // 5. Verification: Audit Property (Truth Anchor)
        const integrity = await auditLog.verifyChain();
        expect(integrity.valid).toBe(true);
        console.log('📜 Audit Chain Integrity & Authenticity: VERIFIED');

        // 6. Shredding Receipt Verification
        const shreddingReceipt = auditLog.getShreddingReceipt(keyId);
        expect(shreddingReceipt).toBeDefined();
        expect(shreddingReceipt?.signature).toBeDefined();
        console.log('🧾 Shredding Receipt Exported & Signed');

        // Show the log
        const report = await auditLog.exportReport();
        console.table(report.entries.map(e => ({
            Action: e.action,
            Hash: e.currentHash.substring(0, 8),
            Signed: !!e.signature
        })));
    });
});
