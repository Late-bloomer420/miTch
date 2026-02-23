/**
 * Integration Example (Phase-0 Security Hardening - Version 1)
 */

import { LocalAuditLog } from './LocalAuditLog.js';
import { VerifierDirectProtocol, DIRECT_VERIFIER_DID } from './VerifierDirectProtocol.js';
import { EIDASComplianceChecker, ComplianceStatus } from './EIDASComplianceChecker.js';
import { PanicGuard, UserDerivedKeyProtection } from './ADVANCED_SECURITY_HARDENING.js';

export async function demonstrateSecurePresentation() {
    console.log('🚀 Phase-0 Security Hardening Demo (Version 1)');

    // 1. Audit Log Initialization (Encrypted)
    const auditLog = new LocalAuditLog();
    await auditLog.initialize();
    console.log('✅ Local Audit Log Initialized (IndexedDB + Hash Chain + AES-GCM Encryption)');

    // 2. Runtime Compliance Checks (7-Point Check)
    const checker = new EIDASComplianceChecker(auditLog);

    // Feature: Human Readable Report for Regulators
    const readableReport = await checker.generateHumanReadableReport();
    console.log('\n' + readableReport + '\n');

    const report = await checker.runChecks({
        remoteVerifierUrl: null,
        keyProtection: 'SOFTWARE_EPHEMERAL',
    });

    if (report.status === ComplianceStatus.FAIL) {
        console.error('🛑 System is NOT eIDAS Compliant. Halting.');
        return;
    }

    // 3. User-Derived Key Demo
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const userKey = await UserDerivedKeyProtection.deriveKeyFromUser('correct-horse-battery-staple', salt);
    console.log('🛡️ User Derived Key Generated (PBKDF2 Ref check):', (userKey as any).algorithm.name);

    // 4. Verifier-Direct Protocol (No Server Relay)
    const protocol = new VerifierDirectProtocol();
    const session = await protocol.createDirectSession();
    console.log('🔗 Generated Direct Deep Link:', session.deepLink);

    // 5. Record Policy Evaluation in Audit Log
    const evaluation = {
        action: 'POLICY_EVALUATION',
        verifier: DIRECT_VERIFIER_DID,
        verdict: 'ALLOW',
        timestamp: Date.now(),
        details: { matchedRule: 'liquor-store-age-check' }
    };

    const logEntry = await auditLog.append(evaluation as any);
    console.log('📝 Audit Entry Logged & Encrypted. Chain Hash:', logEntry.hash);

    // 6. Simulate Presentation
    const vp = {
        type: ['VerifiablePresentation'],
        holder: 'did:mitch:user-1',
        verifiableCredential: [{ type: ['AgeCredential'] }]
    };

    const success = await protocol.submitDirectPresentation(vp, session.verifierEndpoint);

    if (success) {
        console.log('✅ Presentation Accepted by Verifier Directly!');
        await auditLog.append({
            action: 'CREDENTIAL_PRESENTATION',
            verifier: DIRECT_VERIFIER_DID,
            timestamp: Date.now(),
            details: { sessionId: session.sessionId }
        } as any);
    } else {
        console.warn('⚠️ Verification Failed or Backend Offline (Expected in simple demo run)');
    }

    // 7. Data Portability (GDPR Art. 20)
    const exportData = await auditLog.exportForUser();
    console.log(`📦 GDPR Export: ${exportData.entries.length} entries. Root Hash: ${exportData.integrityProof.rootHash}`);

    // 8. Verify Log Integrity
    const integrity = await auditLog.verifyIntegrity();
    console.log('🔒 Audit Log Integrity Check:', integrity.valid ? 'PASS' : 'FAIL');

    // 9. Right to Erasure (GDPR Art. 17)
    // Uncomment to test full deletion flow
    // console.log('🗑️ Testing Right to Erasure...');
    // await auditLog.deleteAll();
    // const postDelete = await auditLog.getAllEntries();
    // console.log('   Entries after deletion:', postDelete.length);
}

demonstrateSecurePresentation().catch(console.error);
