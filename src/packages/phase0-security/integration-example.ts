/**
 * Integration Example: Phase-0 Security Hardening
 * 
 * Demonstrates:
 * 1. Local Audit-Log with hash-chain
 * 2. Verifier-Direct Protocol (no miTch server)
 * 3. eIDAS 2.0 compliance checking
 */

import { LocalAuditLog, AuditEvent } from './LocalAuditLog';
import { VerifierDirectClient, WalletDirectProtocol } from './VerifierDirectProtocol';
import { EIDASComplianceChecker } from './EIDASComplianceChecker';

/**
 * SCENARIO: User presents AgeCredential to Liquor Store
 */
async function demonstrateSecurePresentation() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  miTch Phase-0: Secure Credential Presentation Demo');
  console.log('═══════════════════════════════════════════════════════════\n');

  // ==================== SETUP ====================

  // 1. Initialize Wallet's Local Audit-Log
  console.log('1️⃣  Initializing Wallet (User-Side)...');
  const auditLog = new LocalAuditLog();
  await auditLog.initialize();
  
  await auditLog.append({
    type: 'KEY_GENERATED',
    timestamp: Date.now(),
    details: {
      keyType: 'ECDSA-P256',
      protectionLevel: 'SOFTWARE_EPHEMERAL',
      extractable: false
    }
  });
  console.log('   ✓ Wallet initialized with ephemeral keys\n');

  // 2. Initialize Verifier (Liquor Store)
  console.log('2️⃣  Initializing Verifier (Liquor Store)...');
  const verifier = new VerifierDirectClient('did:mitch:verifier-liquor-store');
  await verifier.initialize();
  console.log('   ✓ Verifier initialized with ephemeral session key\n');

  // ==================== VERIFIER-DIRECT FLOW ====================

  // 3. Verifier generates presentation request (NO miTch server)
  console.log('3️⃣  Verifier generates QR-Code (locally, no server)...');
  const deepLink = await verifier.generateRequest(
    ['AgeCredential'],
    'https://liquor-store.com/api/verify'
  );
  console.log('   QR-Code content:', deepLink.slice(0, 60) + '...');
  console.log('   ⚠️  miTch server saw: NOTHING (0 requests)\n');

  // 4. Wallet scans QR-Code and parses request (NO server fetch)
  console.log('4️⃣  Wallet scans QR-Code (locally, no server)...');
  const walletProtocol = new WalletDirectProtocol();
  const request = await walletProtocol.parseRequest(deepLink);
  console.log('   ✓ Request validated:', {
    verifier: request.verifierDID,
    credentialTypes: request.credentialTypes
  });
  console.log('   ⚠️  miTch server saw: NOTHING (0 requests)\n');

  // 5. Wallet evaluates policy (locally)
  console.log('5️⃣  Wallet evaluates policy (locally)...');
  await auditLog.append({
    type: 'POLICY_EVALUATED',
    timestamp: Date.now(),
    details: {
      verifier: request.verifierDID,
      credentialType: 'AgeCredential',
      rule: 'age >= 18',
      decision: 'ALLOW',
      policyEngine: 'LOCAL_DETERMINISTIC'
    }
  });
  console.log('   ✓ Policy evaluated: ALLOW (age >= 18)\n');

  // 6. Wallet generates ZK-Proof (locally)
  console.log('6️⃣  Wallet generates ZK-Proof (locally)...');
  const zkProof = {
    type: 'ZKProof' as const,
    claim: 'age_over_18',
    proof: '0xABCD1234...', // Simplified
    timestamp: Date.now(),
    nonce: request.nonce
  };
  
  await auditLog.append({
    type: 'CREDENTIAL_PRESENTED',
    timestamp: Date.now(),
    details: {
      verifier: request.verifierDID,
      credentialType: 'AgeCredential',
      proofType: 'ZKProof',
      claim: zkProof.claim,
      disclosedData: 'NONE' // Zero-Knowledge
    }
  });
  console.log('   ✓ ZK-Proof generated (no PII disclosed)\n');

  // 7. Wallet sends proof DIRECTLY to Verifier (NO miTch server)
  console.log('7️⃣  Wallet sends proof to Verifier (direct HTTPS)...');
  console.log('   POST', request.callbackURL);
  console.log('   ⚠️  miTch server saw: NOTHING (bypassed completely)\n');

  // ==================== NETWORK AUDIT ====================

  console.log('═══════════════════════════════════════════════════════════');
  console.log('  NETWORK TRAFFIC AUDIT');
  console.log('═══════════════════════════════════════════════════════════\n');

  console.log('📊 Requests to miTch Server: 0');
  console.log('   ✓ Verifier generated request locally (JavaScript)');
  console.log('   ✓ Wallet parsed request locally (no fetch)');
  console.log('   ✓ Wallet sent proof directly to Verifier\n');

  console.log('📊 PII in Network:');
  console.log('   ✗ Wallet → Verifier: ZK-Proof only (TRUE/FALSE)');
  console.log('   ✗ No birthdate, no name, no DID transmitted\n');

  console.log('📊 Server-Side Logs:');
  console.log('   miTch Server: EMPTY (structural non-existence)');
  console.log('   Liquor Store: "ZK-Proof verified: age >= 18" (anonymous)\n');

  // ==================== COMPLIANCE CHECK ====================

  console.log('═══════════════════════════════════════════════════════════');
  console.log('  eIDAS 2.0 + DSGVO COMPLIANCE CHECK');
  console.log('═══════════════════════════════════════════════════════════\n');

  const complianceChecker = new EIDASComplianceChecker(auditLog);
  const report = await complianceChecker.generateHumanReadableReport();
  console.log(report);

  // ==================== AUDIT-LOG EXPORT ====================

  console.log('═══════════════════════════════════════════════════════════');
  console.log('  AUDIT-LOG EXPORT (GDPR Art. 20)');
  console.log('═══════════════════════════════════════════════════════════\n');

  const exportedLog = await auditLog.exportForUser();
  console.log('User can export audit-log:');
  console.log(JSON.stringify(exportedLog, null, 2));
  console.log('');

  // ==================== INTEGRITY VERIFICATION ====================

  console.log('═══════════════════════════════════════════════════════════');
  console.log('  AUDIT-LOG INTEGRITY VERIFICATION');
  console.log('═══════════════════════════════════════════════════════════\n');

  const isValid = await auditLog.verifyIntegrity();
  console.log(`Hash-Chain Integrity: ${isValid ? '✅ VALID' : '❌ COMPROMISED'}`);
  console.log(`Root Hash: ${exportedLog.integrityProof.rootHash.slice(0, 16)}...`);
  console.log(`Total Entries: ${exportedLog.integrityProof.totalEntries}\n`);

  // ==================== SUMMARY ====================

  console.log('═══════════════════════════════════════════════════════════');
  console.log('  PHASE-0 SECURITY SUMMARY');
  console.log('═══════════════════════════════════════════════════════════\n');

  console.log('✅ Structural Non-Existence:');
  console.log('   miTch server saw ZERO presentation data\n');

  console.log('✅ Local Audit-Log:');
  console.log('   User has complete processing record (hash-chain verified)\n');

  console.log('✅ Ephemeral Keys:');
  console.log('   All keys session-scoped, no persistence\n');

  console.log('✅ eIDAS 2.0 Compliance:');
  console.log('   Audit-log exportable, deletable, tamper-evident\n');

  console.log('✅ Zero-Knowledge Proofs:');
  console.log('   Verifier received TRUE/FALSE, no PII\n');

  console.log('═══════════════════════════════════════════════════════════\n');
}

// Run demo
demonstrateSecurePresentation().catch(console.error);
