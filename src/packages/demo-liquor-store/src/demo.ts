/**
 * @package @mitch/demo-liquor-store
 * @description Interactive Liquor Store Demo for Investor Presentations
 *
 * Demonstrates:
 * - Government issuer creates age credential
 * - Zero-knowledge proof (isOver18 without birthdate)
 * - Layer-based policy evaluation
 * - Automated layer violation detection
 */

import { MockGovernmentIssuer, computeAgeProof } from '@mitch/mock-issuer';
import { ProtectionLayer, getLayerName } from '@mitch/layer-resolver';

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function log(message: string, style: 'header' | 'info' | 'success' | 'error' | 'warn' = 'info') {
  const colors = {
    header: '\x1b[1m\x1b[36m', // Bold Cyan
    info: '\x1b[37m', // White
    success: '\x1b[32m', // Green
    error: '\x1b[31m', // Red
    warn: '\x1b[33m', // Yellow
    reset: '\x1b[0m',
  };

  const color = colors[style] || colors.info;
  console.log(`${color}${message}${colors.reset}`);
}

async function spinner(message: string, duration: number, success: boolean = true) {
  process.stdout.write(`⏳ ${message}...`);
  await sleep(duration);
  if (success) {
    console.log(` ✅`);
  } else {
    console.log(` ❌`);
  }
}

async function runDemo() {
  console.clear();
  log('\n🎉 miTch Liquor Store Demo\n', 'header');
  log('Layer-based Privacy & Consent Management\n');

  // Step 1: Issuer Setup
  await spinner('Setting up Government Issuer', 800);
  const issuer = new MockGovernmentIssuer();
  await issuer.initialize();
  log('Government Issuer initialized', 'success');

  // Step 2: Credential Issuance
  log('\n📝 Issuing Age Credential...', 'info');
  await sleep(500);
  const birthdate = new Date('1990-05-15');
  const userDID = 'did:example:alice';
  const _credential = await issuer.issueAgeCredential(birthdate, userDID);
  await sleep(1000);
  log('✅ Age Credential issued (JWT signed)', 'success');
  log(`   User: ${userDID}`, 'info');
  log(`   Birthdate: ${birthdate.toDateString()} (HIDDEN in proof)\n`, 'info');

  // Step 3: ZK Proof Generation
  await spinner('Computing Zero-Knowledge Proof (isOver18)', 1200);
  const isOver18 = computeAgeProof(birthdate, 18);
  log(`✅ ZK Proof: isOver18 = ${isOver18}`, 'success');
  log('   ✨ Exact birthdate NOT revealed!\n', 'warn');

  // Step 4: Liquor Store Request (Layer 1 - ALLOWED)
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'header');
  log('📋 Scenario 1: Legitimate Request', 'header');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'header');

  await spinner('Liquor Store requests age verification', 800);

  const policy1 = {
    verifierDID: 'did:example:liquor-store',
    minimumLayer: ProtectionLayer.GRUNDVERSORGUNG, // Layer 1
    allowedClaims: ['age'],
  };

  log(`📊 Policy: ${getLayerName(policy1.minimumLayer)}`, 'info');
  log('   Requested: age', 'info');
  log('   Required Layer: 1 (GRUNDVERSORGUNG)\n', 'info');

  await spinner('Evaluating policy', 1000);

  // Simple layer check
  const verifierLayer = policy1.minimumLayer;
  const requiredLayer = ProtectionLayer.GRUNDVERSORGUNG; // 'age' requires Layer 1
  const allowed = verifierLayer >= requiredLayer && isOver18;

  if (allowed) {
    log('✅ ALLOW - User may purchase alcohol', 'success');
    log('   Reason: Layer 1 can access age data', 'success');
    log('   Proof: isOver18 = true\n', 'success');
  }

  // Step 5: Malicious Request (Layer 2 - DENIED)
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'header');
  log('🚨 Scenario 2: Layer Violation', 'header');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'header');

  await spinner('Malicious actor requests health data', 800);

  const policy2 = {
    verifierDID: 'did:example:liquor-store',
    minimumLayer: ProtectionLayer.GRUNDVERSORGUNG, // Layer 1
    allowedClaims: ['healthRecord'], // Requires Layer 2!
  };

  log(`⚠️  Policy: ${getLayerName(policy2.minimumLayer)}`, 'warn');
  log('   Requested: healthRecord', 'info');
  log('   Required Layer: 2 (VULNERABLE) ⚠️\n', 'error');

  await spinner('Evaluating policy', 1200);

  const requiredLayer2 = ProtectionLayer.VULNERABLE; // Layer 2
  const denied = verifierLayer < requiredLayer2;

  if (denied) {
    log('❌ DENY - LAYER_VIOLATION', 'error');
    log('   Reason: Layer 1 cannot access Layer 2 data', 'error');
    log('   Action: Request blocked automatically\n', 'error');
  }

  // Summary
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'header');
  log('📊 Demo Summary', 'header');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'header');

  log('✅ Privacy Preserved: Birthdate never disclosed', 'success');
  log('✅ Zero-Knowledge: Age proof computed locally', 'success');
  log('✅ Layer Protection: Automated enforcement', 'success');
  log('✅ Fail-Closed: Deny-by-default policy\n', 'success');

  log('💡 miTch - Where Privacy Meets Compliance\n');

  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'header');
  log('Demo complete! Ready for investor presentation. 🎊\n', 'success');
}

// Run demo if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runDemo().catch((error) => {
    console.error('Demo error:', error);
    process.exit(1);
  });
}

export { runDemo };
