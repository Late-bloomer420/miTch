/**
 * @package @askmi/demo-liquor-store
 * @description Interactive Liquor Store Demo for Investor Presentations
 *
 * Demonstrates:
 * - Mock issuer creates a synthetic age credential
 * - Local age calculation (not an issuer-authenticated zero-knowledge proof)
 * - Illustrative layer comparison (not an integrated policy enforcement path)
 * - Illustrative layer violation scenario
 */

import { MockGovernmentIssuer, computeAgeProof } from '@askmi/mock-issuer';
import { ProtectionLayer, getLayerName } from '@askmi/layer-resolver';

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
  log('\n🎉 AskMI Liquor Store Demo\n', 'header');
  log('Synthetic age and layer comparison demo; no real verifier or consent flow\n');

  // Step 1: Issuer Setup
  await spinner('Setting up mock issuer', 800);
  const issuer = new MockGovernmentIssuer();
  await issuer.initialize();
  log('Mock issuer initialized', 'success');

  // Step 2: Credential Issuance
  log('\n📝 Issuing Age Credential...', 'info');
  await sleep(500);
  const birthdate = new Date('1990-05-15');
  const userDID = 'did:example:alice';
  const _credential = await issuer.issueAgeCredential(birthdate, userDID);
  await sleep(1000);
  log('✅ Age Credential issued (JWT signed)', 'success');
  log(`   User: ${userDID}`, 'info');
  log(`   Synthetic birthdate: ${birthdate.toDateString()}\n`, 'info');

  // Step 3: Local age calculation (no cryptographic proof)
  await spinner('Computing local age result (isOver18)', 1200);
  const isOver18 = computeAgeProof(birthdate, 18);
  log(`✅ Local result: isOver18 = ${isOver18}`, 'success');
  log('   No verifier presentation is performed in this demo.\n', 'warn');

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
    log('   Local result: isOver18 = true\n', 'success');
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
    log('   Simulated outcome: DENY\n', 'error');
  }

  // Summary
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'header');
  log('📊 Demo Summary', 'header');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'header');

  log('Local calculation only; no issuer-authenticated zero-knowledge proof.', 'warn');
  log('Layer outcomes are illustrative comparisons, not an integrated enforcement test.', 'warn');
  log('Synthetic birthdate is printed locally; no verifier presentation is performed.\n', 'warn');

  log('💡 AskMI - Development and evaluation software\n');

  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'header');
  log('Synthetic demonstration complete.\n', 'success');
}

// Run demo if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runDemo().catch((error) => {
    console.error('Demo error:', error);
    process.exit(1);
  });
}

export { runDemo };
