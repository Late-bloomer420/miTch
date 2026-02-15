import { performance } from 'perf_hooks';

/**
 * COLD-PATH BENCHMARK: Wallet Security Environment Boot Latency
 * 
 * Objective: Measure the time for critical wallet operations against
 * the performance budget defined in ZKQF_SPEC.md.
 * 
 * Target Budgets:
 * - Unlock/Init: 150-400ms (Max: 800ms)
 * - Policy Eval: <5-15ms
 * - End-to-End Proof: <500ms (Acceptable: <1.2s)
 */

interface BenchmarkResult {
    name: string;
    duration_ms: number;
    budget_ms: number;
    status: 'PASS' | 'WARN' | 'FAIL';
}

const results: BenchmarkResult[] = [];

function recordResult(name: string, duration: number, budgetMax: number, budgetWarn?: number): BenchmarkResult {
    const warnThreshold = budgetWarn || budgetMax * 0.8;
    let status: 'PASS' | 'WARN' | 'FAIL' = 'PASS';

    if (duration > budgetMax) {
        status = 'FAIL';
    } else if (duration > warnThreshold) {
        status = 'WARN';
    }

    const result = { name, duration_ms: parseFloat(duration.toFixed(2)), budget_ms: budgetMax, status };
    results.push(result);
    return result;
}

/**
 * Simulates PBKDF2 key derivation (Unlock Path)
 */
async function benchmarkUnlock(): Promise<number> {
    const t0 = performance.now();

    const password = new TextEncoder().encode('123456');
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const baseKey = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveKey']);

    await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    return performance.now() - t0;
}

/**
 * Simulates Policy Evaluation (Set Operations + Pattern Match)
 */
function benchmarkPolicyEval(ruleCount: number): number {
    const t0 = performance.now();

    // Simulate rule matching
    const rules = Array.from({ length: ruleCount }, (_, i) => ({
        id: `rule-${i}`,
        verifierPattern: `service-${i}.example.com`,
        allowedClaims: ['claim1', 'claim2', 'claim3'],
        deniedClaims: ['ssn']
    }));

    const requestedVerifier = 'service-50.example.com';
    const requestedClaims = ['claim1', 'claim2', 'address', 'ssn'];

    // Rule Matching (Linear for now)
    const matchedRule = rules.find(r => r.verifierPattern === requestedVerifier);

    if (matchedRule) {
        // Claim Intersection
        const effectiveClaims = requestedClaims.filter(c =>
            matchedRule.allowedClaims.includes(c) && !matchedRule.deniedClaims.includes(c)
        );
    }

    return performance.now() - t0;
}

/**
 * Simulates AES-GCM Encryption (VP Encrypt)
 */
async function benchmarkEncryption(payloadSizeKb: number): Promise<number> {
    const t0 = performance.now();

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = crypto.getRandomValues(new Uint8Array(payloadSizeKb * 1024));

    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

    return performance.now() - t0;
}

/**
 * Simulates RSA-OAEP Key Wrapping (Seal to Recipient)
 */
async function benchmarkKeyWrap(): Promise<number> {
    const t0 = performance.now();

    const rsaKeyPair = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['wrapKey', 'unwrapKey']
    );

    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

    await crypto.subtle.wrapKey('raw', aesKey, rsaKeyPair.publicKey, { name: 'RSA-OAEP' });

    return performance.now() - t0;
}

/**
 * Simulates ECDSA Signing (Capsule Attestation)
 */
async function benchmarkSigning(): Promise<number> {
    const t0 = performance.now();

    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const data = new TextEncoder().encode(JSON.stringify({ decision_id: 'test-123', verdict: 'ALLOW' }));

    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, data);

    return performance.now() - t0;
}

async function runBenchmarks() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║       MITCH COLD-PATH BENCHMARK (ZKQF Performance Budget)    ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('');

    // 1. Unlock Path
    console.log('🔐 Benchmarking: Wallet Unlock (PBKDF2 100k iterations)...');
    const unlockTime = await benchmarkUnlock();
    const unlockResult = recordResult('Unlock (PIN → MasterKey)', unlockTime, 800, 400);
    console.log(`   Result: ${unlockResult.duration_ms}ms [${unlockResult.status}] (Budget: ${unlockResult.budget_ms}ms)`);

    // 2. Policy Eval (100 Rules)
    console.log('⚖️ Benchmarking: Policy Evaluation (100 rules)...');
    const policyTime100 = benchmarkPolicyEval(100);
    const policyResult100 = recordResult('Policy Eval (100 rules)', policyTime100, 15, 5);
    console.log(`   Result: ${policyResult100.duration_ms}ms [${policyResult100.status}] (Budget: ${policyResult100.budget_ms}ms)`);

    // 3. Policy Eval (500 Rules - Storm Test)
    console.log('🌪️ Benchmarking: Policy Evaluation (500 rules - Storm)...');
    const policyTime500 = benchmarkPolicyEval(500);
    const policyResult500 = recordResult('Policy Eval (500 rules)', policyTime500, 50, 20);
    console.log(`   Result: ${policyResult500.duration_ms}ms [${policyResult500.status}] (Budget: ${policyResult500.budget_ms}ms)`);

    // 4. VP Encryption (2KB payload)
    console.log('🔒 Benchmarking: VP Encryption (2KB payload)...');
    const encryptTime = await benchmarkEncryption(2);
    const encryptResult = recordResult('VP Encrypt (AES-GCM 2KB)', encryptTime, 25, 10);
    console.log(`   Result: ${encryptResult.duration_ms}ms [${encryptResult.status}] (Budget: ${encryptResult.budget_ms}ms)`);

    // 5. Key Wrap (RSA-OAEP)
    console.log('🔑 Benchmarking: Key Wrap (RSA-OAEP 2048)...');
    const wrapTime = await benchmarkKeyWrap();
    const wrapResult = recordResult('Key Wrap (RSA-OAEP)', wrapTime, 60, 30);
    console.log(`   Result: ${wrapResult.duration_ms}ms [${wrapResult.status}] (Budget: ${wrapResult.budget_ms}ms)`);

    // 6. Capsule Signing (ECDSA)
    console.log('✍️ Benchmarking: Capsule Signing (ECDSA P-256)...');
    const signTime = await benchmarkSigning();
    const signResult = recordResult('Capsule Sign (ECDSA)', signTime, 20, 10);
    console.log(`   Result: ${signResult.duration_ms}ms [${signResult.status}] (Budget: ${signResult.budget_ms}ms)`);

    // Summary
    console.log('');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('                        SUMMARY                                ');
    console.log('═══════════════════════════════════════════════════════════════');

    const totalTime = results.reduce((acc, r) => acc + r.duration_ms, 0);
    const failCount = results.filter(r => r.status === 'FAIL').length;
    const warnCount = results.filter(r => r.status === 'WARN').length;

    results.forEach(r => {
        const icon = r.status === 'PASS' ? '✅' : (r.status === 'WARN' ? '⚠️' : '❌');
        console.log(`  ${icon} ${r.name.padEnd(30)} ${r.duration_ms.toString().padStart(8)}ms / ${r.budget_ms}ms`);
    });

    console.log('───────────────────────────────────────────────────────────────');
    console.log(`  Total Measured Time: ${totalTime.toFixed(2)}ms`);
    console.log(`  End-to-End Budget:   <500ms (Acceptable: <1200ms)`);
    console.log(`  Status:              ${failCount === 0 ? (warnCount === 0 ? '✅ ALL PASS' : '⚠️ WARNINGS') : '❌ FAILURES'}`);
    console.log('');

    if (failCount > 0) {
        console.error('BENCHMARK FAILED: Performance budget exceeded.');
        process.exit(1);
    }

    console.log('BENCHMARK PASSED: All operations within budget.');
    process.exit(0);
}

runBenchmarks().catch(err => {
    console.error('Benchmark error:', err);
    process.exit(1);
});
