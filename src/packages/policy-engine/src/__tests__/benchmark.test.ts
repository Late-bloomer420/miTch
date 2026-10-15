import { describe, it } from 'vitest';
import { PolicyEngine } from '../engine';

class BenchmarkEngine extends PolicyEngine {
  public runSelection(
    req: any,
    credentials: any[],
    rule: any,
    policy: any,
    context: any,
    effectiveClaims: string[]
  ) {
    return this['selectCompatibleCredentialsForRequirement'](
      req,
      credentials,
      rule,
      policy,
      context,
      effectiveClaims
    );
  }
}

describe('Performance Benchmark: selectCompatibleCredentialsForRequirement', () => {
  it('measures execution time for a massive number of credentials and claims', () => {
    const numCredentials = 200000;
    const claimsPerCred = 500;
    const effectiveClaimsCount = 100;

    console.log(`Generating ${numCredentials} credentials, each with ${claimsPerCred} claims...`);

    const allClaims = Array.from({ length: 1000 }, (_, i) => `claim_${i}`);
    const effectiveClaims = allClaims.slice(0, effectiveClaimsCount);

    const credentials = Array.from({ length: numCredentials }, (_, i) => ({
      id: `cred_${i}`,
      type: ['TestCredential'],
      issuer: 'did:example:123',
      status: 'active',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 1000000).toISOString(),
      claims: allClaims.slice(i % 500, (i % 500) + claimsPerCred),
    }));

    const req = {
      credentialType: 'TestCredential',
    };

    const rule = {
      requiresTrustedIssuer: false,
    };

    const policy = {
      trustedIssuers: [],
    };

    const context = {
      timestamp: Date.now(),
    };

    const engine = new BenchmarkEngine();

    console.log(
      `Running benchmark (checking ${effectiveClaimsCount} effective claims against ${numCredentials} credentials)...`
    );

    // Warmup
    engine.runSelection(req, credentials.slice(0, 100), rule, policy, context, effectiveClaims);

    const start = performance.now();
    const result = engine.runSelection(req, credentials, rule, policy, context, effectiveClaims);
    const end = performance.now();

    console.log(`\n==============================================`);
    console.log(`Processed ${credentials.length} credentials in ${(end - start).toFixed(2)} ms.`);
    console.log(`Suitable credentials found: ${result.credentials.length}`);
    console.log(`==============================================\n`);
  }, 20000);
});
