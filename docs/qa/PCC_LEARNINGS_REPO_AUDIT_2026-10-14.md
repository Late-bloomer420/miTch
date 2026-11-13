# PCC-learnings repository evidence — 2026-10-14

## Interpretation clarification — 2026-10-14

The observations and diagnostic sources below are retained unchanged. The audit inventoried the repository and selectively inspected/tested paths; it did not manually verify every source file. A signed underage claim may be cryptographically valid: EV-02 concerns original-profile/application eligibility and scope, not a defective signature primitive or a general PolicyEngine failure. EV-04 is a call-site/integration observation, not proof that a particular external leak occurs. EV-07 is a buffer-ownership/asynchronous-lifetime boundary requiring a caller-contract decision, not automatically a defect in a best-effort wipe wrapper. Structural validation and local predicate signing have distinct legitimate contracts (EV-08). Positive component tests remain evidence for their stated scopes.

**Executable baseline:** `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`.
**Scope:** internal repository investigation; not an external audit, full manual line-by-line review or official conformance.
**Runtime:** Linux, Node 24.19.0, pnpm 9.15.9, frozen lockfile. CI's Node 22 is not claimed as newly locally tested.
**Refresh:** master and relevant PR heads were unchanged on the subsequent publication check.

## Method and evidence coverage

Inventoried 1,057 tracked files; repositorywide privacy/security/claims search; all 169 then-existing GitHub issue/PR entries
captured and title/body searched. Relevant active call paths, specs, evidence harness, workflows, roadmaps and PR reviews were followed in depth.
Later intake #170–#173 is tracking, not evidence of implementation. No real credentials/user data or public deployment was tested.

| Verification | Observed result | Scope / limit |
|---|---|---|
| Frozen installation + pinned build | 29/29 build tasks, no cache | Original 14 October executable-baseline run; not a new full-suite claim |
| Rebrand / archived-import guards | passed | Existing guard scope |
| HTTP tests + four new characterization probes | 13/13 | 9 existing tests + four tests asserting the unsafe behavior described below |
| Audit-export schema | 35/35 | Schema/helper behavior, not sink integration |
| Metadata + engine-security paths | 28/28 | Includes #122's two layer regressions |
| Publication-refresh schema/metadata/engine run | 63/63 across three files | Same executable baseline; no full health E2E or entire suite inferred |
| Secure-memory | 5/5 | Four existing tests + timeout/callback-copy characterization |
| Real stored SD-JWT single-use probe | 1/1 under Node | Repeated VP creation retains issuer-JWT and leaves consumedAt absent |
| Existing evidence harness | 10 PASS, 2 RESIDUAL, 0 FAIL | Only manifest claims; excludes active HTTP/real single-use counterexamples |
| CI Python snippet, synthetic critical=1/high=5 | exit 0 | Reproduces gate defect, not current advisory inventory |
| July JSON file hash | final-LF mismatch | Serialization defect, not tampering |

## Reproduced observations

| Probe | Current behavior | Finding |
|---|---|---|
| Repost identical valid signed VP | HTTP 200, then HTTP 200 | EV-01 / #170 |
| Holder-selected nonce and state differ from authorize request | HTTP 200 | EV-01 / #170 |
| Signed age=12 | HTTP 200, ok=true, disclosedClaims.age=12 | EV-02 / #170; crypto validity is not eligibility |
| Signed name added outside original age request | name returned with HTTP 200 | EV-02 / #170 |
| Store singleUse=true, present twice with different nonces | issuer-JWT prefix identical; consumedAt absent | EV-03 / #171 |
| Copy key bytes, timeout, release pending callback | owned wrapper shredded; copy retained; operation continued | EV-07 / GAP-1 |

The six characterization test sources are preserved below. “Passed” means the counterexample was observed,
not that the security requirement was met. They were temporary local files, removed after the run; no application code was changed.

## Hash reproduction

The July artifact header is `bc434aa054fe53d97e26539edf195977beaf61c6ebd947b27dd74b294f4371dc`.
SHA-256 of the exact JSON file bytes is `5fa8fa3a8ae2083453b23ba8599e45611d841dfa373e5380eb095d35afd06ebe`.
Removing only the final LF reproduces the header. `report.ts` hashes JSON; `cli.ts` adds LF on write. #173 is open.

The fresh original harness timestamp was `2026-10-14T09:19:58.414Z` (Node v24.19.0):
SECURE1-F03/F04/F16-18/F14/GAP3 and STRIDE-T1/T2/T5/I2/I1 PASS; GAP-1/GAP-4 RESIDUAL.
This newly published manual record supplies the source/scope boundary missing in the generated report; it does not fix the generator.

## Environment limits and non-claims

The first build accidentally used host pnpm 11 in Turbo subprocesses; pinned pnpm 9 on PATH built successfully.
The tsx CLI IPC socket failed with EPERM; the same harness ran via `node --import tsx src/cli.ts`.
The wallet probe under jsdom hit the repository-documented jose/Uint8Array cross-realm limitation;
under Node it used real signing/storage successfully. These are environment limits, not reclassified product findings.
No fresh whole-suite/lint/browser E2E, official-wallet matrix, external review, legal assessment or live dependency-advisory count is claimed.

## Reproduction outline

Checkout the executable baseline above. Copy each fenced characterization source to its named temporary test path.
Use pnpm 9.15.9 for all subprocesses; set ASKMI_TEST_MODE=1 for synthetic tests.

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm --filter verifier-backend exec vitest run src/__tests__/oid4vp-present.test.ts src/__tests__/pcc-evidence-probes.test.ts
pnpm --filter @askmi/secure-memory exec vitest run test/shredding.test.ts test/pcc-evidence-probes.test.ts
pnpm --filter @askmi/wallet-pwa exec vitest run src/__tests__/pcc-evidence-probes.test.ts --environment node
pnpm --filter @askmi/policy-engine exec vitest run src/__tests__/audit-export-schema.test.ts src/__tests__/audit-metadata.test.ts src/__tests__/engine-security-paths.test.ts
pnpm --filter @askmi/evidence exec node --import tsx src/cli.ts
```

## Source and owner index

- [Current findings](../security/REPO_EVIDENCE_STATUS_2026-10-14.md), [backlog](../BACKLOG.md), #142, #143.
- [Verifier endpoint](../../src/apps/verifier-demo/backend/src/app.ts), [SD-JWT demo validator](../../src/packages/oid4vp/src/demo-flow.ts), #170.
- [Wallet](../../src/apps/wallet-pwa/src/services/WalletService.ts), [UI](../../src/apps/wallet-pwa/src/App.tsx), #171.
- [Audit schema](../../src/packages/policy-engine/src/audit-export-schema.ts), [generic log](../../src/packages/audit-log/src/index.ts), #172.
- [Evidence manifest](../../src/packages/evidence/src/manifest.ts), [report](../../src/packages/evidence/src/report.ts), [CLI](../../src/packages/evidence/src/cli.ts), #173.
- [.github CI audit](../../.github/workflows/ci-security.yml), #141 / SEC-AUDIT-1/2.
- [Secure-memory wrapper](../../src/packages/secure-memory/src/ephemeral_key.ts), [residuals](../security/RESIDUALS.md), GAP-1.

## Characterization sources (synthetic data only)

### `src/apps/verifier-demo/backend/src/__tests__/pcc-evidence-probes.test.ts`

```typescript
// Temporary audit characterization probes; synthetic keys/data only.
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { app, setIssuerKeyResolver } from '../app';
import { buildSDJWTPresentation } from '@askmi/oid4vp';
import { trustListResolver } from '@askmi/shared-crypto';
import { ASKMI_DEMO, ASKMI_SCENARIO_VCT } from '@askmi/shared-types';

describe('PCC audit: active HTTP boundary characterization', () => {
  let issuer: CryptoKeyPair;
  let holder: CryptoKeyPair;
  beforeAll(async () => {
    issuer = await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    holder = await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    trustListResolver.setFetch(vi.fn().mockResolvedValue({ok:true,json:async()=>({id:'synthetic-tsl',version:'1',validUntil:'2030-01-01T00:00:00Z',issuers:[ASKMI_DEMO.issuerUri],verifiers:[ASKMI_DEMO.verifierDid]})}) as any);
    trustListResolver.clearCache();
  });
  beforeEach(async () => {
    await request(app).post('/reset');
    setIssuerKeyResolver(async()=>issuer.publicKey);
  });
  async function token(authRequest: any, claims: Record<string,unknown>) {
    const built = await buildSDJWTPresentation({request:authRequest,issuerPrivateKey:issuer.privateKey,holderKeyPair:holder,claims,vct:ASKMI_SCENARIO_VCT['liquor-store'],issuerDid:ASKMI_DEMO.issuerUri,revoked:false});
    return {vp_token:built.vpTokenString,presentation_submission:built.presentationSubmission,state:authRequest.state};
  }
  it('identical valid token is accepted twice by /oid4vp-present', async()=>{
    const {body:{authRequest}}=await request(app).get('/authorize?scenario=liquor-store');
    const body=await token(authRequest,{age:24});
    const first=await request(app).post('/oid4vp-present').send(body);
    const second=await request(app).post('/oid4vp-present').send(body);
    console.log('AUDIT_PROBE replay',JSON.stringify({first:first.status,second:second.status}));
    expect([first.status,second.status]).toEqual([200,200]);
  });
  it('holder-selected nonce and state are accepted instead of issued values',async()=>{
    const {body:{authRequest}}=await request(app).get('/authorize?scenario=liquor-store');
    const changed={...authRequest,nonce:'synthetic-holder-selected-nonce',state:'synthetic-holder-selected-state'};
    const res=await request(app).post('/oid4vp-present').send(await token(changed,{age:24}));
    console.log('AUDIT_PROBE wrong_binding',res.status);
    expect(res.status).toBe(200);
  });
  it('a cryptographically valid underage credential produces ok:true',async()=>{
    const {body:{authRequest}}=await request(app).get('/authorize?scenario=liquor-store');
    const res=await request(app).post('/oid4vp-present').send(await token(authRequest,{age:12}));
    console.log('AUDIT_PROBE underage',JSON.stringify({status:res.status,ok:res.body.ok,claims:res.body.disclosedClaims}));
    expect(res.status).toBe(200); expect(res.body.disclosedClaims.age).toBe(12);
  });
  it('extra signed name is accepted and returned outside the original age request',async()=>{
    const {body:{authRequest}}=await request(app).get('/authorize?scenario=liquor-store');
    const changed=structuredClone(authRequest);
    changed.presentation_definition.input_descriptors[0].constraints.fields.push({path:['$.name']});
    const res=await request(app).post('/oid4vp-present').send(await token(changed,{age:24,name:'Synthetic Audit Person'}));
    console.log('AUDIT_PROBE overdisclosure',JSON.stringify({status:res.status,claims:res.body.disclosedClaims}));
    expect(res.status).toBe(200); expect(res.body.disclosedClaims.name).toBe('Synthetic Audit Person');
  });
});

```

### `src/packages/secure-memory/test/pcc-evidence-probes.test.ts`

```typescript
import {describe,it,expect} from 'vitest';
import {EphemeralKey} from '../src/ephemeral_key';
describe('PCC audit: shredding guarantee boundary',()=>{
  it('timeout shreds owned buffer but does not cancel work or clear callback copies',async()=>{
    const key=EphemeralKey.import(new Uint8Array(32).fill(7));
    let release!:()=>void;
    const gate=new Promise<void>(resolve=>{release=resolve;});
    let copy:Uint8Array|undefined;
    let continued=false;
    await expect(key.use(async raw=>{copy=raw.slice();await gate;continued=true;return 1;},1)).rejects.toThrow('timeout');
    expect(key.isShredded()).toBe(true);
    expect(copy?.[0]).toBe(7);
    release(); await gate; await Promise.resolve();
    expect(continued).toBe(true);
    console.log('AUDIT_PROBE timeout_copy',JSON.stringify({shredded:key.isShredded(),copyRetained:copy?.[0]===7,continued}));
    copy?.fill(0);
  });
});

```

### `src/apps/wallet-pwa/src/__tests__/pcc-evidence-probes.test.ts`

```typescript
import {describe,it,expect} from 'vitest';
import {WalletService} from '../services/WalletService';
import {createSDJWTDisclosures,buildCNFClaim,issueSDJWTVC} from '@askmi/shared-crypto';
describe('PCC audit: real SD-JWT single-use lifecycle',()=>{
  it('singleUse:true stored credential can be presented twice with the same issuer token',async()=>{
    const wallet=new WalletService();
    await wallet.initialize('synthetic-audit-pin','synthetic-audit-salt');
    const issuer=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    const holder=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    const {_sd,disclosures}=await createSDJWTDisclosures({age:24});
    const jwt=await issueSDJWTVC({iss:'did:web:localhost%3A3005',vct:'https://askmi.demo/vct/age-credential',cnf:await buildCNFClaim(holder.publicKey),_sd,iat:Math.floor(Date.now()/1000)},issuer.privateKey);
    const stored=`${jwt}~${disclosures.join('~')}~`;
    await wallet.addSdJwtVc('synthetic-audit-single-use',stored,await crypto.subtle.exportKey('jwk',holder.privateKey),{singleUse:true});
    const first=await wallet.presentStoredSdJwtVc('synthetic-audit-single-use',['age'],{aud:'did:askmi:verifier',nonce:'audit-session-1'});
    const second=await wallet.presentStoredSdJwtVc('synthetic-audit-single-use',['age'],{aud:'did:askmi:verifier',nonce:'audit-session-2'});
    expect(first).not.toBeNull();expect(second).not.toBeNull();
    expect(first!.vpToken.split('~')[0]).toBe(second!.vpToken.split('~')[0]);
    const metadata=(await wallet.getCredentials()).find(x=>x.id==='synthetic-audit-single-use');
    expect(metadata?.singleUse).toBe(true);expect(metadata?.consumedAt).toBeFalsy();
  });
});

```
