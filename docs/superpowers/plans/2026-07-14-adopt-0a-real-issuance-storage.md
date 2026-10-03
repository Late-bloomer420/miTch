# ADOPT-0a — Real SD-JWT VC Issuance + Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fetch and store a real, issuer-signed, holder-bound **SD-JWT VC** (with selective-disclosure structure) from issuer-mock, verifiable against the trust-list-resolved issuer key — replacing the plain VC-JWT + placeholder-holder + claims-only-storage fabrication.

**Architecture:** Add a standard SD-JWT disclosure primitive to `@askmi/shared-crypto`; make issuer-mock issue a real `vc+sd-jwt` (persistent issuer key, `cnf` from the wallet's holder-key PoP, `_sd` digests + disclosures); make the wallet generate a single-use holder key, send it as the OID4VCI proof, and store the **full SD-JWT VC + holder key** (not just claims). Presentation is untouched (ADOPT-0b).

**Tech Stack:** TypeScript ESM, Vitest, `@askmi/shared-crypto` (`issueSDJWTVC`, `validateSDJWTVC`, `buildCNFClaim`, `extractCNFPublicKey`, `generateHolderBinding`, `trustListResolver`), Express (issuer-mock), React (wallet-pwa). Node built-ins + `@noble/hashes` (already used) for hashing. No new third-party deps.

## Global Constraints

- **Fail-closed:** no holder proof → issuer does not issue; a credential whose issuer signature does not validate against the resolved key → not stored; issuance/storage is atomic (full credential + holder key, or nothing). *(spec §5)*
- **Persistent, trust-anchored, pluggable issuer:** issuer key is issuer-mock's persistent key, resolved via `trustListResolver` (`did:web:localhost%3A3005` + `/.well-known/jwks.json`). **No issuer key hardcoded in the wallet.** A real issuer plugs in via the trust list, no code change. *(spec §3.1, §3.4)*
- **Holder key = fresh single-use per credential** (unlinkability); reuse `generateHolderBinding()` / credential-pool machinery. Preserve pairwise-DID / single-use behavior. *(spec §1, §6)*
- **Present path untouched:** do NOT modify `presentOID4VP` / `SCENARIO_CLAIMS` sourcing — ADOPT-0a is issuance + storage only. *(spec §2, §7)*
- **No new third-party runtime deps.** Prettier (single quotes, 2-space, 100 width); no new `@typescript-eslint/no-explicit-any` warnings in production code.
- **Green bar:** `pnpm build` (30/30) + `pnpm test` (turbo) + `pnpm lint` (0 errors) + `pnpm guard:rebrand` + `pnpm evidence` (0 failed) all pass.
- **TDD mandatory:** RED → verify RED → GREEN → verify GREEN → REFACTOR. No production code without a failing test first.

---

## File structure

- `src/packages/shared-crypto/src/sd-jwt-vc.ts` — add `createSDJWTDisclosures()` (+ export).
- `src/packages/shared-crypto/src/__tests__/` or `test/` — disclosure tests (match the package's existing test location).
- `src/apps/issuer-mock/src/index.ts` — `/credential` issues `vc+sd-jwt`.
- `src/apps/issuer-mock/src/__tests__/` (or the app's test dir) — issuance test.
- `src/apps/wallet-pwa/src/services/WalletService.ts` — store full SD-JWT VC + holder key; trust-validate helper.
- `src/apps/wallet-pwa/src/App.tsx` — get-credential flow sends holder PoP, stores raw credential.
- `src/apps/wallet-pwa/src/__tests__/WalletService.test.ts` — storage + trust-validation + unlinkability tests.

---

## Task 1: SD-JWT disclosure primitive in shared-crypto

**Files:**
- Modify: `src/packages/shared-crypto/src/sd-jwt-vc.ts`
- Test: `src/packages/shared-crypto/src/sd-jwt-vc.test.ts` (create if absent; else the package's existing sd-jwt test file)

**Interfaces:**
- Produces: `createSDJWTDisclosures(claims: Record<string, unknown>): Promise<{ _sd: string[]; disclosures: string[] }>` — one salted disclosure per claim; `_sd[i]` = base64url(sha256(disclosures[i])). Uses the module's existing `sha256Base64url` helper.

- [ ] **Step 1: Write the failing test**

In `sd-jwt-vc.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { createSDJWTDisclosures } from './sd-jwt-vc';
import { sha256 } from '@noble/hashes/sha2';

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('createSDJWTDisclosures', () => {
  it('produces one disclosure + one digest per claim, digest = sha256(disclosure)', async () => {
    const { _sd, disclosures } = await createSDJWTDisclosures({ dateOfBirth: '1990-01-01', isOver18: true });
    expect(_sd).toHaveLength(2);
    expect(disclosures).toHaveLength(2);
    for (let i = 0; i < disclosures.length; i++) {
      expect(_sd).toContain(b64url(sha256(new TextEncoder().encode(disclosures[i]))));
    }
  });
  it('each disclosure decodes to [salt, name, value] with distinct salts', async () => {
    const { disclosures } = await createSDJWTDisclosures({ a: 1, b: 2 });
    const decoded = disclosures.map((d) =>
      JSON.parse(Buffer.from(d.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString())
    );
    expect(decoded[0][1]).toBe('a');
    expect(decoded[1][1]).toBe('b');
    expect(decoded[0][0]).not.toBe(decoded[1][0]); // distinct salts
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/shared-crypto exec vitest run src/sd-jwt-vc.test.ts -t createSDJWTDisclosures`
Expected: FAIL (`createSDJWTDisclosures` not exported).

- [ ] **Step 3: Implement in `sd-jwt-vc.ts`**

Add near the other exports (reuse the existing `sha256Base64url` in the file; confirm its name and import path while implementing):
```ts
function base64urlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Build SD-JWT selective-disclosure entries per IETF SD-JWT: for each claim a
 * salted `[salt, name, value]` disclosure and its base64url(sha256) digest.
 * The issuer puts `_sd` in the payload (claim omitted from the clear) and hands
 * the holder the `disclosures`.
 */
export async function createSDJWTDisclosures(
  claims: Record<string, unknown>
): Promise<{ _sd: string[]; disclosures: string[] }> {
  const _sd: string[] = [];
  const disclosures: string[] = [];
  for (const [name, value] of Object.entries(claims)) {
    const salt = base64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
    const disclosure = base64urlEncode(new TextEncoder().encode(JSON.stringify([salt, name, value])));
    disclosures.push(disclosure);
    _sd.push(await sha256Base64url(disclosure));
  }
  return { _sd, disclosures };
}
```

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/shared-crypto exec vitest run src/sd-jwt-vc.test.ts` then `pnpm --filter @askmi/shared-crypto build`
Expected: PASS + tsc 0 errors.

- [ ] **Step 5: Commit**
```bash
git add src/packages/shared-crypto/src/sd-jwt-vc.ts src/packages/shared-crypto/src/sd-jwt-vc.test.ts
git commit -m "feat(adopt-0a): SD-JWT selective-disclosure primitive (createSDJWTDisclosures)"
```

---

## Task 2: issuer-mock issues a real `vc+sd-jwt` bound to the wallet's holder key

**Files:**
- Modify: `src/apps/issuer-mock/src/index.ts` (`POST /credential`)
- Test: `src/apps/issuer-mock/src/index.test.ts` (create if absent; else the app's existing test file)

**Interfaces:**
- Consumes: `createSDJWTDisclosures` (Task 1), `issueSDJWTVC`, `buildCNFClaim`, `validateSDJWTVC`, `extractCNFPublicKey` from `@askmi/shared-crypto`; the persistent issuer keypair already in `index.ts`.
- Produces: `POST /credential` with body `{ proof: { jwk: <holder public JWK> }, ... }` → `{ format: 'vc+sd-jwt', credential: '<issuerJwt>~<disc>~...~', c_nonce, c_nonce_expires_in }`. Missing/invalid holder JWK → HTTP 400 `{ error: 'holder_proof_required' }`.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app, ready } from './index'; // export `app` (Express) and a `ready` promise for issuer key init if not already exported
import { validateSDJWTVC, extractCNFPublicKey } from '@askmi/shared-crypto';

async function holderJwk() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { pub: await crypto.subtle.exportKey('jwk', kp.publicKey) };
}

describe('issuer-mock /credential issues vc+sd-jwt', () => {
  it('rejects a request without a holder proof (fail-closed)', async () => {
    await ready;
    const res = await request(app).post('/credential').send({ credential_definition: { type: ['AgeCredential'] } });
    expect(res.status).toBe(400);
  });
  it('issues a vc+sd-jwt bound to the supplied holder key', async () => {
    await ready;
    const { pub } = await holderJwk();
    const res = await request(app).post('/credential').send({ proof: { jwk: pub }, credential_definition: { type: ['AgeCredential'] } });
    expect(res.status).toBe(200);
    expect(res.body.format).toBe('vc+sd-jwt');
    const issuerJwt = res.body.credential.split('~')[0];
    // issuer public key from the mock's jwks
    const jwks = await request(app).get('/.well-known/jwks.json');
    const issuerPub = await crypto.subtle.importKey('jwk', jwks.body.keys[0], { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const v = await validateSDJWTVC(issuerJwt, issuerPub);
    expect(v.ok).toBe(true);
    const cnf = await extractCNFPublicKey(v.payload!);
    expect(cnf).not.toBeNull();
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/issuer-mock exec vitest run` (or the app's test command)
Expected: FAIL (still returns `jwt_vc_json` / no holder-proof rejection / `app`/`ready` not exported).

- [ ] **Step 3: Implement**

In `index.ts`: export `app` and a `ready` promise if not already; replace the `/credential` body:
```ts
const holderJwk = (req.body?.proof?.jwk) as JsonWebKey | undefined;
if (!holderJwk || !holderJwk.kty) {
  return res.status(400).json({ error: 'holder_proof_required' });
}
const holderPub = await crypto.subtle.importKey('jwk', holderJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const cnf = await buildCNFClaim(holderPub);
const { _sd, disclosures } = await createSDJWTDisclosures({ dateOfBirth: '1990-01-01', isOver18: true });
const issuerJwt = await issueSDJWTVC(
  { iss: ISSUER_DID, vct: 'https://askmi.demo/vct/age-credential', cnf, _sd },
  issuerKeys.privateKey
);
const credential = `${issuerJwt}~${disclosures.join('~')}~`;
return res.json({ format: 'vc+sd-jwt', credential, c_nonce: crypto.randomUUID(), c_nonce_expires_in: 86400 });
```
(Keep the correlation-id handling. Import the new symbols from `@askmi/shared-crypto`.)

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/issuer-mock exec vitest run` then `pnpm --filter @askmi/issuer-mock build`
Expected: PASS + tsc 0 errors.

- [ ] **Step 5: Commit**
```bash
git add src/apps/issuer-mock/src/index.ts src/apps/issuer-mock/src/index.test.ts
git commit -m "feat(adopt-0a): issuer-mock issues real vc+sd-jwt bound to holder cnf"
```

---

## Task 3: Wallet stores the full SD-JWT VC + single-use holder key

**Files:**
- Modify: `src/apps/wallet-pwa/src/services/WalletService.ts` (add `addSdJwtVc`, extend retrieval)
- Test: `src/apps/wallet-pwa/src/__tests__/WalletService.test.ts`

**Interfaces:**
- Consumes: `generateHolderBinding()` (shared-crypto), `SecureStorage.save(id, data, meta)`, `StoredCredentialMetadata`.
- Produces: `addSdJwtVc(id: string, sdJwtVc: string, holderPrivateJwk: JsonWebKey, opts?: { singleUse?: boolean; poolId?: string }): Promise<void>` — stores `{ sdJwtVc, holderPrivateJwk }` as the credential `data` with `format: 'sd-jwt-vc'` metadata; and `getSdJwtVc(id): Promise<{ sdJwtVc: string; holderPrivateJwk: JsonWebKey } | null>`.

- [ ] **Step 1: Write the failing test**

```ts
it('stores and round-trips a full SD-JWT VC + holder key (not just claims)', async () => {
  const wallet = await makeWallet(); // existing helper in the test file
  const holder = { kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB', d: 'CC' } as JsonWebKey;
  await wallet.addSdJwtVc('vc-1', 'issuerJwt~disc1~disc2~', holder, { singleUse: true });
  const got = await wallet.getSdJwtVc('vc-1');
  expect(got?.sdJwtVc).toBe('issuerJwt~disc1~disc2~');
  expect(got?.holderPrivateJwk.d).toBe('CC');
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/wallet-pwa exec vitest run src/__tests__/WalletService.test.ts -t "full SD-JWT VC"`
Expected: FAIL (`addSdJwtVc` not defined).

- [ ] **Step 3: Implement in `WalletService.ts`**

```ts
async addSdJwtVc(
  id: string,
  sdJwtVc: string,
  holderPrivateJwk: JsonWebKey,
  opts: { singleUse?: boolean; poolId?: string } = {}
): Promise<void> {
  await this.ensureSeeded();
  if (!this.storage) throw new Error('Wallet locked');
  const meta: StoredCredentialMetadata = {
    id,
    issuer: 'did:web:localhost%3A3005',
    type: ['VerifiableCredential', 'AgeCredential'],
    issuedAt: new Date().toISOString(),
    claims: ['dateOfBirth', 'isOver18'],
    format: 'sd-jwt-vc' as StoredCredentialMetadata['format'],
    ...(opts.singleUse ? { singleUse: true } : {}),
    ...(opts.poolId ? { poolId: opts.poolId } : {}),
  };
  await this.storage.save(id, { sdJwtVc, holderPrivateJwk }, meta);
  await this.auditLog.append('KEY_USED', id, { context: 'OID4VCI_ISSUANCE_SDJWT', issuer: meta.issuer });
}

async getSdJwtVc(id: string): Promise<{ sdJwtVc: string; holderPrivateJwk: JsonWebKey } | null> {
  if (!this.storage) throw new Error('Wallet locked');
  const data = (await this.storage.load(id)) as { sdJwtVc?: string; holderPrivateJwk?: JsonWebKey } | null;
  if (!data?.sdJwtVc || !data.holderPrivateJwk) return null;
  return { sdJwtVc: data.sdJwtVc, holderPrivateJwk: data.holderPrivateJwk };
}
```
(Confirm the storage load method name — `load`/`get` — while implementing, matching the existing WalletService usage. `format` must be a valid `CredentialFormat` value; if `'sd-jwt-vc'` is not in the union, add it to `CredentialFormat` in shared-types in this task, with a test-safe value.)

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/wallet-pwa exec vitest run src/__tests__/WalletService.test.ts` then `pnpm --filter @askmi/wallet-pwa build`
Expected: PASS + build clean.

- [ ] **Step 5: Commit**
```bash
git add src/apps/wallet-pwa/src/services/WalletService.ts src/apps/wallet-pwa/src/__tests__/WalletService.test.ts src/packages/shared-types/src/policy.ts
git commit -m "feat(adopt-0a): wallet stores full SD-JWT VC + single-use holder key"
```

---

## Task 4: Wire the get-credential flow to real issuance (PoP + store raw credential)

**Files:**
- Modify: `src/apps/wallet-pwa/src/App.tsx` (the get-credential handler, ~1023-1066)
- Test: covered via Task 3 (WalletService) + a focused App-level assertion if the file has App tests; otherwise a WalletService-level `fetchAndStoreSdJwtVc` method + test.

**Interfaces:**
- Consumes: `addSdJwtVc` (Task 3), `generateHolderBinding()`.
- Produces: `WalletService.fetchAndStoreSdJwtVc(issuerEndpoint = 'http://localhost:3005/credential'): Promise<string>` — generates a single-use holder key, POSTs `{ proof: { jwk } }`, stores the returned `credential` + holder key via `addSdJwtVc`, returns the stored id. (Putting the fetch in WalletService keeps it testable and off the React component.)

- [ ] **Step 1: Write the failing test** (WalletService, fetch mocked)

```ts
it('fetchAndStoreSdJwtVc sends a holder PoP and stores the returned credential', async () => {
  const wallet = await makeWallet();
  const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    new Response(JSON.stringify({ format: 'vc+sd-jwt', credential: 'issuerJwt~d1~' }), { status: 200 })
  );
  const id = await wallet.fetchAndStoreSdJwtVc();
  const body = JSON.parse((spy.mock.calls[0][1] as RequestInit).body as string);
  expect(body.proof.jwk.kty).toBeTruthy();          // holder PoP sent
  const got = await wallet.getSdJwtVc(id);
  expect(got?.sdJwtVc).toBe('issuerJwt~d1~');         // raw credential stored
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/wallet-pwa exec vitest run src/__tests__/WalletService.test.ts -t fetchAndStoreSdJwtVc`
Expected: FAIL (`fetchAndStoreSdJwtVc` not defined).

- [ ] **Step 3: Implement `fetchAndStoreSdJwtVc` in WalletService, then call it from App.tsx**

WalletService:
```ts
async fetchAndStoreSdJwtVc(issuerEndpoint = 'http://localhost:3005/credential'): Promise<string> {
  const binding = await generateHolderBinding();
  const res = await fetch(issuerEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proof: { jwk: binding.publicJwk }, credential_definition: { type: ['VerifiableCredential', 'AgeCredential'] } }),
  });
  if (!res.ok) throw new Error(`Issuer returned ${res.status}`);
  const data = (await res.json()) as { credential?: string; error?: string };
  if (!data.credential) throw new Error(data.error ?? 'No credential in response');
  const id = `vc-sdjwt-${Date.now()}`;
  await this.addSdJwtVc(id, data.credential, binding.privateJwk, { singleUse: true });
  return id;
}
```
(Confirm `generateHolderBinding()`'s exact return field names — `publicJwk`/`privateJwk` vs `publicKey`/`jwk` — while implementing; import it from `@askmi/shared-crypto`.) In `App.tsx`, change the get-credential handler to call `walletRef.current.fetchAndStoreSdJwtVc()` and keep the existing success UI/log. Do NOT touch `presentOID4VP`.

- [ ] **Step 4: Run — verify pass + no present-path regression**

Run: `pnpm --filter @askmi/wallet-pwa test` then `pnpm --filter @askmi/wallet-pwa build`
Expected: PASS (incl. the pre-existing present/demo tests, unchanged) + build clean.

- [ ] **Step 5: Commit**
```bash
git add src/apps/wallet-pwa/src/services/WalletService.ts src/apps/wallet-pwa/src/App.tsx src/apps/wallet-pwa/src/__tests__/WalletService.test.ts
git commit -m "feat(adopt-0a): wallet get-credential sends holder PoP and stores the real SD-JWT VC"
```

---

## Task 5: Trust-list validation of the stored credential + unlinkability regression

**Files:**
- Modify: `src/apps/wallet-pwa/src/services/WalletService.ts` (add `validateStoredIssuerSignature`)
- Test: `src/apps/wallet-pwa/src/__tests__/WalletService.test.ts`

**Interfaces:**
- Consumes: `getSdJwtVc` (Task 3), `validateSDJWTVC`, `trustListResolver` (resolve the issuer key for `ISSUER_DID`).
- Produces: `validateStoredIssuerSignature(id: string, resolveIssuerKey: (iss: string) => Promise<CryptoKey | JsonWebKey | null>): Promise<boolean>` — loads the stored credential, resolves the issuer key via the injected resolver, `validateSDJWTVC(issuerJwt, key)`; true only if `ok`.

- [ ] **Step 1: Write the failing tests**

```ts
it('validates a stored credential against the resolved issuer key; a swapped key fails', async () => {
  const wallet = await makeWallet();
  // build a real issuer-signed credential in-test (reuse issueSDJWTVC + a generated issuer key)
  const issuer = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { issueSDJWTVC, buildCNFClaim } = await import('@askmi/shared-crypto');
  const holder = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwt = await issueSDJWTVC({ iss: 'did:web:localhost%3A3005', vct: 'x', cnf: await buildCNFClaim(holder.publicKey) }, issuer.privateKey);
  await wallet.addSdJwtVc('vc-2', `${jwt}~`, { kty: 'EC', crv: 'P-256', x: 'a', y: 'b', d: 'c' } as JsonWebKey, {});
  const good = await wallet.validateStoredIssuerSignature('vc-2', async () => issuer.publicKey);
  expect(good).toBe(true);
  const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const bad = await wallet.validateStoredIssuerSignature('vc-2', async () => other.publicKey);
  expect(bad).toBe(false);
});

it('two issued credentials carry distinct holder cnf (unlinkability)', async () => {
  const a = await generateHolderBinding();
  const b = await generateHolderBinding();
  expect(JSON.stringify(a.publicJwk)).not.toBe(JSON.stringify(b.publicJwk));
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/wallet-pwa exec vitest run src/__tests__/WalletService.test.ts -t "resolved issuer key"`
Expected: FAIL (`validateStoredIssuerSignature` not defined).

- [ ] **Step 3: Implement**
```ts
async validateStoredIssuerSignature(
  id: string,
  resolveIssuerKey: (iss: string) => Promise<CryptoKey | JsonWebKey | null>
): Promise<boolean> {
  const stored = await this.getSdJwtVc(id);
  if (!stored) return false;
  const issuerJwt = stored.sdJwtVc.split('~')[0];
  const iss = JSON.parse(atob(issuerJwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).iss as string;
  const key = await resolveIssuerKey(iss);
  if (!key) return false;
  const r = await validateSDJWTVC(issuerJwt, key);
  return r.ok === true;
}
```

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/wallet-pwa test`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/apps/wallet-pwa/src/services/WalletService.ts src/apps/wallet-pwa/src/__tests__/WalletService.test.ts
git commit -m "test(adopt-0a): validate stored credential vs trust-resolved issuer key + unlinkability"
```

---

## Task 6: Final green bar + PR

- [ ] **Step 1: Full verification**

Run: `pnpm build` then `pnpm test` then `pnpm lint` then `pnpm guard:rebrand` then `pnpm evidence`
Expected: build 30/30; turbo test all green; lint 0 errors (7 pre-existing wallet-pwa warnings unchanged); guard passed; evidence 10 proven / 2 residual / 0 failed. Delete any newly-generated evidence report so the tree is clean.

- [ ] **Step 2: Push + PR**
```bash
git push -u origin feat/adopt-0-real-presentation
gh pr create --title "ADOPT-0a: real SD-JWT VC issuance + storage" --body "issuer-mock issues a real vc+sd-jwt (persistent issuer key, cnf from the wallet's single-use holder-key PoP, _sd disclosures); the wallet sends the PoP and stores the full signed credential + holder key (no longer discards the signature). validateSDJWTVC passes against the trust-list-resolved issuer key; a swapped key fails. Present path untouched (ADOPT-0b). A real issuer plugs in via the trust list, no code change. Verified: build 30/30, tests green, lint 0 errors, guard + evidence green."
```

---

## Self-Review (completed by author)

**1. Spec coverage:** §3.1 issuer SD-JWT + cnf → Task 2 (+ Task 1 disclosures). §3.2 wallet holder key + PoP + store → Tasks 3, 4. §3.3 storage schema → Task 3. §3.4 trust anchoring → Task 5. §5 fail-closed (no proof, swapped key) → Tasks 2, 5. §6 tests → each task. §7 DoD (present untouched) → Task 4 constraint + no `presentOID4VP` edits anywhere. ✓

**2. Placeholder scan:** No TBD/TODO. Three "confirm the exact name while implementing" notes (`sha256Base64url`, storage `load`/`get`, `generateHolderBinding` field names, `CredentialFormat` union) are concrete verification steps against named symbols the plan already located — not vague directives; each has a fallback action. Complete code shown for every production change.

**3. Type consistency:** `addSdJwtVc`/`getSdJwtVc`/`fetchAndStoreSdJwtVc`/`validateStoredIssuerSignature`/`createSDJWTDisclosures` names + signatures are consistent across tasks; `{ sdJwtVc, holderPrivateJwk }` storage shape is used identically in Tasks 3, 5; the `~`-joined credential format (`issuerJwt~disc~`) is consistent in Tasks 2, 3, 5.
