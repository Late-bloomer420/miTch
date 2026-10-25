# ADOPT-0b — Real Credential Presentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Present the real stored SD-JWT VC (ADOPT-0a) via selective disclosure + a real KB-JWT with the issuer signature preserved, and make the verifier check that signature against a **trust-list-resolved issuer key** (not the wallet-supplied one) — removing the ephemeral-issuer + `SCENARIO_CLAIMS` fabrication.

**Architecture:** New no-issuer-key `buildSdJwtPresentation` in shared-crypto (select disclosures + KB-JWT); `WalletService.presentStoredSdJwtVc` loads the stored credential + holder key and builds the vp_token; `presentOID4VP` swaps its fabrication core for that call (keeping consent/POST/shred); the verifier resolves the issuer key from the credential's `iss` via trust-list/`did:web` JWKS instead of trusting `body.issuer_jwk`.

**Tech Stack:** TypeScript ESM, Vitest, `@askmi/shared-crypto` (`createKeyBindingJWT`, `getSdJwtVc`, `trustListResolver`), Express (verifier), React (wallet). No new third-party deps.

## Global Constraints

- **Fail-closed:** no stored credential matching the request → present nothing (clear message), **never** `SCENARIO_CLAIMS`/fabrication fallback; issuer-sig or KB-JWT failure at the verifier → reject; issuer key unresolvable/untrusted → reject. *(spec §5)*
- **Issuer signature preserved + verified against the authoritative key.** The presented `issuerJwt` is byte-unchanged; the verifier resolves the issuer key from the credential's `iss` via the trust list / `did:web` JWKS — **not** from a wallet-supplied `issuer_jwk`. *(spec §2, §3.4)*
- **Keep the working UX:** consent, POST to `redirect_uri`, session cleanup/shred, audit — unchanged. Only the fabrication core is replaced. *(spec §3.3)*
- **Unlinkability + crypto-shredding unchanged** (holder key per credential). *(spec §7)*
- No new third-party deps. Prettier; no new production `@typescript-eslint/no-explicit-any`.
- **jose `SignJWT` fails under wallet-pwa jsdom** — KB-JWT-signing tests use a Node-env test or the ADOPT-0a Task-5 WebCrypto approach. *(spec §6, §8)*
- **Green bar:** `pnpm build` (30/30) + `pnpm test` + `pnpm lint` (0 errors) + `pnpm guard:rebrand` + `pnpm evidence` (0 failed) all pass. TDD mandatory.

---

## File structure

- `src/packages/shared-crypto/src/sd-jwt-vc.ts` — add `buildSdJwtPresentation()`.
- `src/packages/shared-crypto/src/sd-jwt-vc.test.ts` — presentation-builder test.
- `src/apps/wallet-pwa/src/services/WalletService.ts` — add `presentStoredSdJwtVc()`.
- `src/apps/wallet-pwa/src/__tests__/WalletService.test.ts` — wallet present-from-storage test.
- `src/apps/wallet-pwa/src/App.tsx` — `presentOID4VP`: swap fabrication for the real path; drop `issuer_jwk` from the POST.
- `src/apps/verifier-demo/backend/src/app.ts` — `/oid4vp-present`: resolve issuer key from trust list, not `body.issuer_jwk`.
- `src/apps/verifier-demo/backend/src/__tests__/` — verifier issuer-resolution test.

---

## Task 1: `buildSdJwtPresentation` — present a pre-issued credential (no issuer key)

**Files:**
- Modify: `src/packages/shared-crypto/src/sd-jwt-vc.ts`
- Test: `src/packages/shared-crypto/src/sd-jwt-vc.test.ts`

**Interfaces:**
- Consumes: `createKeyBindingJWT({ aud, nonce, sdJwtWithDisclosures }, holderPrivateKey)` (existing).
- Produces: `buildSdJwtPresentation(sdJwtVc: string, requestedClaimNames: string[], holderPrivateKey: CryptoKey, opts: { aud: string; nonce: string }): Promise<{ vpToken: string; disclosedClaims: Record<string, unknown> }>` — keeps the issuer JWT unchanged, includes only disclosures whose claim name is requested, appends a KB-JWT.

- [ ] **Step 1: Write the failing test** (Node env — the package's default)

In `sd-jwt-vc.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { buildSdJwtPresentation, createSDJWTDisclosures } from './sd-jwt-vc';

function b64urlDecode(s: string): string {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
}

describe('buildSdJwtPresentation', () => {
  it('discloses only requested claims, preserves the issuer JWT, appends a KB-JWT', async () => {
    const { disclosures } = await createSDJWTDisclosures({ dateOfBirth: '1990-01-01', isOver18: true });
    const issuerJwt = 'HEADER.PAYLOAD.SIG';
    const stored = `${issuerJwt}~${disclosures.join('~')}~`;
    const holder = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

    const { vpToken, disclosedClaims } = await buildSdJwtPresentation(
      stored, ['isOver18'], holder.privateKey, { aud: 'did:verifier', nonce: 'n1' }
    );

    const parts = vpToken.split('~');
    expect(parts[0]).toBe(issuerJwt);                                  // issuer JWT preserved
    const kb = parts[parts.length - 1];
    expect(JSON.parse(b64urlDecode(kb.split('.')[1])).typ ?? 'kb+jwt').toBeTruthy();
    // exactly one disclosure kept (isOver18), dateOfBirth dropped
    const kept = parts.slice(1, -1).filter((p) => p.length > 0);
    expect(kept).toHaveLength(1);
    expect(JSON.parse(b64urlDecode(kept[0]))[1]).toBe('isOver18');
    expect(disclosedClaims).toEqual({ isOver18: true });
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/shared-crypto exec vitest run src/sd-jwt-vc.test.ts -t buildSdJwtPresentation`
Expected: FAIL (`buildSdJwtPresentation` not exported).

- [ ] **Step 3: Implement in `sd-jwt-vc.ts`**

```ts
export async function buildSdJwtPresentation(
  sdJwtVc: string,
  requestedClaimNames: string[],
  holderPrivateKey: CryptoKey,
  opts: { aud: string; nonce: string }
): Promise<{ vpToken: string; disclosedClaims: Record<string, unknown> }> {
  const segments = sdJwtVc.split('~');
  const issuerJwt = segments[0];
  // middle segments are disclosures; trailing '' (from the final '~') and any KB-JWT are ignored
  const allDisclosures = segments.slice(1).filter((s) => s.length > 0 && !s.includes('.'));
  const requested = new Set(requestedClaimNames);
  const selected: string[] = [];
  const disclosedClaims: Record<string, unknown> = {};
  for (const d of allDisclosures) {
    let decoded: [string, string, unknown];
    try {
      decoded = JSON.parse(
        new TextDecoder().decode(
          Uint8Array.from(atob(d.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
        )
      );
    } catch {
      continue;
    }
    const [, name, value] = decoded;
    if (requested.has(name)) {
      selected.push(d);
      disclosedClaims[name] = value;
    }
  }
  const presented = `${issuerJwt}~${selected.join('~')}~`;
  const kbJwt = await createKeyBindingJWT(
    { aud: opts.aud, nonce: opts.nonce, sdJwtWithDisclosures: presented },
    holderPrivateKey
  );
  return { vpToken: `${presented}${kbJwt}`, disclosedClaims };
}
```

- [ ] **Step 4: Run — verify pass + build**

Run: `pnpm --filter @askmi/shared-crypto exec vitest run src/sd-jwt-vc.test.ts` then `pnpm --filter @askmi/shared-crypto build`
Expected: PASS + tsc 0 errors.

- [ ] **Step 5: Commit**
```bash
git add src/packages/shared-crypto/src/sd-jwt-vc.ts src/packages/shared-crypto/src/sd-jwt-vc.test.ts
git commit -m "feat(adopt-0b): buildSdJwtPresentation — present a pre-issued credential (no issuer key)"
```

---

## Task 2: `WalletService.presentStoredSdJwtVc` — present from storage (fail-closed)

**Files:**
- Modify: `src/apps/wallet-pwa/src/services/WalletService.ts`
- Test: `src/apps/wallet-pwa/src/__tests__/WalletService.test.ts`

**Interfaces:**
- Consumes: `getSdJwtVc(id)` (ADOPT-0a) → `{ sdJwtVc, holderPrivateJwk } | null`; `buildSdJwtPresentation` (Task 1).
- Produces: `presentStoredSdJwtVc(credentialId: string, requestedClaimNames: string[], opts: { aud: string; nonce: string }): Promise<{ vpToken: string; disclosedClaims: Record<string, unknown> } | null>` — null when no stored credential.

- [ ] **Step 1: Write the failing test**

```ts
it('presentStoredSdJwtVc builds a vp_token from the stored credential; null when absent', async () => {
  const wallet = await makeWallet();
  // store a credential whose disclosures include isOver18 (reuse createSDJWTDisclosures)
  const { createSDJWTDisclosures } = await import('@askmi/shared-crypto');
  const { disclosures } = await createSDJWTDisclosures({ dateOfBirth: '1990-01-01', isOver18: true });
  const holder = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const holderJwk = await crypto.subtle.exportKey('jwk', holder.privateKey);
  await wallet.addSdJwtVc('vc-p', `HDR.PL.SIG~${disclosures.join('~')}~`, holderJwk, {});

  const out = await wallet.presentStoredSdJwtVc('vc-p', ['isOver18'], { aud: 'did:v', nonce: 'n' });
  expect(out?.disclosedClaims).toEqual({ isOver18: true });
  expect(out?.vpToken.startsWith('HDR.PL.SIG~')).toBe(true);

  const none = await wallet.presentStoredSdJwtVc('missing', ['isOver18'], { aud: 'did:v', nonce: 'n' });
  expect(none).toBeNull();
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/wallet-pwa exec vitest run src/__tests__/WalletService.test.ts -t presentStoredSdJwtVc`
Expected: FAIL (`presentStoredSdJwtVc` not defined).

- [ ] **Step 3: Implement in `WalletService.ts`**

```ts
async presentStoredSdJwtVc(
  credentialId: string,
  requestedClaimNames: string[],
  opts: { aud: string; nonce: string }
): Promise<{ vpToken: string; disclosedClaims: Record<string, unknown> } | null> {
  const stored = await this.getSdJwtVc(credentialId);
  if (!stored) return null;
  const holderKey = await crypto.subtle.importKey(
    'jwk', stored.holderPrivateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  return buildSdJwtPresentation(stored.sdJwtVc, requestedClaimNames, holderKey, opts);
}
```
(Import `buildSdJwtPresentation` from `@askmi/shared-crypto`.)

- [ ] **Step 4: Run — verify pass + build**

Run: `pnpm --filter @askmi/wallet-pwa exec vitest run src/__tests__/WalletService.test.ts` then `pnpm --filter @askmi/wallet-pwa build`
Expected: PASS + build clean.

- [ ] **Step 5: Commit**
```bash
git add src/apps/wallet-pwa/src/services/WalletService.ts src/apps/wallet-pwa/src/__tests__/WalletService.test.ts
git commit -m "feat(adopt-0b): WalletService.presentStoredSdJwtVc (fail-closed present from storage)"
```

---

## Task 3: `presentOID4VP` — swap the fabrication core for the real path

**Files:**
- Modify: `src/apps/wallet-pwa/src/App.tsx` (`presentOID4VP` ~820-939)
- Test: covered by Task 2 (WalletService) + updating any App test that asserted the fabricated path.

**Interfaces:**
- Consumes: `presentStoredSdJwtVc` (Task 2); the request's `nonce`, verifier DID (audience), and requested claim names (already derived in `handleIncomingOID4VP` as `authRequest.presentation_definition.input_descriptors.flatMap(d => d.constraints?.fields?.flatMap(f => f.path.map(p => p.replace('$.',''))))`).

- [ ] **Step 1: Locate the fabrication + a stored credential id**

In `presentOID4VP`, the fabrication is: ephemeral `holderKeys`/`issuerKeys` keygen (~833-840), `const claims = SCENARIO_CLAIMS[scenarioId]` (~842), the `buildSDJWTPresentation({ ... issuerPrivateKey, holderKeyPair, claims, ... })` call (~846), and the `issuer_jwk` field in the POST payload. The wallet must have a stored credential id — use the most recent `sd-jwt-vc`-format credential from `getCredentials()` (or a dedicated `getLatestSdJwtVcId()` helper) as the credential to present.

- [ ] **Step 2: Write/adjust the failing test**

Add a WalletService-level test (App.tsx UI logic is thin) asserting that presenting with a stored credential produces a real vp_token and that **presenting with no stored credential is fail-closed** (the App handler shows an error, no POST). If App has a test harness for `presentOID4VP`, assert the POST body has **no `issuer_jwk`** and the `vp_token` came from `presentStoredSdJwtVc`. Otherwise rely on Task 2's coverage + a manual note; do not fabricate a test that asserts nothing.

- [ ] **Step 3: Implement the swap**

Replace the fabrication block with:
```ts
const requestedClaimNames = authRequest.presentation_definition.input_descriptors.flatMap(
  (d) => d.constraints?.fields?.flatMap((f) => f.path.map((p) => p.replace('$.', ''))) ?? []
);
const credId = await walletRef.current.getLatestSdJwtVcId(); // returns null if none
if (!credId) {
  addLog('❌ No stored credential — fetch a credential from the issuer first.', 'error');
  setStatus('IDLE');
  return;
}
const presented = await walletRef.current.presentStoredSdJwtVc(credId, requestedClaimNames, {
  aud: verifier, nonce: authRequest.nonce,
});
if (!presented) {
  addLog('❌ No matching credential for this request.', 'error');
  setStatus('IDLE');
  return;
}
const { vpToken: vpTokenString, disclosedClaims } = presented;
```
Then POST `{ vp_token: vpTokenString, presentation_submission, state: authRequest.state }` — **remove `issuer_jwk`** from the payload. Keep the padding/jitter, the result handling, `buildSessionCleanup`, and the `finally` shred (adjust the `finally` since there are no `issuerKeys` to null now — remove those two lines). Add `getLatestSdJwtVcId(): Promise<string | null>` to WalletService (returns the id of the newest credential whose metadata `format === 'sd-jwt-vc'`, else null).

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/wallet-pwa test` then `pnpm --filter @askmi/wallet-pwa build`
Expected: PASS (fabrication tests updated to the real/fail-closed path) + build clean.

- [ ] **Step 5: Commit**
```bash
git add src/apps/wallet-pwa/src/App.tsx src/apps/wallet-pwa/src/services/WalletService.ts src/apps/wallet-pwa/src/__tests__
git commit -m "feat(adopt-0b): presentOID4VP presents the real stored credential (no fabrication)"
```

---

## Task 4: Verifier resolves the issuer key from the trust list (not the wallet)

**Files:**
- Modify: `src/apps/verifier-demo/backend/src/app.ts` (`/oid4vp-present` ~271-336)
- Test: `src/apps/verifier-demo/backend/src/__tests__/oid4vp-present.test.ts` (create; else the backend's existing test dir)

**Interfaces:**
- Consumes: `trustListResolver.isIssuerTrusted(did)`; a `did:web` → JWKS resolver (issuer-mock exposes `http://localhost:3005/.well-known/jwks.json`; `ISSUER_DID = did:web:localhost%3A3005`).
- Produces: the route verifies the SD-JWT VP's issuer signature against the **resolved** issuer key (from the credential's `iss`), not `body.issuer_jwk`.

- [ ] **Step 1: Write the failing test**

A test that POSTs a vp_token built from a credential signed by key A, with the trust-list/JWKS resolving to key A → `ok: true`; and asserts that supplying a **different** `body.issuer_jwk` (key B) does **not** make a key-A-signed credential verify against B (i.e. the route ignores `body.issuer_jwk` and uses the resolved key). Use a stubbed issuer-key resolver injected for the test, or point the JWKS fetch at a test double. (If the route can't be unit-tested without a live issuer-mock, add a small exported `resolveIssuerKeyForPresentation(iss)` helper and test that in isolation: trusted+resolvable → CryptoKey; untrusted → throws/null.)

- [ ] **Step 2: Run — verify it fails**

Run: the backend test command (e.g. `pnpm --filter verifier-backend exec vitest run`)
Expected: FAIL (route still uses `body.issuer_jwk` / helper missing).

- [ ] **Step 3: Implement**

Add `resolveIssuerKeyForPresentation(iss: string): Promise<CryptoKey | null>`: reject if `!(await trustListResolver.isIssuerTrusted(iss)).isTrusted`; map `iss` (`did:web:HOST` where HOST is percent-encoded) to `http://<decoded-host>/.well-known/jwks.json`, fetch, import `keys[0]` as ECDSA P-256. In `/oid4vp-present`: extract `iss` from the vp_token's issuer JWT payload (`JSON.parse(atob(vpToken.split('~')[0].split('.')[1]...)).iss`); `const issuerPublicKey = await resolveIssuerKeyForPresentation(iss)`; if null → `403 { ok:false, error:'untrusted_or_unresolvable_issuer' }`. Use that `issuerPublicKey` in `validateSDJWTPresentation`. **Stop requiring / using `body.issuer_jwk`** (a wallet-supplied issuer key must not influence verification).

- [ ] **Step 4: Run — verify pass + build**

Run: backend test + `pnpm --filter verifier-backend build`
Expected: PASS + build clean.

- [ ] **Step 5: Commit**
```bash
git add src/apps/verifier-demo/backend/src
git commit -m "feat(adopt-0b): verifier resolves issuer key from trust list, ignores wallet-supplied key"
```

---

## Task 5: End-to-end + final green bar + PR

- [ ] **Step 1: End-to-end assertion**

Add one integration test (in `@askmi/integration-tests` or the verifier backend) that: builds a presentation from a real issuer-mock-signed stored credential (issuer key A), and asserts the verifier route/helper verifies it against the A-resolved key (→ ok) and **fails** against a swapped key B — proving the real issuer signature is carried end-to-end, not a self-signed fabrication.

- [ ] **Step 2: Full verification**

Run: `pnpm build` then `pnpm test` then `pnpm lint` then `pnpm guard:rebrand` then `pnpm evidence`
Expected: build 30/30; turbo test green; lint 0 errors (7 pre-existing wallet-pwa warnings unchanged); guard passed; evidence 10/2/0. Delete any newly-generated evidence report so the tree is clean.

- [ ] **Step 3: Push + PR**
```bash
git push -u origin feat/adopt-0b-real-presentation
gh pr create --title "ADOPT-0b: real credential presentation (from the stored SD-JWT VC)" --body "Replaces the presentOID4VP fabrication (ephemeral issuer keys + SCENARIO_CLAIMS + self-signed) with real presentation from the ADOPT-0a stored credential: buildSdJwtPresentation (select requested disclosures + real KB-JWT, issuer signature preserved), WalletService.presentStoredSdJwtVc, and the verifier now resolves the issuer key from the trust list (did:web JWKS) instead of trusting the wallet-supplied issuer_jwk — closing the circular-verification gap. Fail-closed no-match (no fabrication fallback); consent/POST/shred + unlinkability unchanged. Verified: build 30/30, tests green, lint 0 errors, guard + evidence green."
```

---

## Self-Review (completed by author)

**1. Spec coverage:** §3.1 new no-issuer-key builder → Task 1. §3.2 present-from-storage → Task 2. §3.3 App swap + drop issuer_jwk + fail-closed → Task 3. §3.4 verifier resolves issuer key from trust list → Task 4. §5 fail-closed (no-match, untrusted issuer) → Tasks 2, 3, 4. §6 tests incl. jose/jsdom note → Task 1 (Node env) + Task 4. §7 DoD (issuer preserved, fabrication removed, verifier trust-resolves) → Tasks 1, 3, 4 + Task 5 e2e. Unlinkability unchanged → Task 3 keeps holder key per credential.

**2. Placeholder scan:** No TBD. Task 3 Step 2 explicitly avoids a nothing-asserting test (rely on Task 2 coverage if App has no present harness). Task 4 Step 1 offers an isolatable helper (`resolveIssuerKeyForPresentation`) so the route is testable — concrete, not vague. `getLatestSdJwtVcId` is defined in Task 3 Step 3.

**3. Type consistency:** `buildSdJwtPresentation(sdJwtVc, requestedClaimNames, holderPrivateKey, {aud,nonce}) → {vpToken, disclosedClaims}`, `presentStoredSdJwtVc(credentialId, requestedClaimNames, {aud,nonce})`, `getSdJwtVc → {sdJwtVc, holderPrivateJwk}` (0a), `resolveIssuerKeyForPresentation(iss)`, `getLatestSdJwtVcId()` are consistent across tasks. The `~`-joined credential format is used identically in Tasks 1-4.
