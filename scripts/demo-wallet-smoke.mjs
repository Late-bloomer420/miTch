import assert from 'node:assert/strict';
import { chromium } from 'playwright';

// Run against pnpm demo. An isolated browser context and virtual authenticator
// prevent this check from reading or modifying the user's browser/passkeys.
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 1200 } });
const store = await context.newPage();
const wallet = await context.newPage();
const cdp = await context.newCDPSession(wallet);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});
const presentations = [];
const isPresentation = (request) =>
  request.method() === 'POST' && request.url().endsWith('/presentation');
wallet.on('request', (request) => {
  if (isPresentation(request)) presentations.push(request.url());
});
try {
  await store.goto('http://localhost:5185/?flow=connect');
  await store.getByRole('button', { name: 'Start age verification' }).click();
  const link = store.getByRole('link', { name: 'Open in wallet' });
  await link.waitFor();
  const handoff = await link.getAttribute('href');
  assert.equal(new URL(handoff).origin, 'http://localhost:5184');
  await wallet.goto(handoff);
  await wallet.getByRole('button', { name: 'Create my AskMI account' }).click();
  await wallet.getByRole('button', { name: 'Get demo age credential' }).click();
  await wallet.getByRole('button', { name: 'Test credential ready', exact: true }).waitFor();
  await wallet.getByRole('button', { name: 'Accept & Prove', exact: false }).click();
  await wallet.getByRole('button', { name: 'Approve Disclosure', exact: false }).waitFor();
  assert.equal(presentations.length, 0, 'No presentation before consent');
  await wallet.getByRole('button', { name: 'Approve Disclosure', exact: false }).click();
  await store
    .getByRole('status')
    .filter({ hasText: 'Age eligibility confirmed' })
    .waitFor({ timeout: 20000 });
  assert.equal(presentations.length, 1);
  const databases = await wallet.evaluate(async () =>
    (await indexedDB.databases()).map((db) => db.name)
  );
  assert.ok(databases.includes('askmi_demo_wallet_v1'));
  assert.ok(!databases.includes('mitch_wallet_v1'));

  await store.reload();
  await store.getByRole('button', { name: 'Start age verification' }).click();
  await link.waitFor();
  const declined = await link.getAttribute('href');
  await wallet.goto(declined);
  // The passkey enrolled above makes this a returning wallet, which stays locked
  // behind an overlay until the user unlocks it.
  await wallet.getByRole('button', { name: 'Unlock with Biometrics', exact: true }).click();
  const decline = wallet.getByRole('button', { name: 'Decline request', exact: true });
  await decline.click();
  await decline.waitFor({ state: 'hidden' });
  // A presentation sent by mistake would leave after the click, so watch for one
  // instead of checking the counter straight away.
  const late = await wallet.waitForRequest(isPresentation, { timeout: 2000 }).catch(() => null);
  assert.equal(late, null, 'Decline sends no presentation');
  assert.equal(presentations.length, 1, 'Decline sends no presentation');
  const id = new URL(declined).searchParams.get('state');
  const session = await (await fetch(`http://localhost:3104/askmi/connect/sessions/${id}`)).json();
  assert.equal(session.status, 'pending');
  assert.equal(session.result, undefined);

  // The built-in age check encrypts to the verifier key, so it must find this
  // demo's verifier on port 3104.
  await wallet.goto('http://localhost:5184/?demo=wallet');
  await wallet.getByRole('button', { name: 'Unlock with Biometrics', exact: true }).click();
  await wallet.getByRole('button', { name: 'Requests', exact: true }).click();
  const responseFrom = (url, method) =>
    wallet.waitForResponse(
      (response) =>
        response.url() === url && response.request().method() === method && response.ok(),
      { timeout: 15000 }
    );
  await Promise.all([
    responseFrom('http://localhost:3104/did.json', 'GET'),
    responseFrom('http://localhost:3104/present', 'POST'),
    (async () => {
      await wallet.locator('#btn-liquor-store').click();
      await wallet.getByRole('button', { name: 'Approve Disclosure', exact: false }).click();
    })(),
  ]);

  await wallet.goto('http://localhost:5184/?state=askmi_sess_');
  await wallet.getByRole('heading', { name: 'Invalid wallet request' }).waitFor();
  console.log(
    'PASS: store handoff, virtual-passkey enrollment, mock issuance, consent-before-presentation, verified eligibility, demo database, decline, built-in age check and malformed link.'
  );
} catch (error) {
  await wallet
    .getByRole('button', { name: 'Audit', exact: true })
    .click({ timeout: 1000 })
    .catch(() => {});
  console.error('Wallet UI:', await wallet.locator('body').innerText());
  console.error('Store UI:', await store.locator('body').innerText());
  throw error;
} finally {
  await browser.close();
}
