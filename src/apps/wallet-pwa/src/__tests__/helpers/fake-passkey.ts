import { identityChallenge, type IdentityAssertion } from '@askmi/shared-crypto';

/**
 * A simulated device passkey for wallet tests: a real P-256 key that produces
 * WebAuthn assertions (authenticatorData || SHA-256(clientDataJSON), DER
 * signature) with the challenge SHA-256(data), like signWithIdentityKeyAssertion.
 */
const enc = new TextEncoder();

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

function p1363ToDer(sig: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = Uint8Array.of(0, ...v);
    return Uint8Array.of(0x02, v.length, ...v);
  };
  const r = int(sig.slice(0, 32));
  const s = int(sig.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

export async function fakePasskey(rpId = 'wallet.example') {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);

  async function sign(data: string): Promise<IdentityAssertion> {
    const clientDataJSON = enc.encode(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: b64url(new Uint8Array(await identityChallenge(data))),
        origin: `https://${rpId}`,
      })
    );
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(await sha256(enc.encode(rpId)), 0);
    authenticatorData[32] = 0x05; // UP | UV
    const signed = new Uint8Array([...authenticatorData, ...(await sha256(clientDataJSON))]);
    const sig = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, signed)
    );
    return {
      version: 1,
      credentialId: 'cred-1',
      rpId,
      authenticatorData: b64url(authenticatorData),
      clientDataJSON: b64url(clientDataJSON),
      signature: b64url(p1363ToDer(sig)),
    };
  }

  return { jwk, rpId, sign };
}
