/**
 * Simulated platform authenticator for tests: a real P-256 key that answers
 * navigator.credentials.create/get the way a browser passkey does, including
 * DER-encoded signatures over authenticatorData || SHA-256(clientDataJSON).
 */
const enc = new TextEncoder();

export const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

export function p1363ToDer(sig: Uint8Array): Uint8Array<ArrayBuffer> {
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

export interface SignOptions {
  rpId: string;
  challenge: ArrayBuffer | Uint8Array;
  origin?: string;
  flags?: number;
  type?: string;
}

export async function makeKeyPair() {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  return {
    keys,
    jwk: await crypto.subtle.exportKey('jwk', keys.publicKey),
    spki: await crypto.subtle.exportKey('spki', keys.publicKey),
  };
}

/** Produce the raw assertion parts a browser returns for navigator.credentials.get. */
export async function signAssertion(privateKey: CryptoKey, opts: SignOptions) {
  const challenge =
    opts.challenge instanceof Uint8Array ? opts.challenge : new Uint8Array(opts.challenge);
  const clientDataJSON = enc.encode(
    JSON.stringify({
      type: opts.type ?? 'webauthn.get',
      challenge: b64url(challenge),
      origin: opts.origin ?? 'https://wallet.example',
    })
  );
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(await sha256(enc.encode(opts.rpId)), 0);
  authenticatorData[32] = opts.flags ?? 0x05; // UP | UV
  authenticatorData.set([0, 0, 0, 7], 33);
  const signed = new Uint8Array([...authenticatorData, ...(await sha256(clientDataJSON))]);
  const p1363 = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signed)
  );
  return { authenticatorData, clientDataJSON, signature: p1363ToDer(p1363) };
}

/**
 * navigator.credentials stand-in backed by one P-256 key.
 * `publicKey: null` simulates an authenticator whose getPublicKey() returns nothing.
 */
export async function fakePlatformAuthenticator(opts: { exposePublicKey?: boolean } = {}) {
  const pair = await makeKeyPair();
  const rawId = Uint8Array.of(9, 8, 7, 6).buffer;
  const credentials = {
    create: async () => ({
      rawId,
      response: {
        getPublicKey: () => (opts.exposePublicKey === false ? null : pair.spki),
        getPublicKeyAlgorithm: () => -7,
      },
    }),
    get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
      const parts = await signAssertion(pair.keys.privateKey, {
        rpId: publicKey.rpId!,
        challenge: publicKey.challenge as ArrayBuffer,
      });
      return {
        rawId,
        response: {
          authenticatorData: parts.authenticatorData.buffer,
          clientDataJSON: parts.clientDataJSON.buffer,
          signature: parts.signature.buffer,
        },
      };
    },
  };
  return { ...pair, credentials };
}
