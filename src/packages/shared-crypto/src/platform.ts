/**
 * Cross‑platform WebCrypto abstraction.
 *
 * In the browser `globalThis.crypto` is the native WebCrypto API.
 * In Node we fall back to the bundled WebCrypto implementation
 * (`require('crypto').webcrypto`).
 */
export const crypto: Crypto = (() => {
    if (typeof globalThis.crypto !== 'undefined') {
        return globalThis.crypto;
    }
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require('crypto').webcrypto;
    return nodeCrypto;
})();
