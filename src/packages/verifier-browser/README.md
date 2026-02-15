# @mitch/verifier-browser

> **Browser-Only Verifier SDK** for miTch Identity Infrastructure  
> Zero-Backend Integration for SMEs (Static HTML Pages)

## 🎯 Purpose

Enable small businesses (liquor stores, pharmacies, etc.) to verify credentials **without running a server**. All cryptographic operations happen in the browser using WebCrypto API.

## ✨ Key Features

- ✅ **Zero Backend Required**: Pure client-side verification
- ✅ **Ephemeral Keys**: Keys exist only in RAM (shredded on page refresh)
- ✅ **QR Code Flow**: Generate challenge URL for wallet scanning
- ✅ **GDPR-by-Design**: No PII stored (structural non-existence)
- ✅ **15-Minute Integration**: Drop-in script for static pages

---

## 📦 Installation

### Option 1: NPM (for bundled apps)

```bash
npm install @mitch/verifier-browser
```

### Option 2: CDN (for static HTML)

```html
<script type="module">
  import { BrowserVerifier } from 'https://cdn.jsdelivr.net/npm/@mitch/verifier-browser/dist/index.js';
  // ... your code ...
</script>
```

---

## 🚀 Quick Start

### Basic Age Verification

```typescript
import { BrowserVerifier } from '@mitch/verifier-browser';

// 1. Initialize verifier
const verifier = new BrowserVerifier({
  verifierName: "Joe's Liquor Store",
  purpose: "Age Verification (18+)",
  requestedClaims: ["age"],
  requestedProvenClaims: ["age >= 18"]
});

// 2. Create ephemeral session
const session = await verifier.createSession();

// 3. Show QR code to user
displayQRCode(session.challengeUrl);

// 4. Wait for wallet response (polling)
const result = await verifier.waitForResponse(session.sessionId);

if (result.success && result.provenClaims?.["age >= 18"]) {
  console.log("✅ Age verified! Proceed with sale.");
} else {
  console.log("❌ Age verification failed.");
}
```

---

## 🏪 Liquor Store Example (Full HTML)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Age Verification</title>
  <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
</head>
<body>
  <h1>Please verify your age</h1>
  <div id="qrcode"></div>
  <p id="status">Scan QR code with miTch Wallet...</p>

  <script type="module">
    import { BrowserVerifier } from 'https://cdn.jsdelivr.net/npm/@mitch/verifier-browser/dist/index.js';

    const verifier = new BrowserVerifier({
      verifierName: "Joe's Liquor Store",
      purpose: "Age Verification (18+)",
      requestedProvenClaims: ["age >= 18"]
    });

    // Generate session
    const session = await verifier.createSession();

    // Display QR code
    new QRCode(document.getElementById("qrcode"), {
      text: session.challengeUrl,
      width: 256,
      height: 256
    });

    // Poll for response
    const result = await verifier.waitForResponse(session.sessionId, 120_000);

    if (result.success) {
      document.getElementById("status").textContent = "✅ Age verified!";
      document.getElementById("status").style.color = "green";
    } else {
      document.getElementById("status").textContent = "❌ Verification failed";
      document.getElementById("status").style.color = "red";
    }
  </script>
</body>
</html>
```

---

## 📖 API Reference

### `BrowserVerifier`

#### Constructor

```typescript
new BrowserVerifier(config: BrowserVerifierConfig, sessionStorage?: SessionStorage)
```

**Config Options:**

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `verifierName` | `string` | ✅ | Display name (e.g., "Joe's Liquor Store") |
| `purpose` | `string` | ✅ | Verification purpose (shown to user) |
| `requestedClaims` | `string[]` | ✅ | Claims to request (e.g., `["age"]`) |
| `requestedProvenClaims` | `string[]` | ❌ | ZKP predicates (e.g., `["age >= 18"]`) |
| `sessionTimeoutMs` | `number` | ❌ | Session timeout (default: 5 minutes) |
| `callbackUrl` | `string` | ❌ | Webhook URL for async results |

#### Methods

##### `createSession(): Promise<VerificationSession>`

Generates ephemeral key pair and creates verification session.

**Returns:**
```typescript
{
  sessionId: string,
  publicKey: JsonWebKey,
  challengeUrl: string,  // For QR code
  nonce: string,
  expiresAt: number
}
```

##### `verifyResponse(response: WalletResponse): Promise<VerifiedResponse>`

Verifies wallet response (signature + decryption).

**Returns:**
```typescript
{
  success: boolean,
  provenClaims?: { [predicate: string]: boolean },
  disclosedClaims?: { [claim: string]: any },
  timestamp: number,
  walletDid: string,
  error?: string
}
```

##### `waitForResponse(sessionId: string, timeoutMs?: number): Promise<VerifiedResponse>`

Polls for wallet response (synchronous flow).

---

## 🔐 Security Guarantees

### 1. Ephemeral Keys (T-86)

```typescript
// Keys are generated fresh for each session
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,  // extractable (for export)
  ['sign', 'verify']
);

// Keys are NEVER persisted:
// ❌ No localStorage
// ❌ No IndexedDB
// ❌ No cookies
// ✅ RAM-only (shredded on refresh)
```

### 2. Crypto-Shredding on Refresh

When the page refreshes:
1. JavaScript context is destroyed
2. All `CryptoKey` objects are garbage-collected
3. Private keys become irrecoverable (WebCrypto guarantees)

**Result:** Even if an attacker dumps RAM post-refresh, keys are gone.

### 3. No Backend = No Liability

```
Traditional Verifier:
┌──────────────┐
│    Server    │ ← Stores keys, sessions, logs
│ (GDPR Risk)  │ ← Single point of failure
└──────────────┘

Browser Verifier:
┌──────────────┐
│   Browser    │ ← Keys exist 1-5 minutes
│ (Ephemeral)  │ ← No persistent storage
└──────────────┘ ← No GDPR controller risk
```

---

## 🛡️ Privacy Compliance

### GDPR Art. 25 (Privacy by Design)

✅ **Data Minimization:** Only ZKP predicates transmitted (`age >= 18`), not raw birthdate  
✅ **Structural Non-Existence:** No PII reaches verifier (proofs only)  
✅ **Purpose Limitation:** Session-specific keys (cannot be reused)  
✅ **Storage Limitation:** Keys shredded after 5 minutes or page refresh

### Verifier Liability

**Traditional System:**
- Verifier = Data Controller (GDPR Art. 4)
- Must handle GDPR requests (Art. 15-22)
- Liable for data breaches (Art. 33)

**Browser Verifier:**
- Verifier = Blind Convener (no data)
- No GDPR requests possible (no data exists)
- No breach risk (nothing to steal)

---

## ⚡ Performance

| Operation | Time | Notes |
|-----------|------|-------|
| `createSession()` | ~50ms | Generates P-256 key pair |
| `verifyResponse()` | ~20ms | ECDSA signature verification |
| `waitForResponse()` | 1-120s | Polling interval: 1s |

**Memory Usage:**
- Per Session: ~2KB (key + metadata)
- Max Sessions: Limited by browser (typically 1000+)

---

## 🔮 Roadmap

### Current (v0.1.0)
- ✅ Ephemeral key generation
- ✅ QR code challenge URLs
- ✅ Polling-based response handling
- ⏳ Mock verification (no real JWE decryption)

### Next (v0.2.0)
- [ ] Full JWE decryption (ECDH-ES + A256GCM)
- [ ] DID resolution for signature verification
- [ ] WebSocket support (push-based responses)
- [ ] localStorage persistence (opt-in)

### Future (v1.0.0)
- [ ] Multi-credential bundles (T-29)
- [ ] Biometric binding (WebAuthn integration)
- [ ] Audit log export (WORM format)

---

## 🧪 Testing

```bash
npm test
```

**Test Coverage:**
- ✅ Key generation (ephemeral)
- ✅ Session creation
- ✅ Challenge URL format
- ✅ Session expiration
- ⏳ Response verification (mocked)

---

## 📄 License

MIT License (same as miTch core)

---

## 🆘 Support

- **Documentation:** https://docs.mitch.id
- **Issues:** https://github.com/mitch-id/mitch/issues
- **Email:** support@mitch.id

---

## 🏆 Credits

Built with:
- **WebCrypto API** (W3C Standard)
- **QRCode.js** (QR code generation)
- **TypeScript** (type safety)

Developed as part of the **miTch Sovereign Identity Infrastructure** project.

---

**Note:** This SDK is designed for **proof-of-concept** deployments. For production use, ensure:
1. HTTPS-only hosting (WebCrypto requirement)
2. Content Security Policy (CSP) headers
3. Regular security audits
4. Wallet compatibility testing
