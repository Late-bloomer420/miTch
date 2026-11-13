// Development-only bootstrap. Production startup continues through index.ts
// without implicit browser origins, preserving deny-by-default CORS.
process.env.CORS_ALLOWED_ORIGINS ??= 'http://localhost:5174,http://localhost:5175';

// issuer-mock serves an unsigned trust list over HTTP, which only dev trust mode
// accepts. Production startup stays in live mode: signed list, anchor key, HTTPS.
process.env.ASKMI_TRUST_MODE ??= 'dev';

void import('./index.js');
