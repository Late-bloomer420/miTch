// Development-only bootstrap. Production startup continues through index.ts
// without implicit browser origins, preserving deny-by-default CORS.
process.env.CORS_ALLOWED_ORIGINS ??= 'http://localhost:5174,http://localhost:5175';

void import('./index.js');
