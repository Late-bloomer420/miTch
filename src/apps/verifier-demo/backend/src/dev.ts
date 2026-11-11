// Development-only bootstrap. Production startup continues through index.ts
// without implicit browser origins, preserving deny-by-default CORS.
// The wallet dev server serves HTTPS by default (ASKMI_DEV_HTTPS=0 switches it to
// HTTP), so both wallet origins are listed.
process.env.CORS_ALLOWED_ORIGINS ??=
  'https://localhost:5174,http://localhost:5174,http://localhost:5175';

void import('./index.js');
