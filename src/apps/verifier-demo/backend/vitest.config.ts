import { defineConfig } from 'vitest/config';

// The suites serve unsigned mock trust lists, which only dev trust mode accepts (#240).
// Live-mode behaviour is tested in @askmi/shared-crypto (trust-list-mode.test.ts).
export default defineConfig({
  test: { env: { ASKMI_TRUST_MODE: 'dev' } },
});
