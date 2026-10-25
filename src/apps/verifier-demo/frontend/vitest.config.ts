import { defineConfig } from 'vitest/config';

// Static data and server-rendered React assertions need no browser environment.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
