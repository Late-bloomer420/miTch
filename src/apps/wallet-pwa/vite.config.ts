import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import basicSsl from '@vitejs/plugin-basic-ssl';
import path from 'path';

const useBasicSsl = process.env.ASKMI_DEV_HTTPS !== '0';

const securityHeaders = {
  'Content-Security-Policy': "frame-ancestors 'none';",
  'X-Frame-Options': 'DENY',
};

export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    ...(useBasicSsl && mode !== 'demo' ? [basicSsl()] : []),
    ...(mode === 'demo'
      ? [
          {
            name: 'demo-connect-policy',
            transformIndexHtml(html: string) {
              return html.replace(
                /connect-src[^;]+;/,
                "connect-src 'self' http://localhost:3104 http://localhost:3005 ws://localhost:5184;"
              );
            },
          },
        ]
      : []),
  ],

  define: {
    'process.env': {},
  },

  resolve: {
    alias: {
      // Resolve workspace packages
      '@askmi/shared-types': path.resolve(__dirname, '../../packages/shared-types/src'),
      '@askmi/shared-crypto': path.resolve(__dirname, '../../packages/shared-crypto/src'),
      '@askmi/policy-engine': path.resolve(__dirname, '../../packages/policy-engine/src'),
      '@askmi/audit-log': path.resolve(__dirname, '../../packages/audit-log/src'),
      '@askmi/secure-storage': path.resolve(__dirname, '../../packages/secure-storage/src'),
      '@askmi/predicates': path.resolve(__dirname, '../../packages/predicates/src'),
      '@askmi/layer-resolver': path.resolve(__dirname, '../../packages/layer-resolver/src'),
      '@askmi/oid4vp': path.resolve(__dirname, '../../packages/oid4vp/src'),
      '@askmi/data-flow': path.resolve(__dirname, '../../packages/data-flow/src'),
    },
  },

  // Optimize dependencies (avoid pre-bundling workspace packages)
  optimizeDeps: {
    exclude: [
      '@askmi/shared-types',
      '@askmi/shared-crypto',
      '@askmi/policy-engine',
      '@askmi/audit-log',
      '@askmi/secure-storage',
      '@askmi/predicates',
      '@askmi/layer-resolver',
      '@askmi/oid4vp',
      '@askmi/data-flow',
    ],
  },

  server: {
    port: mode === 'demo' ? 5184 : 5174,
    strictPort: true,
    host: mode === 'demo' ? 'localhost' : true,
    allowedHosts: mode === 'demo' ? ['localhost'] : true,
    headers: securityHeaders,
  },

  preview: {
    headers: securityHeaders,
  },
}));
