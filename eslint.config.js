import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
    },
  },
  {
    files: ['src/packages/wallet-sync/**/*'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@mitch/secure-storage',
              message:
                'Architectural Boundary Violation: wallet-sync must never import secure-storage.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['src/packages/audit-log/**/*', 'src/packages/policy-engine/**/*'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@mitch/wallet-auth',
              message:
                'Architectural Boundary Violation: audit-log and policy-engine are pure consumers and must never import wallet-auth.',
            },
          ],
        },
      ],
    },
  },
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/.turbo/**',
      '**/phase0-security/**',
      '**/poc-hardened/**',
    ],
  }
);
