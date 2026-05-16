import js from '@eslint/js';
import globals from 'globals';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
// eslint-plugin-security: SAST-style rules. Catches eval, regex DoS,
// child_process injection, fs path injection, pseudoRandomBytes for crypto,
// etc. Complements CodeQL + Semgrep with cheap local lint.
import security from 'eslint-plugin-security';

export default [
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ['**/*.{ts,tsx,js,mjs}'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        ...globals.node,
        ...globals.vitest,
        ...globals.jest,
        fs: 'readonly',
        // DOM fetch primitives exposed by Node 18+ as ambient globals.
        RequestInfo: 'readonly',
        RequestInit: 'readonly',
        Response: 'readonly',
        Request: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
      security,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      'no-console': 'off',
      // Security plugin rules — error on the high-signal ones, warn on the
      // noisy heuristics we want to see but not block.
      'security/detect-eval-with-expression': 'error',
      'security/detect-child-process': 'error',
      'security/detect-non-literal-require': 'error',
      'security/detect-pseudoRandomBytes': 'error',
      'security/detect-buffer-noassert': 'error',
      'security/detect-disable-mustache-escape': 'error',
      'security/detect-no-csrf-before-method-override': 'error',
      'security/detect-bidi-characters': 'error',
      // Heuristics that often false-positive on our codebase — keep as warn.
      'security/detect-object-injection': 'warn',
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-non-literal-regexp': 'warn',
      'security/detect-unsafe-regex': 'warn',
      'security/detect-possible-timing-attacks': 'warn',
      'security/detect-new-buffer': 'warn',
    },
  },
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      'coverage/**',
      'bin/**',
      'src/generated/**',
      '.venv/**',
    ],
  },
];
