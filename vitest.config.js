import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      // Coverage applies repo-wide; threshold strict only on hardening surfaces.
      include: ['src/**/*.ts'],
      exclude: [
        'src/generated/**',
        'src/__tests__/**',
        '**/*.d.ts',
        'src/index.ts', // bootstrap
      ],
      thresholds: {
        // Strict thresholds on modules where security regressions are catastrophic.
        // Per ADR-0001 (cross-LLM review grid) + SECURITY.md, these directories
        // host the hardening primitives and OAuth AS — coverage must not regress.
        'src/security/**': {
          lines: 80,
          functions: 80,
          branches: 75,
          statements: 80,
        },
        'src/oauth/**': {
          lines: 80,
          functions: 80,
          branches: 75,
          statements: 80,
        },
        'src/request-context.ts': {
          lines: 80,
          functions: 80,
          branches: 75,
          statements: 80,
        },
      },
    },
  },
});
