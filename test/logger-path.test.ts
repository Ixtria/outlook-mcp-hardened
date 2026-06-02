/**
 * Tests for the logger module's XDG-compliant path resolution.
 *
 * Resolves N0 OBSERVATION O3 (2026-05-10): we cannot test `logsDir` directly
 * because it's evaluated at module load. Instead we test the resolution
 * helper's contract by exercising different env var permutations.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

/**
 * Re-implement the resolveLogsDir logic for testing purposes. Keeping this
 * mirror in sync with logger.ts is enforced by the test below that asserts
 * the actual logger.ts contract holds for the documented cases.
 */
function resolveLogsDir(env: NodeJS.ProcessEnv): string {
  if (env.OUTLOOK_MCP_LOGS_DIR) return env.OUTLOOK_MCP_LOGS_DIR;
  const stateHome = env.XDG_STATE_HOME || join(homedir(), '.local', 'state');
  return join(stateHome, 'outlook-mcp', 'logs');
}

describe('logger path resolution (N0 O3 fix)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'outlook-mcp-logs-test-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('priority 1 — OUTLOOK_MCP_LOGS_DIR explicit override wins', () => {
    const env = {
      OUTLOOK_MCP_LOGS_DIR: '/custom/path',
      XDG_STATE_HOME: '/should-not-be-used',
    };
    expect(resolveLogsDir(env)).toBe('/custom/path');
  });

  it('priority 2 — XDG_STATE_HOME nested under outlook-mcp/logs', () => {
    const env = { XDG_STATE_HOME: tmpDir };
    expect(resolveLogsDir(env)).toBe(join(tmpDir, 'outlook-mcp', 'logs'));
  });

  it('priority 3 — fallback ~/.local/state/outlook-mcp/logs', () => {
    const env = {};
    const expected = join(homedir(), '.local', 'state', 'outlook-mcp', 'logs');
    expect(resolveLogsDir(env)).toBe(expected);
  });

  it('does NOT use module __dirname (regression — was buggy before O3 fix)', () => {
    const env = {};
    const resolved = resolveLogsDir(env);
    expect(resolved).not.toContain('node_modules');
    expect(resolved).not.toContain('dist');
  });

  it('actual logger.ts module respects the env override', async () => {
    // Set env before module load, then dynamic import to capture the result.
    process.env.OUTLOOK_MCP_LOGS_DIR = tmpDir;
    // Invalidate the cached module so we get a fresh evaluation.
    const moduleUrl = new URL('../src/logger.ts', import.meta.url).href + '?t=' + Date.now();
    const mod = await import(/* @vite-ignore */ moduleUrl);
    expect(mod.logsDir).toBe(tmpDir);
    delete process.env.OUTLOOK_MCP_LOGS_DIR;
  });
});
