/**
 * Regression tests for N4 expert review BLOCKERS B1+B2+B3 fixed in server.ts
 * and oauth-provider.ts. These assert the INVARIANTS — the actual HTTP
 * surface tests would need a running server, which we already exercise
 * via the existing http-routes.test.ts integration suite.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_TS = readFileSync(join(__dirname, '..', '..', 'server.ts'), 'utf8');
const PROVIDER_TS = readFileSync(join(__dirname, '..', '..', 'oauth-provider.ts'), 'utf8');

describe('N4 BLOCKERS regression (Phase B 2026-06-02)', () => {
  describe('N4-B1 — PKCE required (RFC 9700)', () => {
    it('GET /authorize handler refuses missing code_challenge', () => {
      // The handler must contain a guard for `!clientCodeChallenge` returning
      // 400 invalid_request before any forward to AAD.
      expect(SERVER_TS).toMatch(/if\s*\(\s*!\s*clientCodeChallenge\s*\)/);
      expect(SERVER_TS).toContain('PKCE mandatory');
    });

    it('GET /authorize refuses code_challenge_method != S256', () => {
      // Existing check (Phase A fix) for method-name validation.
      expect(SERVER_TS).toMatch(/code_challenge_method must be S256/);
    });
  });

  describe('N4-B2 — POST /authorize bypass blocked', () => {
    it('app.post(/authorize) handler exists and returns 405', () => {
      expect(SERVER_TS).toMatch(/app\.post\(\s*['"]\/authorize['"]/);
      expect(SERVER_TS).toMatch(/status\(\s*405\s*\)/);
      expect(SERVER_TS).toMatch(/Allow.*GET/);
    });

    it('POST handler is registered BEFORE mcpAuthRouter mount', () => {
      const postAuthorizeIdx = SERVER_TS.indexOf("app.post('/authorize'");
      const mcpAuthRouterIdx = SERVER_TS.indexOf('mcpAuthRouter({');
      expect(postAuthorizeIdx).toBeGreaterThan(0);
      expect(mcpAuthRouterIdx).toBeGreaterThan(0);
      expect(postAuthorizeIdx).toBeLessThan(mcpAuthRouterIdx);
    });
  });

  describe('N4-B3 — setOAuthToken global state mutation removed', () => {
    it('verifyMicrosoftAccessToken does NOT call authManager.setOAuthToken', () => {
      // Extract the body of verifyMicrosoftAccessToken (between its signature
      // and the closing of the next exported symbol).
      const fnStart = PROVIDER_TS.indexOf('export async function verifyMicrosoftAccessToken');
      const fnEnd = PROVIDER_TS.indexOf('export class MicrosoftOAuthProvider');
      expect(fnStart).toBeGreaterThan(-1);
      expect(fnEnd).toBeGreaterThan(fnStart);
      const fnBody = PROVIDER_TS.slice(fnStart, fnEnd);
      // Negative assertion : the call site must be gone.
      expect(fnBody).not.toMatch(/await\s+authManager\.setOAuthToken/);
    });

    it('fix is documented with reasoning + threat model reference', () => {
      expect(PROVIDER_TS).toContain('N4 B3 BLOCKER');
      expect(PROVIDER_TS).toContain('Cross-user data leak');
    });
  });
});
