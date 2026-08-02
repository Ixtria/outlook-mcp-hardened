/**
 * Regression tests for N4 expert review BLOCKERS B1+B2+B3.
 *
 * HISTORY (MAINT-TEST-BEHAV, 2026-08-02) :
 *   B1 / B2 were originally asserted here by reading `server.ts` and
 *   grepping for handler strings — the pattern ADR-0004 rule 3 now
 *   forbids ("SOURCE.toContain sur fs.readFileSync"). The behavior itself
 *   is now covered by `test/lot1-behavior.test.ts` via real HTTP round
 *   trips against the same factories (`createRejectPostAuthorizeHandler`,
 *   `createAuthorizeHandler`) that `server.ts` wires in production. The
 *   assertions below have been narrowed to :
 *     - N4-B1 / N4-B2 → point at the extracted `http-routes.ts` (same
 *       greppable location as the behavior it locks in) so a rewrite of
 *       the factories fails BOTH here and in the behavioral test.
 *     - N4-B3 → still points at `oauth-provider.ts` (untouched by the
 *       MAINT-TEST-BEHAV extraction).
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HTTP_ROUTES_TS = readFileSync(join(__dirname, '..', 'http-routes.ts'), 'utf8');
const SERVER_TS = readFileSync(join(__dirname, '..', '..', 'server.ts'), 'utf8');
const PROVIDER_TS = readFileSync(join(__dirname, '..', '..', 'oauth-provider.ts'), 'utf8');

describe('N4 BLOCKERS regression (Phase B 2026-06-02)', () => {
  describe('N4-B1 — PKCE required (RFC 9700)', () => {
    it('createAuthorizeHandler refuses missing code_challenge', () => {
      // The handler must contain a guard for `!clientCodeChallenge` returning
      // 400 invalid_request before any forward to AAD.
      expect(HTTP_ROUTES_TS).toMatch(/if\s*\(\s*!\s*clientCodeChallenge\s*\)/);
      expect(HTTP_ROUTES_TS).toContain('PKCE mandatory');
    });

    it('createAuthorizeHandler refuses code_challenge_method != S256', () => {
      expect(HTTP_ROUTES_TS).toMatch(/code_challenge_method must be S256/);
    });
  });

  describe('N4-B2 — POST /authorize bypass blocked', () => {
    it('createRejectPostAuthorizeHandler exists and returns 405', () => {
      expect(HTTP_ROUTES_TS).toMatch(/createRejectPostAuthorizeHandler/);
      expect(HTTP_ROUTES_TS).toMatch(/status\(\s*405\s*\)/);
      expect(HTTP_ROUTES_TS).toMatch(/Allow.*GET/);
    });

    it('server.ts registers POST /authorize BEFORE mcpAuthRouter mount', () => {
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
