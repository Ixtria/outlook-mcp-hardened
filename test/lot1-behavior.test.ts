/**
 * MAINT-TEST-BEHAV — Lot 1 behavioral regression tests (2026-08-02).
 *
 * Foundation Phase A tests that lock the N4-B1 (PKCE mandatory), N4-B2
 * (POST /authorize → 405) and SEC-01 (refresh token non-logué) fixes.
 *
 * Discipline (ADR-0004 rule 3 — tests comportementaux) :
 *   - No fs.readFileSync on src/, no SOURCE.toContain, no regex on file
 *     content. Every assertion targets observable behavior:
 *       * HTTP status + body + headers hit via a real Express listener
 *       * Captured winston log entries via an in-memory transport
 *   - The fixture (`test/helpers/oauth-server-fixture.ts`) mounts the
 *     same route factories that `src/server.ts` uses in production,
 *     so any regression in the extracted handlers or in server.ts
 *     wiring fails these tests.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import GraphClient from '../src/graph-client.js';
import type AuthManager from '../src/auth.js';
import {
  attachLogCapture,
  startOauthFixture,
  type LogCapture,
  type OauthFixture,
} from './helpers/oauth-server-fixture.js';

// Real registered redirect_uri (see src/oauth/registered-clients.ts) — used
// by test 1 so we get PAST the redirect_uri check and hit the PKCE guard.
const VALID_REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';

// Fake Azure refresh token in the opaque `M.C_...` format. The redactor
// (src/security/log-redactor.ts) does NOT match this shape — the only
// defense is the source-side destructuring in graph-client.ts:192.
// If that destructuring regresses, this exact string will appear in a
// captured log line and the assertion fires.
const FAKE_REFRESH_TOKEN = 'M.C_FAKE_TOKEN_1234';

describe('Lot 1 — behavioral regression tests', () => {
  describe('GET /authorize without code_challenge → 400 (N4-B1 PKCE mandatory)', () => {
    let fixture: OauthFixture;

    beforeEach(async () => {
      fixture = await startOauthFixture();
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('rejects with 400 and code_challenge-required message', async () => {
      const url = new URL('/authorize', fixture.baseUrl);
      url.searchParams.set('client_id', 'test-client');
      url.searchParams.set('redirect_uri', VALID_REDIRECT_URI);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'Mail.Read');
      url.searchParams.set('state', 'abc');
      // NOTE: no `code_challenge` — this is what the test proves is rejected.

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(400);
      // Body should surface the code_challenge / PKCE contract, not just a
      // generic 400. The exact phrasing is part of the contract with clients.
      const body = await response.text();
      expect(body).toContain('code_challenge');
      // No Location header should have been emitted (open-redirect guard).
      expect(response.headers.get('location')).toBeNull();
    });

    it('accepts (302 redirect) once code_challenge is present — sanity check', async () => {
      const url = new URL('/authorize', fixture.baseUrl);
      url.searchParams.set('client_id', 'test-client');
      url.searchParams.set('redirect_uri', VALID_REDIRECT_URI);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'Mail.Read');
      url.searchParams.set('state', 'abc');
      url.searchParams.set('code_challenge', 'X'.repeat(43));
      url.searchParams.set('code_challenge_method', 'S256');

      const response = await fetch(url, { redirect: 'manual' });

      // 302 to login.microsoftonline.com — proves the handler processed
      // the request fully once the PKCE contract was honored.
      expect(response.status).toBe(302);
      const location = response.headers.get('location');
      expect(location).toBeTruthy();
      expect(location).toContain('login.microsoftonline.com');
    });
  });

  describe('POST /authorize → 405 (N4-B2 method not allowed)', () => {
    let fixture: OauthFixture;

    beforeEach(async () => {
      fixture = await startOauthFixture();
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('rejects POST with 405, Allow: GET header, and explanatory body', async () => {
      const url = new URL('/authorize', fixture.baseUrl);

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: 'test-client',
          redirect_uri: VALID_REDIRECT_URI,
          response_type: 'code',
          code_challenge: 'X'.repeat(43),
          code_challenge_method: 'S256',
          state: 'abc',
        }).toString(),
      });

      expect(response.status).toBe(405);
      // RFC 7231 §6.5.5 : 405 responses MUST include Allow.
      expect(response.headers.get('allow')).toBe('GET');
      const body = await response.text();
      // Explanatory body helps operators understand why POST is refused
      // (bypasses PKCE + scope validation via SDK mcpAuthRouter).
      expect(body.toLowerCase()).toContain('method_not_allowed');
    });
  });

  describe('SEC-01 — GraphClient.graphRequest never logs the refresh token', () => {
    let capture: LogCapture;
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
      capture = attachLogCapture();
      originalFetch = global.fetch;
    });

    afterEach(() => {
      capture.restore();
      global.fetch = originalFetch;
      vi.restoreAllMocks();
    });

    it('does not emit the refresh token in any captured log message', async () => {
      // Stub fetch : return a plain 200 so graphRequest does NOT enter the
      // refresh-on-401 branch (which would fetch the real Microsoft token
      // endpoint). We're only exercising the log-safety of the ENTRY line
      // in graph-client.ts:195 — that's where the SEC-01 leak lived.
      global.fetch = vi.fn(async () => {
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as unknown as typeof global.fetch;

      const mockAuthManager = {
        isOAuthModeEnabled: () => false,
        getToken: async () => null,
        getScopes: () => [] as readonly string[],
        getSelectedAccountId: () => null,
      } as unknown as AuthManager;

      const graphClient = new GraphClient(mockAuthManager, {
        clientId: 'test-client',
        tenantId: 'common',
        cloudType: 'global',
      });

      const response = await graphClient.graphRequest('/me/messages', {
        method: 'GET',
        accessToken: 'access-token-value',
        refreshToken: FAKE_REFRESH_TOKEN,
      });

      // Sanity : the call itself completed (fetch stub returned 200).
      expect(response.isError).toBeUndefined();

      // Core assertion : NO log message may embed the refresh token
      // literal. If the SEC-01 destructuring regresses, the "Calling
      // /me/messages with options: ..." line would contain the token
      // and this assertion fires.
      expect(capture.messages.length).toBeGreaterThan(0);
      for (const message of capture.messages) {
        expect(message).not.toContain(FAKE_REFRESH_TOKEN);
        expect(message).not.toContain('refreshToken');
        // Access token is also stripped by the same destructuring.
        expect(message).not.toContain('access-token-value');
        expect(message).not.toContain('accessToken');
      }
    });
  });
});
