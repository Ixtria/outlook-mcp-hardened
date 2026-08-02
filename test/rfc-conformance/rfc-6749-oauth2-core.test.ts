/**
 * RFC 6749 — The OAuth 2.0 Authorization Framework.
 *
 * Contract tests labelled by RFC section for audit traceability (TEST-06,
 * 2026-08-02). Scope is deliberately narrowed to the endpoints mounted by
 * `test/helpers/oauth-server-fixture.ts` — /authorize (GET + POST) — which
 * is what src/server.ts also composes in production via the same route
 * factories. /token is NOT covered by the fixture (needs AuthManager +
 * MSAL); regressions there are caught by graph-client.ts and auth.ts unit
 * tests. Documented so an auditor knows which clauses are gaps.
 *
 * Discipline (ADR-0004 rule 3) : behavioral only — HTTP status, headers,
 * body. No file-content assertions.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  startOauthFixture,
  type OauthFixture,
} from '../helpers/oauth-server-fixture.js';

const VALID_REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';
const VALID_CHALLENGE = 'X'.repeat(43); // 43 chars is the minimum PKCE S256 length.

function buildAuthorizeUrl(
  fixture: OauthFixture,
  overrides: Record<string, string | undefined> = {},
): URL {
  const url = new URL('/authorize', fixture.baseUrl);
  const defaults: Record<string, string> = {
    client_id: 'test-client',
    redirect_uri: VALID_REDIRECT_URI,
    response_type: 'code',
    scope: 'Mail.Read',
    state: 'state-abc',
    code_challenge: VALID_CHALLENGE,
    code_challenge_method: 'S256',
  };
  const merged = { ...defaults, ...overrides };
  for (const [k, v] of Object.entries(merged)) {
    if (v !== undefined) {
      url.searchParams.set(k, v);
    }
  }
  return url;
}

describe('RFC 6749 — OAuth 2.0 Core', () => {
  let fixture: OauthFixture;

  beforeEach(async () => {
    fixture = await startOauthFixture();
  });

  afterEach(async () => {
    await fixture.close();
  });

  describe('§3.1 — Authorization Endpoint: HTTP method', () => {
    it('RFC 6749 §3.1 — authorization endpoint MUST support GET (302 redirect on success)', async () => {
      const url = buildAuthorizeUrl(fixture);

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(302);
      const location = response.headers.get('location');
      expect(location).toBeTruthy();
      expect(location).toContain('login.microsoftonline.com');
    });

    it('RFC 6749 §3.1 — POST is optional; our server refuses it (405) to avoid PKCE bypass', async () => {
      // We reject POST /authorize deliberately (N4-B2). RFC 6749 §3.1 allows
      // us to support only GET. The behavior is: 405 with `Allow: GET`.
      const url = new URL('/authorize', fixture.baseUrl);
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: 'test-client',
          redirect_uri: VALID_REDIRECT_URI,
          response_type: 'code',
          code_challenge: VALID_CHALLENGE,
          code_challenge_method: 'S256',
          state: 'abc',
        }).toString(),
      });

      expect(response.status).toBe(405);
      expect(response.headers.get('allow')).toBe('GET');
    });
  });

  describe('§4.1.1 — Authorization Request', () => {
    it('RFC 6749 §4.1.1 — forwards response_type=code to the upstream authorization endpoint', async () => {
      const url = buildAuthorizeUrl(fixture, { response_type: 'code' });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const location = response.headers.get('location') ?? '';
      const forwarded = new URL(location);
      expect(forwarded.searchParams.get('response_type')).toBe('code');
    });

    it('RFC 6749 §4.1.1 — forwards state opaquely (unmodified) to the upstream endpoint', async () => {
      const opaqueState = 'opaque-state-value-42';
      const url = buildAuthorizeUrl(fixture, { state: opaqueState });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const forwarded = new URL(response.headers.get('location') ?? '');
      // §4.1.1 : the AS MUST return the exact `state` value in its redirect.
      // We are the AS-proxy here; we MUST forward `state` unchanged upstream.
      expect(forwarded.searchParams.get('state')).toBe(opaqueState);
    });
  });

  describe('§4.1.2.1 — Error Response', () => {
    it('RFC 6749 §4.1.2.1 — invalid_request when redirect_uri is missing (local error, no Location header)', async () => {
      const url = buildAuthorizeUrl(fixture, { redirect_uri: undefined });

      const response = await fetch(url, { redirect: 'manual' });

      // §4.1.2.1 : if redirect_uri is missing/invalid, the AS MUST NOT
      // redirect back to the client. It shows a local error page instead.
      expect(response.status).toBe(400);
      expect(response.headers.get('location')).toBeNull();
      const body = await response.text();
      expect(body.toLowerCase()).toContain('invalid_request');
      expect(body).toContain('redirect_uri');
    });

    it('RFC 6749 §4.1.2.1 — invalid_request when redirect_uri is not in the registered allowlist', async () => {
      const url = buildAuthorizeUrl(fixture, {
        redirect_uri: 'https://attacker.example.com/callback',
      });

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(400);
      expect(response.headers.get('location')).toBeNull();
      const body = await response.text();
      expect(body.toLowerCase()).toContain('invalid_request');
    });

    it('RFC 6749 §4.1.2.1 — invalid_scope when the requested scope is empty after intersection', async () => {
      const url = buildAuthorizeUrl(fixture, {
        scope: 'ThisScope.DoesNotExist',
      });

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(400);
      const body = await response.text();
      expect(body.toLowerCase()).toContain('invalid_scope');
    });
  });

  describe('§3.3 — Access Token Scope', () => {
    it('RFC 6749 §3.3 — scope is passed as a space-delimited list', async () => {
      const url = buildAuthorizeUrl(fixture, {
        scope: 'Mail.Read Calendars.Read',
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const forwarded = new URL(response.headers.get('location') ?? '');
      const scope = forwarded.searchParams.get('scope') ?? '';
      // Scope MUST be a space-separated list — never comma, semicolon, plus, etc.
      expect(scope.split(' ')).toEqual(
        expect.arrayContaining(['Mail.Read', 'Calendars.Read']),
      );
    });
  });

  describe('§10.6 — Authorization Code Redirection URI Manipulation (PKCE)', () => {
    it('RFC 6749 §10.6 — PKCE code_challenge is required (mitigates code injection)', async () => {
      const url = buildAuthorizeUrl(fixture, { code_challenge: undefined });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(400);
      const body = await response.text();
      expect(body).toContain('code_challenge');
    });

    it('RFC 6749 §10.6 — server rewrites the code_challenge (two-leg PKCE prevents downstream replay)', async () => {
      // Two-leg PKCE: the challenge sent upstream is NOT the client's
      // challenge — the server generates its own verifier so a compromised
      // upstream token endpoint response cannot be reused by the client
      // (and vice-versa). The client value must never appear upstream.
      const clientChallenge = 'C'.repeat(43);
      const url = buildAuthorizeUrl(fixture, {
        code_challenge: clientChallenge,
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const forwarded = new URL(response.headers.get('location') ?? '');
      const upstreamChallenge = forwarded.searchParams.get('code_challenge');
      expect(upstreamChallenge).toBeTruthy();
      expect(upstreamChallenge).not.toBe(clientChallenge);
    });
  });
});
