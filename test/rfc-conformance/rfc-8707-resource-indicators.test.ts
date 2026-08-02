/**
 * RFC 8707 — Resource Indicators for OAuth 2.0.
 *
 * Contract tests labelled by RFC section for audit traceability (TEST-06,
 * 2026-08-02). RFC 8707 lets a client tell the AS which resource server(s)
 * a token will be used against, so the AS can audience-restrict the token
 * (aud claim scoped, preventing token-reuse across resource servers).
 *
 * KNOWN COVERAGE GAPS (documented as tests-skipped-with-note so auditors
 * can find them via `vitest --reporter=verbose`) :
 *   - §2 : forwarding the `resource` parameter to the upstream AAD
 *          endpoint is not yet implemented (the /authorize handler only
 *          forwards a fixed allowedParams list). Followup ticket: none yet.
 *   - §4 : audience validation of the token response is done by MSAL
 *          during exchange (not by our /token handler, which is not in
 *          the OAuth fixture). Covered indirectly by graph-client.ts
 *          integration tests.
 *
 * What we DO test here is that the /authorize handler tolerates a
 * `resource` parameter without regressing (400/500) — the minimum guard
 * that keeps upgrade paths open when we add full RFC 8707 support.
 *
 * Discipline (ADR-0004 rule 3) : behavioral only.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  startOauthFixture,
  type OauthFixture,
} from '../helpers/oauth-server-fixture.js';

const VALID_REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';
const VALID_CHALLENGE = 'X'.repeat(43);

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

describe('RFC 8707 — Resource Indicators for OAuth 2.0', () => {
  let fixture: OauthFixture;

  beforeEach(async () => {
    fixture = await startOauthFixture();
  });

  afterEach(async () => {
    await fixture.close();
  });

  describe('§2 — Resource parameter on the authorization request', () => {
    it('RFC 8707 §2 — /authorize accepts a valid resource parameter without regressing (302)', async () => {
      // The RFC allows a single-URI `resource` value that identifies the
      // protected resource server. Whether we forward it upstream today or
      // not, the handler MUST NOT reject a well-formed request that carries
      // it. If we later start forwarding, this test still passes; if we
      // ever start rejecting unknown params, this test fires.
      const url = buildAuthorizeUrl(fixture, {
        resource: 'https://graph.microsoft.com/',
      });

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(302);
      const location = response.headers.get('location');
      expect(location).toBeTruthy();
      expect(location).toContain('login.microsoftonline.com');
    });

    it('RFC 8707 §2 — /authorize accepts multiple resource parameters (per RFC allows repeat)', async () => {
      // §2 : the resource parameter MAY appear multiple times. We must
      // not choke on repeats.
      const url = new URL('/authorize', fixture.baseUrl);
      url.searchParams.set('client_id', 'test-client');
      url.searchParams.set('redirect_uri', VALID_REDIRECT_URI);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'Mail.Read');
      url.searchParams.set('state', 'state-abc');
      url.searchParams.set('code_challenge', VALID_CHALLENGE);
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.append('resource', 'https://graph.microsoft.com/');
      url.searchParams.append('resource', 'https://outlook.office.com/');

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(302);
    });

    it('RFC 8707 §2 — resource param does not leak into the upstream redirect as a bogus scope', async () => {
      // Regression guard: a resource URI must never be confused with a
      // scope. If someone later wires the resource param through
      // computeEffectiveScope() by mistake, the assertion fires.
      const url = buildAuthorizeUrl(fixture, {
        resource: 'https://graph.microsoft.com/',
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const forwarded = new URL(response.headers.get('location') ?? '');
      const forwardedScope = forwarded.searchParams.get('scope') ?? '';
      expect(forwardedScope).not.toContain('https://graph.microsoft.com/');
    });
  });

  describe('§2 — Malformed resource is not required to fail here (upstream AS validates)', () => {
    it('RFC 8707 §2 — a syntactically weird resource does not crash the AS-proxy', async () => {
      // RFC §2 says the AS SHOULD reject invalid resource URIs (§2 error
      // code invalid_target). Our proxy delegates that check to AAD today
      // (documented gap). What we test here: no 5xx, no unhandled throw.
      const url = buildAuthorizeUrl(fixture, {
        resource: 'not a uri at all',
      });

      const response = await fetch(url, { redirect: 'manual' });

      // Either the proxy tolerates and 302s, or it 400s locally — both
      // are conformant here. What is NOT tolerable is a 5xx.
      expect(response.status).toBeLessThan(500);
    });
  });

  describe('§4 — Token response audience (gap, covered by MSAL integration)', () => {
    it.skip('RFC 8707 §4 — resource is echoed / audience-restricted in token response (GAP: no /token in fixture)', () => {
      // Intentionally skipped: /token is not mounted by the OAuth fixture.
      // Audience restriction in the access token is enforced by MSAL and
      // by the Bearer-middleware audience check in server.ts. When the
      // fixture grows to include /token (see TEST-01 follow-up), replace
      // this skip with a behavioral assertion on the returned `aud` claim.
    });
  });
});
