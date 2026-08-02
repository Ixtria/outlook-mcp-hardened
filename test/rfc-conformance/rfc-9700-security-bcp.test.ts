/**
 * RFC 9700 — Best Current Practice for OAuth 2.0 Security.
 *
 * Contract tests labelled by RFC section for audit traceability (TEST-06,
 * 2026-08-02). This RFC crystalizes the last decade of OAuth attack
 * research (mix-up, token injection, open redirection, wildcard bypass) and
 * demands PKCE for ALL clients, strict redirect_uri matching, and refusal
 * of confidential-only grants to public clients.
 *
 * Scope covered by the fixture: /authorize + /register.
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

describe('RFC 9700 — OAuth 2.0 Security Best Current Practice', () => {
  describe('§2.1.1 — PKCE required for all clients', () => {
    let fixture: OauthFixture;

    beforeEach(async () => {
      fixture = await startOauthFixture();
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('RFC 9700 §2.1.1 — /authorize without code_challenge is rejected (400)', async () => {
      const url = buildAuthorizeUrl(fixture, { code_challenge: undefined });

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(400);
      const body = await response.text();
      expect(body).toContain('code_challenge');
    });

    it('RFC 9700 §2.1.1 — code_challenge_method must be S256; plain is refused', async () => {
      // The BCP explicitly deprecates the `plain` method. S256 only.
      const url = buildAuthorizeUrl(fixture, {
        code_challenge_method: 'plain',
      });

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(400);
      const body = await response.text();
      expect(body).toContain('S256');
    });

    it('RFC 9700 §2.1.1 — unknown PKCE method (e.g. MD5) is refused', async () => {
      const url = buildAuthorizeUrl(fixture, { code_challenge_method: 'MD5' });

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(400);
    });
  });

  describe('§2.1.2 — Redirect URI strict matching', () => {
    let fixture: OauthFixture;

    beforeEach(async () => {
      fixture = await startOauthFixture();
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('RFC 9700 §2.1.2 — wildcard path suffix does NOT match a registered URI', async () => {
      // registered_clients.ts registers `https://claude.ai/api/mcp/auth_callback`.
      // A wildcard-style attack tries `.../auth_callback/../evil` — must fail.
      const url = buildAuthorizeUrl(fixture, {
        redirect_uri: 'https://claude.ai/api/mcp/auth_callback/anything',
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(400);
      expect(response.headers.get('location')).toBeNull();
    });

    it('RFC 9700 §2.1.2 — substring prefix is NOT accepted (exact-match only)', async () => {
      const url = buildAuthorizeUrl(fixture, {
        redirect_uri: 'https://claude.ai/api/mcp',
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(400);
    });

    it('RFC 9700 §2.1.2 — different scheme (http instead of https) is refused', async () => {
      const url = buildAuthorizeUrl(fixture, {
        redirect_uri: 'http://claude.ai/api/mcp/auth_callback',
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(400);
    });

    it('RFC 9700 §2.1.2 — userinfo-embedded URI (userinfo attack) is refused', async () => {
      // `https://attacker@claude.ai/api/mcp/auth_callback` — a naive
      // normalizer would strip the userinfo and match the allowlist. The
      // redirect-uri module rejects any userinfo component.
      const url = buildAuthorizeUrl(fixture, {
        redirect_uri: 'https://attacker@claude.ai/api/mcp/auth_callback',
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(400);
    });

    it('RFC 9700 §2.1.2 — different registered host (claude.com vs claude.ai) still requires exact match', async () => {
      // Both claude.ai and claude.com are registered. Any other host must fail.
      const url = buildAuthorizeUrl(fixture, {
        redirect_uri: 'https://claude.attacker.com/api/mcp/auth_callback',
      });

      const response = await fetch(url, { redirect: 'manual' });
      expect(response.status).toBe(400);
    });
  });

  describe('§2.1.2 — Redirect URI matching at /register (dynamic client)', () => {
    let fixture: OauthFixture;

    beforeEach(async () => {
      fixture = await startOauthFixture({ enableDynamicRegistration: true });
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('RFC 9700 §2.1.2 — /register also enforces strict matching (no open registration)', async () => {
      // ADR-0003 Niveau B — we do NOT allow open dynamic registration. Even
      // when the endpoint is mounted, redirect_uris must be in the static
      // allowlist. This closes the 'register attacker.com then use its code'
      // exfiltration path.
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'evil',
          redirect_uris: ['https://attacker.example.com/callback'],
        }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error?: string };
      expect(body.error).toBe('invalid_redirect_uri');
    });
  });

  describe('§2.3 — Client authentication (public client posture)', () => {
    let fixture: OauthFixture;

    beforeEach(async () => {
      fixture = await startOauthFixture({ enableDynamicRegistration: true });
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('RFC 9700 §2.3 — public clients register with token_endpoint_auth_method=none', async () => {
      // BCP §2.3 : the AS must be honest about which clients are public.
      // MCP clients are public (no secret) — must be reflected in the metadata.
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'public-client',
          redirect_uris: [VALID_REDIRECT_URI],
        }),
      });

      expect(response.status).toBe(201);
      const body = (await response.json()) as {
        token_endpoint_auth_method?: string;
      };
      expect(body.token_endpoint_auth_method).toBe('none');
    });
  });

  describe('§4.1 — State parameter length is bounded', () => {
    let fixture: OauthFixture;

    beforeEach(async () => {
      fixture = await startOauthFixture();
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('RFC 9700 §4.1 — pathologically large state is rejected (memory-exhaustion guard)', async () => {
      // N0 B2 : maxStateLength default is 256. 2 KB must be refused.
      const url = buildAuthorizeUrl(fixture, { state: 'A'.repeat(2048) });

      const response = await fetch(url, { redirect: 'manual' });

      expect(response.status).toBe(400);
      const body = await response.text();
      expect(body.toLowerCase()).toContain('state');
    });
  });
});
