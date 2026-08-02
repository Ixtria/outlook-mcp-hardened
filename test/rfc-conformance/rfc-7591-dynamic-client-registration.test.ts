/**
 * RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol.
 *
 * Contract tests labelled by RFC section for audit traceability (TEST-06,
 * 2026-08-02). Each test name is prefixed 'RFC 7591 §X.Y — description' so a
 * conformance auditor can grep the vitest output against the RFC table of
 * contents and see which clauses are actually exercised by CI.
 *
 * Scope: only the /register endpoint mounted by the OAuth fixture
 * (`test/helpers/oauth-server-fixture.ts`) is behavioral here. The endpoint
 * is opt-in (enableDynamicRegistration:true) — the server ships with it
 * gated by --enable-dynamic-registration in production.
 *
 * Discipline (ADR-0004 rule 3) : behavioral only. No fs.readFileSync,
 * no SOURCE.toContain, no regex on file content. Every assertion targets
 * an observable HTTP response.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  startOauthFixture,
  type OauthFixture,
} from '../helpers/oauth-server-fixture.js';

const VALID_REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';
const INVALID_REDIRECT_URI = 'https://attacker.example.com/callback';

describe('RFC 7591 — Dynamic Client Registration', () => {
  let fixture: OauthFixture;

  beforeEach(async () => {
    fixture = await startOauthFixture({ enableDynamicRegistration: true });
  });

  afterEach(async () => {
    await fixture.close();
  });

  describe('§2 — Client Metadata: redirect_uris', () => {
    it('RFC 7591 §2 — rejects registration with missing redirect_uris (invalid_redirect_uri)', async () => {
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: 'test-client' }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as {
        error?: string;
        error_description?: string;
      };
      // §5.1 error code taxonomy — missing redirect_uris is invalid_redirect_uri
      // (they cannot be validated if absent, so the URI check is what fires).
      expect(body.error).toBe('invalid_redirect_uri');
      expect(body.error_description).toMatch(/redirect_uris/i);
    });

    it('RFC 7591 §2 — rejects registration with empty redirect_uris array', async () => {
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: 'test-client', redirect_uris: [] }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error?: string };
      expect(body.error).toBe('invalid_redirect_uri');
    });

    it('RFC 7591 §2 — rejects redirect_uris that is not an array (type check)', async () => {
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'test-client',
          redirect_uris: VALID_REDIRECT_URI, // string, not array
        }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error?: string };
      expect(body.error).toBe('invalid_redirect_uri');
    });
  });

  describe('§3.1 — Client Registration Request: Content-Type', () => {
    it('RFC 7591 §3.1 — accepts application/json Content-Type', async () => {
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'json-client',
          redirect_uris: [VALID_REDIRECT_URI],
        }),
      });

      // Successful registration should return 201 with the client metadata.
      expect(response.status).toBe(201);
      expect(response.headers.get('content-type')).toContain(
        'application/json',
      );
    });

    it('RFC 7591 §3.1 — non-JSON body is not parsed as valid registration', async () => {
      // Express.json() only parses application/json — a text/plain payload
      // results in an empty req.body which triggers the redirect_uris check.
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: `redirect_uris=${VALID_REDIRECT_URI}`,
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error?: string };
      // Without JSON parsing, redirect_uris is undefined → invalid_redirect_uri.
      expect(body.error).toBe('invalid_redirect_uri');
    });
  });

  describe('§3.2.1 — Client Information Response', () => {
    it('RFC 7591 §3.2.1 — successful registration returns client_id + client_id_issued_at', async () => {
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'meta-client',
          redirect_uris: [VALID_REDIRECT_URI],
        }),
      });

      expect(response.status).toBe(201);
      const body = (await response.json()) as {
        client_id?: string;
        client_id_issued_at?: number;
        redirect_uris?: string[];
        grant_types?: string[];
        response_types?: string[];
        token_endpoint_auth_method?: string;
      };

      expect(typeof body.client_id).toBe('string');
      expect(body.client_id?.length).toBeGreaterThan(0);
      expect(typeof body.client_id_issued_at).toBe('number');
      // Registration must echo the accepted redirect_uris (§3.2.1).
      expect(body.redirect_uris).toEqual([VALID_REDIRECT_URI]);
      // Defaults RFC 7591 §2 : authorization_code + refresh_token, response_type=code.
      expect(body.grant_types).toContain('authorization_code');
      expect(body.response_types).toContain('code');
      expect(body.token_endpoint_auth_method).toBe('none');
    });
  });

  describe('§5.1 — Client Registration Error Response', () => {
    it('RFC 7591 §5.1 — invalid_redirect_uri when a URI is not in the allowlist', async () => {
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'attacker',
          redirect_uris: [INVALID_REDIRECT_URI],
        }),
      });

      expect(response.status).toBe(400);
      expect(response.headers.get('content-type')).toContain(
        'application/json',
      );
      const body = (await response.json()) as {
        error?: string;
        error_description?: string;
      };
      expect(body.error).toBe('invalid_redirect_uri');
      expect(typeof body.error_description).toBe('string');
      expect(body.error_description?.length).toBeGreaterThan(0);
    });

    it('RFC 7591 §5.1 — invalid_redirect_uri when a mix of valid + invalid URIs is submitted', async () => {
      // ADR-0003 D2 : any invalid URI in the batch rejects the whole request —
      // partial acceptance would let an attacker register (legit, attacker)
      // and later exfiltrate codes via the second one.
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'mixed',
          redirect_uris: [VALID_REDIRECT_URI, INVALID_REDIRECT_URI],
        }),
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error?: string };
      expect(body.error).toBe('invalid_redirect_uri');
    });

    it('RFC 7591 §5.1 — error response is a JSON object with an error field', async () => {
      const response = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body: unknown = await response.json();
      expect(typeof body).toBe('object');
      expect(body).not.toBeNull();
      const asRecord = body as Record<string, unknown>;
      // RFC 7591 §5.1 : `error` is REQUIRED and MUST be a single ASCII string.
      expect(typeof asRecord.error).toBe('string');
    });
  });
});
