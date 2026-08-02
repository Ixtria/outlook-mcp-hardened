/**
 * OBS-02 (2026-08-02) — Behavioral tests for the OAuth audit-event catalog.
 *
 * Every OAuth-facing event listed in `docs/AUDIT_EVENTS.md` MUST be emitted
 * by real handler code under a real (or realistic) HTTP round-trip. This
 * file asserts on the observable audit stream — the JSON-line output that
 * `auditLog()` writes to `process.stderr` — never on source content.
 *
 * Discipline (ADR-0004 rule 3) : no `fs.readFileSync` on src/,
 * no `SOURCE.toContain`. Behavior only.
 *
 * Two entry points are exercised :
 *
 *   1. `startFullOauthFixture()` — the same factory `src/server.ts` wires
 *      in production — covers /register, /authorize, POST /authorize,
 *      /token (with the audit wrapper injected via `withTokenExchangeAudit`).
 *
 *   2. `verifyMicrosoftAccessToken()` invoked directly with a mocked global
 *      `fetch` — covers /mcp verify success, /mcp verify reject, and the
 *      egress-guard-triggered egress.violation branch. The fixture bypasses
 *      the real verifier via its `tokenVerifier` stub, so these paths cannot
 *      be reached from a /mcp HTTP round-trip against the fixture.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  startFullOauthFixture,
  type FullOauthFixture,
} from './helpers/oauth-server-fixture.js';
import {
  verifyMicrosoftAccessToken,
  withTokenExchangeAudit,
} from '../src/oauth-provider.js';
import { EgressViolationError } from '../src/security/egress-guard.js';
import { resetAuditSaltCache } from '../src/security/audit-salt.js';
import type AuthManager from '../src/auth.js';

const VALID_REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';

interface CapturedAudit {
  ts: string;
  tool: string;
  method: string;
  path: string;
  scopes: string[];
  account: string;
  status: number;
  duration_ms: number;
  request_id?: string;
}

/**
 * Attach a stderr spy that parses every JSON line the audit-logger writes
 * and exposes them as strongly-typed `CapturedAudit` objects. Passes
 * anything that isn't an OAuth audit line straight through — we don't want
 * to swallow unrelated stderr chatter.
 */
function captureAudits(): {
  audits: CapturedAudit[];
  rawLines: string[];
  spy: ReturnType<typeof vi.spyOn>;
  restore: () => void;
} {
  const audits: CapturedAudit[] = [];
  const rawLines: string[] = [];
  const spy = vi
    .spyOn(process.stderr, 'write')
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- justif: process.stderr.write accepts many overloads; the mock only needs the truthy return.
    .mockImplementation(((chunk: any): boolean => {
      const line = typeof chunk === 'string' ? chunk : String(chunk);
      rawLines.push(line);
      for (const segment of line.split('\n').filter((s) => s.length > 0)) {
        try {
          const parsed = JSON.parse(segment) as CapturedAudit;
          if (typeof parsed.tool === 'string' && parsed.tool.startsWith('oauth.')) {
            audits.push(parsed);
          }
        } catch {
          // Not JSON — plain stderr line (winston console, etc). Ignore.
        }
      }
      return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- justif: same as above; matches the spied signature loosely.
    }) as any);

  return {
    audits,
    rawLines,
    spy,
    restore: () => spy.mockRestore(),
  };
}

/**
 * Assert that the given audit stream does NOT leak any of the supplied
 * sensitive values in ANY field of ANY emitted line. Consolidates the
 * per-test PII-safety check.
 */
function assertNoSensitiveLeaks(audits: CapturedAudit[], sensitive: string[]): void {
  const joined = audits.map((a) => JSON.stringify(a)).join('\n');
  for (const secret of sensitive) {
    expect(joined).not.toContain(secret);
  }
}

describe('OBS-02 — OAuth audit events', () => {
  let fixture: FullOauthFixture | undefined;
  let capture: ReturnType<typeof captureAudits>;

  beforeEach(() => {
    // Pin the audit salt so hashAccount() output is deterministic across the
    // suite. Same trick as test/audit-logger.test.ts.
    process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = '00112233445566778899aabbccddeeff';
    resetAuditSaltCache();
    capture = captureAudits();
  });

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
    capture.restore();
    delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    resetAuditSaltCache();
  });

  // ────────────────────────────────────────────────────────────────────────
  //  oauth.client.register
  // ────────────────────────────────────────────────────────────────────────
  describe('oauth.client.register', () => {
    it('emits status=201 on a successful /register call', async () => {
      fixture = await startFullOauthFixture({ enableDynamicRegistration: true });

      const resp = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: [VALID_REDIRECT_URI],
          client_name: 'audit-test-success',
        }),
      });
      expect(resp.status).toBe(201);

      const registerAudits = capture.audits.filter((a) => a.tool === 'oauth.client.register');
      expect(registerAudits).toHaveLength(1);
      expect(registerAudits[0]).toMatchObject({
        tool: 'oauth.client.register',
        method: 'POST',
        path: '/register',
        status: 201,
        account: 'none',
        scopes: [],
      });
      expect(registerAudits[0]!.duration_ms).toBeGreaterThanOrEqual(0);
    });

    it('emits status=400 when redirect_uris is missing', async () => {
      fixture = await startFullOauthFixture({ enableDynamicRegistration: true });

      const resp = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: 'audit-test-missing' }),
      });
      expect(resp.status).toBe(400);

      const registerAudits = capture.audits.filter((a) => a.tool === 'oauth.client.register');
      expect(registerAudits).toHaveLength(1);
      expect(registerAudits[0]!.status).toBe(400);
    });

    it('emits status=400 when redirect_uri is not in the allowlist', async () => {
      fixture = await startFullOauthFixture({ enableDynamicRegistration: true });

      const attackerUri = 'https://attacker.example/steal';
      const resp = await fetch(new URL('/register', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: [attackerUri],
          client_name: 'audit-test-attacker',
        }),
      });
      expect(resp.status).toBe(400);

      const registerAudits = capture.audits.filter((a) => a.tool === 'oauth.client.register');
      expect(registerAudits).toHaveLength(1);
      expect(registerAudits[0]!.status).toBe(400);

      // Sensitive field guard : the attacker's URI is a redirect_uri and
      // MUST NOT be echoed into the audit stream.
      assertNoSensitiveLeaks(registerAudits, [attackerUri, 'audit-test-attacker']);
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  //  oauth.authorize.request  +  oauth.authorize.reject
  // ────────────────────────────────────────────────────────────────────────
  describe('oauth.authorize.request / oauth.authorize.reject', () => {
    it('emits oauth.authorize.request status=302 on a valid PKCE redirect', async () => {
      fixture = await startFullOauthFixture();
      const url = new URL('/authorize', fixture.baseUrl);
      url.searchParams.set('client_id', 'test-client');
      url.searchParams.set('redirect_uri', VALID_REDIRECT_URI);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'Mail.Read');
      url.searchParams.set('state', 'obs02-happy');
      url.searchParams.set('code_challenge', 'X'.repeat(43));
      url.searchParams.set('code_challenge_method', 'S256');

      const resp = await fetch(url, { redirect: 'manual' });
      expect(resp.status).toBe(302);

      const authorizeAudits = capture.audits.filter((a) => a.tool === 'oauth.authorize.request');
      expect(authorizeAudits).toHaveLength(1);
      expect(authorizeAudits[0]).toMatchObject({
        tool: 'oauth.authorize.request',
        method: 'GET',
        path: '/authorize',
        status: 302,
        account: 'none',
      });
      // Effective scopes reach the audit stream — that's the whole point of
      // this event : "what was this client authorized for?"
      expect(authorizeAudits[0]!.scopes).toContain('Mail.Read');
    });

    it('emits oauth.authorize.reject status=400 when code_challenge is missing (PKCE mandatory)', async () => {
      fixture = await startFullOauthFixture();
      const url = new URL('/authorize', fixture.baseUrl);
      url.searchParams.set('client_id', 'test-client');
      url.searchParams.set('redirect_uri', VALID_REDIRECT_URI);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'Mail.Read');
      url.searchParams.set('state', 'obs02-no-pkce');

      const resp = await fetch(url, { redirect: 'manual' });
      expect(resp.status).toBe(400);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.authorize.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]).toMatchObject({
        tool: 'oauth.authorize.reject',
        method: 'GET',
        path: '/authorize',
        status: 400,
      });
    });

    it('emits oauth.authorize.reject status=400 when redirect_uri is not registered', async () => {
      fixture = await startFullOauthFixture();
      const url = new URL('/authorize', fixture.baseUrl);
      url.searchParams.set('client_id', 'test-client');
      url.searchParams.set('redirect_uri', 'https://attacker.example/cb');
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'Mail.Read');
      url.searchParams.set('code_challenge', 'X'.repeat(43));
      url.searchParams.set('code_challenge_method', 'S256');

      const resp = await fetch(url, { redirect: 'manual' });
      expect(resp.status).toBe(400);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.authorize.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]!.status).toBe(400);
      assertNoSensitiveLeaks(rejects, ['https://attacker.example/cb']);
    });

    it('emits oauth.authorize.reject status=405 on POST /authorize (N4-B2)', async () => {
      fixture = await startFullOauthFixture();

      const resp = await fetch(new URL('/authorize', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'client_id=x',
      });
      expect(resp.status).toBe(405);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.authorize.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]).toMatchObject({
        tool: 'oauth.authorize.reject',
        method: 'POST',
        path: '/authorize',
        status: 405,
      });
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  //  oauth.token.request  +  oauth.token.reject
  // ────────────────────────────────────────────────────────────────────────
  describe('oauth.token.request / oauth.token.reject', () => {
    // We inject wrapped stubs into the fixture — this is exactly what
    // server.ts does in production via `withTokenExchangeAudit(...)`.
    // The stubs themselves do NOT touch AAD.

    const CANNED_ACCESS_TOKEN = 'test-fixture-access-token-XYZ';
    const CANNED_REFRESH_TOKEN = 'test-fixture-refresh-token-ABC';
    const SUBMITTED_CODE = 'authcode-from-aad-42';
    const SUBMITTED_VERIFIER = 'v'.repeat(64);

    it('emits oauth.token.request status=200 on a successful authorization_code exchange', async () => {
      fixture = await startFullOauthFixture({
        exchangeCode: withTokenExchangeAudit(async () => ({
          access_token: CANNED_ACCESS_TOKEN,
          token_type: 'Bearer',
          scope: 'Mail.Read User.Read',
          expires_in: 3600,
          refresh_token: CANNED_REFRESH_TOKEN,
        })),
      });

      const resp = await fetch(new URL('/token', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: SUBMITTED_CODE,
          redirect_uri: VALID_REDIRECT_URI,
          code_verifier: SUBMITTED_VERIFIER,
        }).toString(),
      });
      expect(resp.status).toBe(200);

      const tokenAudits = capture.audits.filter((a) => a.tool === 'oauth.token.request');
      expect(tokenAudits).toHaveLength(1);
      expect(tokenAudits[0]).toMatchObject({
        tool: 'oauth.token.request',
        method: 'POST',
        path: '/token',
        status: 200,
      });
      expect(tokenAudits[0]!.scopes).toEqual(expect.arrayContaining(['Mail.Read', 'User.Read']));

      // Sensitive-field guard : NONE of the OAuth secrets touched in this
      // exchange should surface in the audit stream.
      assertNoSensitiveLeaks(capture.audits, [
        CANNED_ACCESS_TOKEN,
        CANNED_REFRESH_TOKEN,
        SUBMITTED_CODE,
        SUBMITTED_VERIFIER,
      ]);
    });

    it('emits oauth.token.request status=200 on a successful refresh_token grant', async () => {
      fixture = await startFullOauthFixture({
        refreshToken: withTokenExchangeAudit(async () => ({
          access_token: 'refresh-new-access-999',
          token_type: 'Bearer',
          scope: 'Mail.Read offline_access',
          expires_in: 3600,
          refresh_token: 'refresh-new-refresh-000',
        })),
      });

      const resp = await fetch(new URL('/token', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: 'incoming-refresh-token-BAD',
        }).toString(),
      });
      expect(resp.status).toBe(200);

      const tokenAudits = capture.audits.filter((a) => a.tool === 'oauth.token.request');
      expect(tokenAudits).toHaveLength(1);
      expect(tokenAudits[0]!.status).toBe(200);

      assertNoSensitiveLeaks(capture.audits, [
        'incoming-refresh-token-BAD',
        'refresh-new-access-999',
        'refresh-new-refresh-000',
      ]);
    });

    it('emits oauth.token.reject status=500 when the exchange throws a non-egress error', async () => {
      fixture = await startFullOauthFixture({
        exchangeCode: withTokenExchangeAudit(async () => {
          throw new Error('simulated AAD 400 invalid_grant');
        }),
      });

      const resp = await fetch(new URL('/token', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'bad-code',
          redirect_uri: VALID_REDIRECT_URI,
        }).toString(),
      });
      expect(resp.status).toBe(500);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.token.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]).toMatchObject({
        tool: 'oauth.token.reject',
        method: 'POST',
        path: '/token',
        status: 500,
      });
    });

    it('emits oauth.egress.violation + oauth.token.reject status=502 when EgressViolationError is thrown', async () => {
      const url = 'https://attacker.example/steal-tokens';
      fixture = await startFullOauthFixture({
        exchangeCode: withTokenExchangeAudit(async () => {
          throw new EgressViolationError('attacker.example', url, 'hostname not in allowlist');
        }),
      });

      const resp = await fetch(new URL('/token', fixture.baseUrl), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'x',
          redirect_uri: VALID_REDIRECT_URI,
        }).toString(),
      });
      expect(resp.status).toBe(500);

      const egress = capture.audits.filter((a) => a.tool === 'oauth.egress.violation');
      expect(egress).toHaveLength(1);
      expect(egress[0]!.status).toBe(0);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.token.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]!.status).toBe(502);
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  //  oauth.mcp.request  +  oauth.mcp.reject  +  oauth.egress.violation
  //
  //  These live in verifyMicrosoftAccessToken(). The full-stack fixture
  //  stubs the verifier, so we call the real function directly with a mocked
  //  global fetch.
  // ────────────────────────────────────────────────────────────────────────
  describe('oauth.mcp.request / oauth.mcp.reject (verifyMicrosoftAccessToken)', () => {
    let originalFetch: typeof fetch;
    const stubAuthManager = { setOAuthToken: vi.fn() } as unknown as AuthManager;

    beforeEach(() => {
      originalFetch = globalThis.fetch;
    });

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it('emits oauth.mcp.request status=200 with hashed UPN on a successful Graph /me call', async () => {
      globalThis.fetch = vi.fn(
        async () =>
          ({
            ok: true,
            status: 200,
            json: async () => ({ userPrincipalName: 'alice@example.com' }),
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- justif: stubbed Response shape, only `ok`/`status`/`json` are consumed by the SUT.
          }) as any
      );

      await verifyMicrosoftAccessToken(
        'bearer-token-SECRET-XYZ',
        'global',
        'client-id-42',
        stubAuthManager
      );

      const mcpAudits = capture.audits.filter((a) => a.tool === 'oauth.mcp.request');
      expect(mcpAudits).toHaveLength(1);
      expect(mcpAudits[0]).toMatchObject({
        tool: 'oauth.mcp.request',
        method: 'GET',
        path: '/mcp',
        status: 200,
      });
      // account is the HMAC-hashed UPN, NOT the raw email.
      expect(mcpAudits[0]!.account).toMatch(/^hmac-sha256:[a-f0-9]{32}$/);

      // Sensitive-field guard : the raw Bearer token and the raw UPN never
      // reach the audit stream.
      assertNoSensitiveLeaks(capture.audits, [
        'bearer-token-SECRET-XYZ',
        'alice@example.com',
      ]);
    });

    it('emits oauth.mcp.reject with the Graph status when Graph returns non-2xx', async () => {
      globalThis.fetch = vi.fn(
        async () =>
          ({
            ok: false,
            status: 401,
            json: async () => ({}),
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- justif: same shape rationale.
          }) as any
      );

      await expect(
        verifyMicrosoftAccessToken('bad-bearer', 'global', 'client-id-42', stubAuthManager)
      ).rejects.toThrow(/Token verification failed: 401/);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.mcp.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]).toMatchObject({
        tool: 'oauth.mcp.reject',
        method: 'GET',
        path: '/mcp',
        status: 401,
        account: 'none',
      });

      assertNoSensitiveLeaks(capture.audits, ['bad-bearer']);
    });

    it('emits oauth.mcp.reject status=0 when fetch itself throws (network flake)', async () => {
      globalThis.fetch = vi.fn(async () => {
        throw new Error('ECONNREFUSED');
      });

      await expect(
        verifyMicrosoftAccessToken(
          'bearer-token-net-fail',
          'global',
          'client-id-42',
          stubAuthManager
        )
      ).rejects.toThrow(/ECONNREFUSED/);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.mcp.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]!.status).toBe(0);
      // Nothing else — a plain network error is not an egress violation.
      const egress = capture.audits.filter((a) => a.tool === 'oauth.egress.violation');
      expect(egress).toHaveLength(0);
    });

    it('emits oauth.egress.violation + oauth.mcp.reject when the egress guard blocks the fetch', async () => {
      const blockedUrl = 'https://graph.microsoft.com.attacker.example/v1.0/me';
      globalThis.fetch = vi.fn(async () => {
        throw new EgressViolationError(
          'graph.microsoft.com.attacker.example',
          blockedUrl,
          'hostname not in allowlist'
        );
      });

      await expect(
        verifyMicrosoftAccessToken('bearer-blocked', 'global', 'client-id-42', stubAuthManager)
      ).rejects.toThrow(EgressViolationError);

      const egress = capture.audits.filter((a) => a.tool === 'oauth.egress.violation');
      expect(egress).toHaveLength(1);
      expect(egress[0]!.status).toBe(0);

      const rejects = capture.audits.filter((a) => a.tool === 'oauth.mcp.reject');
      expect(rejects).toHaveLength(1);
      expect(rejects[0]!.status).toBe(0);

      assertNoSensitiveLeaks(capture.audits, ['bearer-blocked']);
    });
  });
});
