import { describe, expect, it, vi } from 'vitest';
import {
  computeEffectiveScope,
  createRegisterHandler,
  validateAuthorizeRedirectUri,
} from '../http-routes.js';
import { allRegisteredRedirectUris } from '../registered-clients.js';

function makeLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
  };
}

function makeRes() {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    type: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
    redirect: vi.fn().mockReturnThis(),
  };
  return res as unknown as import('express').Response & typeof res;
}

const ALLOWED = allRegisteredRedirectUris();
const REGISTERED_SCOPES_STRING =
  'User.Read Mail.Read Mail.ReadWrite Mail.Send Calendars.Read Calendars.ReadWrite offline_access openid profile';

describe('createRegisterHandler', () => {
  it('returns 400 when redirect_uris is missing', async () => {
    const handler = createRegisterHandler({
      allowedRedirectUris: ALLOWED,
      logger: makeLogger(),
    });
    const res = makeRes();
    await handler({ body: {} } as never, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'invalid_redirect_uri' })
    );
  });

  it('returns 400 when redirect_uris is empty array', async () => {
    const handler = createRegisterHandler({
      allowedRedirectUris: ALLOWED,
      logger: makeLogger(),
    });
    const res = makeRes();
    await handler({ body: { redirect_uris: [] } } as never, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('returns 400 when ANY redirect_uri is not in allowlist (codex N1-B2 regression)', async () => {
    const handler = createRegisterHandler({
      allowedRedirectUris: ALLOWED,
      logger: makeLogger(),
    });
    const res = makeRes();
    await handler(
      {
        body: {
          redirect_uris: [
            'https://claude.ai/api/mcp/auth_callback', // valid
            'https://evil.com/callback', // invalid → whole request rejected
          ],
        },
      } as never,
      res,
      vi.fn()
    );
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_redirect_uri',
        error_description: expect.stringContaining('registered-clients allowlist'),
      })
    );
  });

  it('returns 400 for userinfo bypass (N0-B1 regression)', async () => {
    const handler = createRegisterHandler({
      allowedRedirectUris: ALLOWED,
      logger: makeLogger(),
    });
    const res = makeRes();
    await handler(
      {
        body: {
          redirect_uris: ['https://attacker@claude.ai/api/mcp/auth_callback'],
        },
      } as never,
      res,
      vi.fn()
    );
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('returns 400 for trailing newline (mcp-vault v0.3.4 hygiene)', async () => {
    const handler = createRegisterHandler({
      allowedRedirectUris: ALLOWED,
      logger: makeLogger(),
    });
    const res = makeRes();
    await handler(
      {
        body: {
          redirect_uris: ['https://claude.ai/api/mcp/auth_callback\n'],
        },
      } as never,
      res,
      vi.fn()
    );
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('returns 201 with echoed metadata for valid request', async () => {
    const handler = createRegisterHandler({
      allowedRedirectUris: ALLOWED,
      logger: makeLogger(),
      now: () => 1234567890_000,
    });
    const res = makeRes();
    await handler(
      {
        body: {
          redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
          client_name: 'Claude',
        },
      } as never,
      res,
      vi.fn()
    );
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        client_id: 'mcp-client-1234567890000',
        client_id_issued_at: 1234567890,
        client_name: 'Claude',
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      })
    );
  });

  it('logs a warning when rejecting (audit trail)', async () => {
    const logger = makeLogger();
    const handler = createRegisterHandler({ allowedRedirectUris: ALLOWED, logger });
    const res = makeRes();
    await handler(
      { body: { redirect_uris: ['https://evil.com/cb'], client_name: 'sus' } } as never,
      res,
      vi.fn()
    );
    expect(logger.warn).toHaveBeenCalledWith(
      'Rejected /register: redirect_uri not in allowlist',
      expect.objectContaining({ invalid_count: 1, client_name: 'sus' })
    );
  });

  it('does not leak which specific URI failed in the response body', async () => {
    const handler = createRegisterHandler({ allowedRedirectUris: ALLOWED, logger: makeLogger() });
    const res = makeRes();
    await handler(
      {
        body: {
          redirect_uris: [
            'https://attacker.example.com/exfil?secret=AKIA1234567890',
          ],
        },
      } as never,
      res,
      vi.fn()
    );
    // Response should NOT echo the attacker-controlled URI (audit log keeps the count only)
    const jsonCalls = res.json.mock.calls;
    const bodySent = JSON.stringify(jsonCalls[0]?.[0] ?? {});
    expect(bodySent).not.toContain('attacker.example.com');
    expect(bodySent).not.toContain('AKIA1234567890');
  });
});

describe('validateAuthorizeRedirectUri', () => {
  it('returns ok=true for an allowlisted URI', () => {
    const r = validateAuthorizeRedirectUri('https://claude.ai/api/mcp/auth_callback', ALLOWED);
    expect(r.ok).toBe(true);
  });

  it('returns ok=false reason=missing when redirect_uri is null', () => {
    const r = validateAuthorizeRedirectUri(null, ALLOWED);
    expect(r).toEqual({ ok: false, reason: 'missing' });
  });

  it('returns ok=false reason=not_in_allowlist for wrong host', () => {
    const r = validateAuthorizeRedirectUri('https://evil.example.com/cb', ALLOWED);
    expect(r).toEqual({ ok: false, reason: 'not_in_allowlist' });
  });

  it('rejects userinfo bypass', () => {
    const r = validateAuthorizeRedirectUri(
      'https://attacker@claude.ai/api/mcp/auth_callback',
      ALLOWED
    );
    expect(r.ok).toBe(false);
  });

  it('rejects path-traversal', () => {
    const r = validateAuthorizeRedirectUri(
      'https://claude.ai/api/mcp/auth_callback/../evil',
      ALLOWED
    );
    expect(r.ok).toBe(false);
  });
});

describe('computeEffectiveScope', () => {
  function makeDeps(knownScopesList: string[]) {
    return {
      allowedRedirectUris: ALLOWED,
      registeredScopesString: REGISTERED_SCOPES_STRING,
      knownScopes: () => new Set(knownScopesList),
      logger: makeLogger(),
    };
  }

  it('intersects requested ∩ registered ∩ KNOWN', () => {
    const r = computeEffectiveScope('Mail.Read', makeDeps(['Mail.Read', 'Mail.ReadWrite']));
    expect(r.set.has('Mail.Read')).toBe(true);
    expect(r.set.has('Mail.ReadWrite')).toBe(false);
    expect(r.effective).toBe('Mail.Read');
  });

  it('drops scope NOT in KNOWN even if registered (e.g. Mail.ReadWrite when read-only)', () => {
    const r = computeEffectiveScope(
      'Mail.ReadWrite',
      makeDeps(['Mail.Read']) // writePolicy=read-only → Mail.ReadWrite not in KNOWN
    );
    // Mail.ReadWrite is dropped; result has no Graph scope.
    expect(r.set.has('Mail.ReadWrite')).toBe(false);
  });

  it('drops scope NOT in registered (e.g. Files.Read attempt)', () => {
    const r = computeEffectiveScope(
      'Files.Read Mail.Read',
      makeDeps(['Files.Read', 'Mail.Read']) // even if KNOWN somehow contains Files.Read
    );
    expect(r.set.has('Files.Read')).toBe(false);
    expect(r.set.has('Mail.Read')).toBe(true);
  });

  describe('META_SCOPES bypass (N0-B1 + N0-I2 fix)', () => {
    it('keeps offline_access even when KNOWN does not contain it', () => {
      // endpoints.json doesn't declare offline_access → KNOWN won't either.
      const r = computeEffectiveScope(
        'Mail.Read offline_access',
        makeDeps(['Mail.Read']) // no offline_access in KNOWN
      );
      expect(r.set.has('offline_access')).toBe(true);
      expect(r.set.has('Mail.Read')).toBe(true);
      expect(r.effective).toBe('Mail.Read offline_access');
    });

    it('keeps User.Read even when KNOWN does not contain it', () => {
      const r = computeEffectiveScope('User.Read Mail.Read', makeDeps(['Mail.Read']));
      expect(r.set.has('User.Read')).toBe(true);
    });

    it('keeps openid + profile (OIDC compliance)', () => {
      const r = computeEffectiveScope('openid profile Mail.Read', makeDeps(['Mail.Read']));
      expect(r.set.has('openid')).toBe(true);
      expect(r.set.has('profile')).toBe(true);
    });

    it('does NOT add META_SCOPES if not requested', () => {
      const r = computeEffectiveScope('Mail.Read', makeDeps(['Mail.Read']));
      expect(r.set.has('offline_access')).toBe(false);
      expect(r.set.has('User.Read')).toBe(false);
    });

    it('falls back to registered when scope param is undefined (includes META)', () => {
      // RFC 6749 §3.3 fallback : no scope → request = registered
      const r = computeEffectiveScope(undefined, makeDeps(['Mail.Read', 'Calendars.Read']));
      // Graph scopes via intersection
      expect(r.set.has('Mail.Read')).toBe(true);
      expect(r.set.has('Calendars.Read')).toBe(true);
      // META scopes added too
      expect(r.set.has('offline_access')).toBe(true);
      expect(r.set.has('User.Read')).toBe(true);
    });
  });

  it('returns null effective when intersection is empty AND no META requested', () => {
    const r = computeEffectiveScope('Files.Read', makeDeps([])); // not registered, not META
    expect(r.set.size).toBe(0);
    expect(r.effective).toBeNull();
  });

  it('produces sorted serialized scope (deterministic for tests/cache)', () => {
    const r = computeEffectiveScope(
      'Mail.Read offline_access User.Read',
      makeDeps(['Mail.Read'])
    );
    // serializeScope() sorts alphabetically
    expect(r.effective).toBe('Mail.Read User.Read offline_access');
  });

  describe('Mail.ReadWrite — write-policy regression (N0-I1 fix)', () => {
    it('forwards Mail.ReadWrite when --enable-send (writePolicy.mail=true → KNOWN includes it)', () => {
      const r = computeEffectiveScope(
        'Mail.ReadWrite offline_access',
        makeDeps(['Mail.ReadWrite']) // simulate --enable-send
      );
      expect(r.set.has('Mail.ReadWrite')).toBe(true);
      expect(r.set.has('offline_access')).toBe(true);
    });

    it('drops Mail.ReadWrite when read-only (writePolicy default → KNOWN excludes it)', () => {
      const r = computeEffectiveScope('Mail.ReadWrite Mail.Read', makeDeps(['Mail.Read']));
      expect(r.set.has('Mail.ReadWrite')).toBe(false);
      expect(r.set.has('Mail.Read')).toBe(true);
    });
  });
});
