/**
 * Tests for createBearerAuthMiddleware — N0 I2 BLOCKER fix regression suite.
 *
 * Before the fix, microsoftBearerTokenAuthMiddleware was pass-through — any
 * string after "Bearer " reached the protected handler. This test suite
 * asserts the new factory's contract: verifier MUST be called, failures MUST
 * return 401 with WWW-Authenticate, the token MUST be attached to req only
 * on success.
 */

import { describe, expect, it, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { createBearerAuthMiddleware } from '../src/lib/microsoft-auth.js';

vi.mock('../src/logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

type ReqWithAuth = Request & {
  microsoftAuth?: { accessToken: string; refreshToken: string };
  clientIp?: string;
};

function makeReq(headers: Record<string, string> = {}, clientIp = '127.0.0.1'): ReqWithAuth {
  return {
    headers,
    clientIp,
  } as ReqWithAuth;
}

function makeRes() {
  const res = {
    status: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  return res as unknown as Response & typeof res;
}

describe('createBearerAuthMiddleware (N0 I2 BLOCKER fix)', () => {
  describe('missing or malformed header', () => {
    it('returns 401 + WWW-Authenticate when Authorization header is missing', async () => {
      const verifier = vi.fn();
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({});
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.set).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer realm="mcp"');
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'invalid_token' })
      );
      expect(verifier).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it('returns 401 when header does not start with "Bearer "', async () => {
      const verifier = vi.fn();
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: 'Basic abc123' });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(verifier).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it('returns 401 when Bearer token is empty', async () => {
      const verifier = vi.fn();
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: 'Bearer ' });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.set).toHaveBeenCalledWith(
        'WWW-Authenticate',
        'Bearer realm="mcp", error="invalid_token"'
      );
      expect(verifier).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it('returns 401 when Bearer token is only whitespace', async () => {
      const verifier = vi.fn();
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: 'Bearer    ' });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(verifier).not.toHaveBeenCalled();
    });
  });

  describe('verifier rejection (N0 I2 main case)', () => {
    it('returns 401 + WWW-Authenticate when verifier throws', async () => {
      const verifier = vi.fn().mockRejectedValue(new Error('Token verification failed: 401'));
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: 'Bearer forged-token-12345' });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(verifier).toHaveBeenCalledWith('forged-token-12345');
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.set).toHaveBeenCalledWith(
        'WWW-Authenticate',
        'Bearer realm="mcp", error="invalid_token"'
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('does NOT attach req.microsoftAuth when verifier rejects', async () => {
      const verifier = vi.fn().mockRejectedValue(new Error('bad token'));
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: 'Bearer bad' });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(req.microsoftAuth).toBeUndefined();
    });

    it('does NOT leak the failing token in response body', async () => {
      const verifier = vi.fn().mockRejectedValue(new Error('Token verification failed: 401'));
      const mw = createBearerAuthMiddleware(verifier);
      const sensitiveToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.SENSITIVE.PAYLOAD';
      const req = makeReq({ authorization: `Bearer ${sensitiveToken}` });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      const jsonCalls = res.json.mock.calls;
      const bodySent = JSON.stringify(jsonCalls[0]?.[0] ?? {});
      expect(bodySent).not.toContain('SENSITIVE');
      expect(bodySent).not.toContain('PAYLOAD');
      expect(bodySent).not.toContain(sensitiveToken);
    });
  });

  describe('verifier accepts (happy path)', () => {
    it('calls next() and attaches token to req.microsoftAuth', async () => {
      const verifier = vi.fn().mockResolvedValue({ token: 'good', clientId: 'x', scopes: [] });
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: 'Bearer good-token' });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(verifier).toHaveBeenCalledWith('good-token');
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(req.microsoftAuth).toEqual({
        accessToken: 'good-token',
        refreshToken: '',
      });
    });

    it('captures x-microsoft-refresh-token header when present', async () => {
      const verifier = vi.fn().mockResolvedValue({ token: 'good', clientId: 'x', scopes: [] });
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({
        authorization: 'Bearer good-token',
        'x-microsoft-refresh-token': 'refresh-abc',
      });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(req.microsoftAuth?.refreshToken).toBe('refresh-abc');
    });

    it('strips trailing whitespace from token before verifier call', async () => {
      const verifier = vi.fn().mockResolvedValue({});
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: 'Bearer trimmed-token   ' });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(verifier).toHaveBeenCalledWith('trimmed-token');
    });
  });

  describe('attack scenarios (regression)', () => {
    it('SQL-injection-style token is rejected by verifier and 401 returned', async () => {
      const verifier = vi.fn().mockRejectedValue(new Error('Token verification failed: 401'));
      const mw = createBearerAuthMiddleware(verifier);
      const req = makeReq({ authorization: "Bearer ' OR 1=1 --" });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('JWT-shaped forged token is verified (not naively passed through)', async () => {
      // Before I2 fix, the old middleware accepted any "JWT-shaped" string.
      // Now we delegate to the verifier — which would reach out to Graph and
      // get rejected. Test asserts the verifier IS called even with a
      // plausible-looking JWT.
      const verifier = vi.fn().mockRejectedValue(new Error('Token verification failed: 401'));
      const mw = createBearerAuthMiddleware(verifier);
      const forgedJwt =
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.fake-sig';
      const req = makeReq({ authorization: `Bearer ${forgedJwt}` });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      expect(verifier).toHaveBeenCalledWith(forgedJwt);
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('extremely long token is still passed through (verifier decides)', async () => {
      const verifier = vi.fn().mockRejectedValue(new Error('bad'));
      const mw = createBearerAuthMiddleware(verifier);
      const longToken = 'x'.repeat(10_000);
      const req = makeReq({ authorization: `Bearer ${longToken}` });
      const res = makeRes();
      const next = vi.fn() as NextFunction;

      await mw(req, res, next);

      // We do NOT short-circuit on length — that's the verifier's call.
      expect(verifier).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });
  });
});
