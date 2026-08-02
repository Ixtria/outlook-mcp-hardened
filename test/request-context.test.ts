import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import {
  coerceClientRequestId,
  createRequestIdMiddleware,
  getRequestId,
  getRequestTokens,
  parseTrustedProxiesEnv,
  requestContext,
} from '../src/request-context.js';
import { auditLog } from '../src/security/audit-logger.js';
import { resetAuditSaltCache } from '../src/security/audit-salt.js';
import GraphClient from '../src/graph-client.js';
import type AuthManager from '../src/auth.js';
import { AppSecrets } from '../src/secrets.js';

describe('parseTrustedProxiesEnv', () => {
  it('returns empty Set for undefined / empty / whitespace', () => {
    expect(parseTrustedProxiesEnv(undefined).size).toBe(0);
    expect(parseTrustedProxiesEnv('').size).toBe(0);
    expect(parseTrustedProxiesEnv('   ').size).toBe(0);
    expect(parseTrustedProxiesEnv(',,,').size).toBe(0);
  });

  it('parses single IP', () => {
    const set = parseTrustedProxiesEnv('10.0.0.1');
    expect(set.has('10.0.0.1')).toBe(true);
    expect(set.size).toBe(1);
  });

  it('parses comma-separated list with whitespace tolerance', () => {
    const set = parseTrustedProxiesEnv('  10.0.0.1 , 10.0.0.2 ,127.0.0.1  ');
    expect(set.has('10.0.0.1')).toBe(true);
    expect(set.has('10.0.0.2')).toBe(true);
    expect(set.has('127.0.0.1')).toBe(true);
    expect(set.size).toBe(3);
  });

  it('filters out empty tokens from trailing/double commas', () => {
    const set = parseTrustedProxiesEnv('10.0.0.1,,10.0.0.2,');
    expect(set.size).toBe(2);
  });
});

describe('request-context', () => {
  it('should isolate tokens between concurrent async operations', async () => {
    const results: string[] = [];

    const request1 = requestContext.run(
      { accessToken: 'token-A', refreshToken: 'refresh-A' },
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        const tokens = getRequestTokens();
        results.push(`req1: ${tokens?.accessToken}`);
        return tokens?.accessToken;
      }
    );

    const request2 = requestContext.run(
      { accessToken: 'token-B', refreshToken: 'refresh-B' },
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        const tokens = getRequestTokens();
        results.push(`req2: ${tokens?.accessToken}`);
        return tokens?.accessToken;
      }
    );

    const [result1, result2] = await Promise.all([request1, request2]);

    expect(result1).toBe('token-A');
    expect(result2).toBe('token-B');
    expect(results).toContain('req1: token-A');
    expect(results).toContain('req2: token-B');
  });

  it('should return undefined outside of request context', () => {
    const tokens = getRequestTokens();
    expect(tokens).toBeUndefined();
  });

  it('should handle nested async operations within a context', async () => {
    const result = await requestContext.run({ accessToken: 'outer-token' }, async () => {
      const inner = async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return getRequestTokens()?.accessToken;
      };

      const [a, b, c] = await Promise.all([inner(), inner(), inner()]);

      return { a, b, c };
    });

    expect(result.a).toBe('outer-token');
    expect(result.b).toBe('outer-token');
    expect(result.c).toBe('outer-token');
  });

  it('should not leak tokens between separate contexts', async () => {
    const tokens: (string | undefined)[] = [];

    const p1 = requestContext.run({ accessToken: 'first' }, async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      tokens.push(getRequestTokens()?.accessToken);
    });

    await new Promise((resolve) => setTimeout(resolve, 5));
    const p2 = requestContext.run({ accessToken: 'second' }, async () => {
      tokens.push(getRequestTokens()?.accessToken);
    });

    tokens.push(getRequestTokens()?.accessToken);

    await Promise.all([p1, p2]);

    expect(tokens).toContain('first');
    expect(tokens).toContain('second');
    expect(tokens).toContain(undefined);
  });
});

describe('GraphClient request-context integration', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('should use correct token for each concurrent request (race condition test)', async () => {
    const capturedTokens: string[] = [];

    global.fetch = vi
      .fn()
      .mockImplementation(async (_url: string, options: { headers?: Record<string, string> }) => {
        const authHeader = options.headers?.['Authorization'];
        const token = authHeader?.replace('Bearer ', '') ?? '';
        capturedTokens.push(token);

        await new Promise((resolve) => setTimeout(resolve, Math.random() * 10));

        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ id: 'test' }),
          headers: new Headers(),
        };
      });

    const mockAuthManager = {
      getToken: vi.fn().mockResolvedValue(null),
    } as unknown as AuthManager;

    const mockSecrets: AppSecrets = {
      clientId: 'test-client',
      tenantId: 'common',
      cloudType: 'global',
    };

    const graphClient = new GraphClient(mockAuthManager, mockSecrets);

    const userARequest = requestContext.run({ accessToken: 'USER_A_TOKEN' }, async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      await graphClient.makeRequest('/me');
      return 'A';
    });

    const userBRequest = requestContext.run({ accessToken: 'USER_B_TOKEN' }, async () => {
      await graphClient.makeRequest('/me');
      return 'B';
    });

    const userCRequest = requestContext.run({ accessToken: 'USER_C_TOKEN' }, async () => {
      await new Promise((resolve) => setTimeout(resolve, 2));
      await graphClient.makeRequest('/me');
      return 'C';
    });

    await Promise.all([userARequest, userBRequest, userCRequest]);

    expect(capturedTokens).toHaveLength(3);
    expect(capturedTokens).toContain('USER_A_TOKEN');
    expect(capturedTokens).toContain('USER_B_TOKEN');
    expect(capturedTokens).toContain('USER_C_TOKEN');

    const tokenCounts = capturedTokens.reduce(
      (acc, token) => {
        acc[token] = (acc[token] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    expect(tokenCounts['USER_A_TOKEN']).toBe(1);
    expect(tokenCounts['USER_B_TOKEN']).toBe(1);
    expect(tokenCounts['USER_C_TOKEN']).toBe(1);
  });

  it('should not leak tokens when requests overlap in time', async () => {
    const requestLog: { token: string; timestamp: number }[] = [];
    const startTime = Date.now();

    global.fetch = vi
      .fn()
      .mockImplementation(async (_url: string, options: { headers?: Record<string, string> }) => {
        const authHeader = options.headers?.['Authorization'];
        const token = authHeader?.replace('Bearer ', '') ?? '';

        requestLog.push({ token, timestamp: Date.now() - startTime });

        await new Promise((resolve) => setTimeout(resolve, 50));

        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ id: 'test' }),
          headers: new Headers(),
        };
      });

    const mockAuthManager = {
      getToken: vi.fn().mockResolvedValue(null),
    } as unknown as AuthManager;

    const secrets: AppSecrets = {
      clientId: 'test-client',
      tenantId: 'common',
      cloudType: 'global',
    };

    const graphClient = new GraphClient(mockAuthManager, secrets);

    const requestA = requestContext.run({ accessToken: 'ALICE_TOKEN' }, async () => {
      await graphClient.makeRequest('/me/messages');
    });

    await new Promise((resolve) => setTimeout(resolve, 10));
    const requestB = requestContext.run({ accessToken: 'BOB_TOKEN' }, async () => {
      await graphClient.makeRequest('/me/calendar');
    });

    await Promise.all([requestA, requestB]);

    expect(requestLog).toHaveLength(2);
    expect(requestLog.map((r) => r.token).sort()).toEqual(['ALICE_TOKEN', 'BOB_TOKEN'].sort());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// OBS-04 (2026-08-02) : correlation-id middleware behavioural coverage.
// ─────────────────────────────────────────────────────────────────────────────

describe('coerceClientRequestId — client-supplied X-Request-Id validation', () => {
  it('accepts a lowercase UUID v4-shaped string', () => {
    expect(coerceClientRequestId('550e8400-e29b-41d4-a716-446655440000')).toBe(
      '550e8400-e29b-41d4-a716-446655440000'
    );
  });

  it('normalises upper/mixed case to lowercase (single-representation invariant)', () => {
    expect(coerceClientRequestId('550E8400-E29B-41D4-A716-446655440000')).toBe(
      '550e8400-e29b-41d4-a716-446655440000'
    );
  });

  it.each([
    ['not a uuid at all', 'obviously-not-a-uuid'],
    ['too short (missing final block)', '550e8400-e29b-41d4-a716'],
    ['too long (extra trailing chars)', '550e8400-e29b-41d4-a716-446655440000-extra'],
    ['non-hex character injected', '550e8400-e29b-41d4-a716-44665544000g'],
    ['leading whitespace', ' 550e8400-e29b-41d4-a716-446655440000'],
    ['trailing whitespace', '550e8400-e29b-41d4-a716-446655440000 '],
    ['empty string', ''],
    ['completely bogus payload', "'; DROP TABLE audit; --"],
  ])('rejects invalid input (%s)', (_label, input) => {
    expect(coerceClientRequestId(input)).toBeUndefined();
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['number', 12345],
    ['boolean', true],
    ['object', { toString: () => '550e8400-e29b-41d4-a716-446655440000' }],
    ['array', ['550e8400-e29b-41d4-a716-446655440000']],
  ])('rejects non-string input (%s)', (_label, input) => {
    expect(coerceClientRequestId(input)).toBeUndefined();
  });
});

/**
 * Behavioural fixture : mount the middleware on a real Express app, expose a
 * probe endpoint that reports what the request handler saw (ambient
 * requestId via ALS, `req.request_id`, and response header echo), and hit it
 * over HTTP. This exercises the exact middleware wiring the production code
 * relies on.
 */
async function startProbeApp(
  generateId?: () => string
): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(createRequestIdMiddleware(generateId ? { generateId } : undefined));
  app.get('/probe', (req, res) => {
    res.json({
      ambient: getRequestId() ?? null,
      onRequest: (req as express.Request & { request_id?: string }).request_id ?? null,
      echoed: res.getHeader('X-Request-Id') ?? null,
    });
  });
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const address = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${address.port}`;
  return {
    url,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

describe('createRequestIdMiddleware — behavioural HTTP coverage', () => {
  let fixture: { url: string; close: () => Promise<void> } | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('mints a fresh UUID when no X-Request-Id header is supplied', async () => {
    fixture = await startProbeApp();
    const resp = await fetch(`${fixture.url}/probe`);
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { ambient: string; onRequest: string; echoed: string };
    // Round-trip consistency : ALS, req field, and response header all
    // carry the exact same value.
    expect(body.ambient).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
    expect(body.onRequest).toBe(body.ambient);
    expect(body.echoed).toBe(body.ambient);
    // Response header case-insensitive check.
    expect(resp.headers.get('x-request-id')).toBe(body.ambient);
  });

  it('adopts a valid client-supplied X-Request-Id verbatim', async () => {
    fixture = await startProbeApp();
    const supplied = '11111111-2222-3333-4444-555555555555';
    const resp = await fetch(`${fixture.url}/probe`, {
      headers: { 'X-Request-Id': supplied },
    });
    const body = (await resp.json()) as { ambient: string; onRequest: string; echoed: string };
    expect(body.ambient).toBe(supplied);
    expect(body.onRequest).toBe(supplied);
    expect(body.echoed).toBe(supplied);
    expect(resp.headers.get('x-request-id')).toBe(supplied);
  });

  it('overrides an invalid client-supplied X-Request-Id with a server-generated UUID', async () => {
    fixture = await startProbeApp(() => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    const resp = await fetch(`${fixture.url}/probe`, {
      headers: { 'X-Request-Id': "'; DROP TABLE audit; --" },
    });
    const body = (await resp.json()) as { ambient: string; onRequest: string; echoed: string };
    expect(body.ambient).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    expect(body.echoed).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    // The malicious payload never surfaces anywhere observable.
    expect(JSON.stringify(body)).not.toContain('DROP TABLE');
  });

  it('assigns two distinct ids to two concurrent requests', async () => {
    fixture = await startProbeApp();
    const [respA, respB] = await Promise.all([
      fetch(`${fixture.url}/probe`),
      fetch(`${fixture.url}/probe`),
    ]);
    const bodyA = (await respA.json()) as { ambient: string };
    const bodyB = (await respB.json()) as { ambient: string };
    expect(bodyA.ambient).not.toBe(bodyB.ambient);
    // Both should look like UUIDs.
    for (const b of [bodyA, bodyB]) {
      expect(b.ambient).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    }
  });

  it('normalises uppercase client-supplied ids to lowercase in the echoed header', async () => {
    fixture = await startProbeApp();
    const supplied = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE';
    const resp = await fetch(`${fixture.url}/probe`, {
      headers: { 'X-Request-Id': supplied },
    });
    expect(resp.headers.get('x-request-id')).toBe(supplied.toLowerCase());
  });

  it('preserves an outer context (e.g. accessToken) when merging requestId', async () => {
    // Simulate a hypothetical outer middleware that already opened an ALS
    // scope with an accessToken before ours ran. The merge must NOT drop
    // pre-existing keys.
    const app = express();
    app.use((req, res, next) => {
      requestContext.run({ accessToken: 'outer-token' }, () => next());
    });
    app.use(createRequestIdMiddleware());
    app.get('/probe', (_req, res) => {
      const store = getRequestTokens();
      res.json({
        accessToken: store?.accessToken ?? null,
        requestId: store?.requestId ?? null,
      });
    });
    const server: Server = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    fixture = {
      url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      close: () => new Promise((resolve) => server.close(() => resolve())),
    };
    const resp = await fetch(`${fixture.url}/probe`);
    const body = (await resp.json()) as { accessToken: string; requestId: string };
    expect(body.accessToken).toBe('outer-token');
    expect(body.requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
  });
});

describe('auditLog — request_id correlation (OBS-04)', () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = '00112233445566778899aabbccddeeff';
    resetAuditSaltCache();
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    resetAuditSaltCache();
  });

  function readEmitted(): Record<string, unknown> {
    const line = (stderrSpy.mock.calls[0]?.[0] as string).trimEnd();
    return JSON.parse(line);
  }

  const sample = {
    tool: 'list-mail-messages',
    method: 'GET',
    path: '/me/messages',
    scopes: ['Mail.Read'],
    account: null as string | null,
    status: 200,
    duration_ms: 12,
  };

  it('omits the request_id field entirely when no correlation is available (backwards compatible)', () => {
    auditLog(sample);
    const parsed = readEmitted();
    expect('request_id' in parsed).toBe(false);
  });

  it('uses an explicit entry.request_id verbatim (call-site override wins)', () => {
    auditLog({ ...sample, request_id: 'explicit-id-from-caller' });
    const parsed = readEmitted();
    expect(parsed.request_id).toBe('explicit-id-from-caller');
  });

  it('falls back to the ambient AsyncLocalStorage requestId when the entry does not carry one', () => {
    requestContext.run({ requestId: 'ambient-id-from-als' }, () => {
      auditLog(sample);
    });
    const parsed = readEmitted();
    expect(parsed.request_id).toBe('ambient-id-from-als');
  });

  it('propagates a middleware-generated id through auditLog for a real HTTP request', async () => {
    const capturedAudit: Record<string, unknown>[] = [];
    // Reroute stderr writes into an array — we assert on structured content.
    stderrSpy.mockImplementation((chunk: string | Uint8Array) => {
      const text = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString();
      for (const line of text.split('\n').filter(Boolean)) {
        try {
          capturedAudit.push(JSON.parse(line));
        } catch {
          /* ignore non-JSON stderr writes */
        }
      }
      return true;
    });

    const app = express();
    app.use(createRequestIdMiddleware());
    app.get('/probe', (_req, res) => {
      auditLog({ ...sample });
      res.json({ ambient: getRequestId() ?? null });
    });
    const server: Server = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as AddressInfo).port;
    try {
      const suppliedId = '99999999-8888-7777-6666-555555555555';
      const resp = await fetch(`http://127.0.0.1:${port}/probe`, {
        headers: { 'X-Request-Id': suppliedId },
      });
      const body = (await resp.json()) as { ambient: string };
      expect(body.ambient).toBe(suppliedId);
      expect(resp.headers.get('x-request-id')).toBe(suppliedId);
      // The audit line emitted inside the handler carries the same id.
      const auditEntry = capturedAudit.find((e) => e.tool === 'list-mail-messages');
      expect(auditEntry).toBeDefined();
      expect(auditEntry?.request_id).toBe(suppliedId);
    } finally {
      await new Promise((resolve) => server.close(() => resolve(undefined)));
    }
  });
});
