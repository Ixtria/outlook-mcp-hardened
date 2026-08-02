/**
 * Hardened OAuth+MCP Express app factory (TEST-01, MAINT-TEST-BEHAV 2026-08-02).
 *
 * Extracted from `src/server.ts` `MicrosoftGraphServer.start()` so the exact
 * production wiring can be exercised in behavioral tests against a real
 * Express listener (see `test/e2e/oauth-routes.test.ts` and
 * `test/helpers/oauth-server-fixture.ts`).
 *
 * The invariant : this module IS the production wiring. `server.ts` only
 * runs boot guards + `createHardenedOAuthApp(...)` + `app.listen(...)`.
 * Any regression that fails here fails production, and vice-versa.
 *
 * All security-sensitive behaviors preserved verbatim :
 *   - N0-B2 bounded pkceStore + interval sweep
 *   - N4-B1 PKCE mandatory, N4-B2 POST /authorize → 405
 *   - N0-I2 Bearer verifier before /mcp
 *   - N0-I3 / N4-I1 fixed issuer URL, never Host header
 *   - N0-I5 / N0-I6 CORS default-deny, wildcard opt-in
 *   - N4-I2 global error handler no stack trace leak
 *   - N4-I3 /.well-known/oauth-protected-resource/mcp variant
 *   - N4-B3 verifier does NOT mutate AuthManager global state
 */

import crypto from 'node:crypto';
import express, {
  type Express,
  type Request,
  type Response,
  type NextFunction,
  type RequestHandler,
} from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Logger } from 'winston';

import type AuthManager from '../auth.js';
import { buildScopesFromEndpoints } from '../auth.js';
import type { AppSecrets } from '../secrets.js';
import { MicrosoftOAuthProvider, verifyMicrosoftAccessToken } from '../oauth-provider.js';
import {
  createBearerAuthMiddleware,
  exchangeCodeForToken as defaultExchangeCode,
  refreshAccessToken as defaultRefreshToken,
  type TokenVerifier,
} from '../lib/microsoft-auth.js';
import { resolveClientIp } from '../lib/trust-proxy.js';
import { allRegisteredRedirectUris, allRegisteredScopes } from './registered-clients.js';
import {
  createAuthorizeHandler,
  createRegisterHandler,
  createRejectPostAuthorizeHandler,
  type PkceStoreEntry,
} from './http-routes.js';
import { requestContext } from '../request-context.js';
import { validateAuditSaltFile } from '../security/audit-logger.js';
import { isEgressGuardActive } from '../security/egress-guard.js';
import { version } from '../version.js';

const MAX_PKCE_STORE_SIZE_DEFAULT = 10_000;
const MAX_STATE_LENGTH_DEFAULT = 256;
const PKCE_SWEEP_INTERVAL_MS_DEFAULT = 60_000;
const PKCE_ENTRY_TTL_MS_DEFAULT = 10 * 60 * 1000;

/**
 * Options that shape the hardened OAuth app. Every collaborator that was
 * previously read from `process.env` or `this` inside `start()` is now an
 * explicit dep. Defaults mirror server.ts constants so behavior is unchanged.
 */
export interface HardenedOAuthAppDeps {
  secrets: AppSecrets;
  authManager: AuthManager;
  /** Factory invoked per /mcp request to build a fresh McpServer. */
  createMcpServer: () => McpServer;
  /** CLI-shaped options subset that matters to HTTP wiring. */
  options: {
    orgMode?: boolean;
    enabledTools?: string;
    enableSend?: boolean;
    enableWrite?: boolean;
    enableDynamicRegistration?: boolean;
    baseUrl?: string;
  };
  /** Bound host — used to build the fixed issuer URL (no Host reflection). */
  host: string;
  /** Bound port — same as above. */
  port: number;
  /** Explicit public URL (OUTLOOK_MCP_PUBLIC_URL). Optional in loopback mode. */
  publicUrl?: string;
  /** Trusted reverse-proxy IPs (OUTLOOK_MCP_TRUSTED_PROXIES). */
  trustedProxies: ReadonlySet<string>;
  /** CORS origin (OUTLOOK_MCP_CORS_ORIGIN). Default-deny when absent. */
  corsOrigin?: string;
  /** Winston-like logger. */
  logger: Logger;
  /**
   * OBS-04 (2026-08-02) : correlation-ID middleware. Mounted FIRST in the
   * chain (before trust-proxy client-ip resolution, body parsers, and any
   * route handler) so every subsequent layer — including handlers that
   * respond without calling `next()` — runs inside the AsyncLocalStorage
   * scope that carries `requestId`. Server.ts injects the real factory
   * (`createRequestIdMiddleware()`); tests may inject a stub or omit
   * entirely.
   */
  requestIdMiddleware?: RequestHandler;

  // ────────────────────── Test injection points ─────────────────────────
  /** Override the Graph verifier — tests inject a synchronous stub. */
  tokenVerifier?: TokenVerifier;
  /** Override the AAD code exchange. */
  exchangeCode?: typeof defaultExchangeCode;
  /** Override the AAD refresh call. */
  refreshToken?: typeof defaultRefreshToken;
  /** Skip mounting the SDK mcpAuthRouter (unit tests that don't need it). */
  disableSdkAuthRouter?: boolean;
  /** Skip mounting the /mcp handlers (tests that only exercise OAuth). */
  disableMcpRoutes?: boolean;
  /** Deterministic clock for tests. */
  now?: () => number;
  /** Override PKCE store bound. */
  maxPkceStoreSize?: number;
  /** Override state length bound. */
  maxStateLength?: number;
  /** Override PKCE sweep interval. */
  pkceSweepIntervalMs?: number;
  /** Override PKCE entry TTL. */
  pkceEntryTtlMs?: number;
  /** Skip installing the sweep interval (tests never want an unref'd timer). */
  disablePkceSweep?: boolean;
}

export interface HardenedOAuthApp {
  app: Express;
  pkceStore: Map<string, PkceStoreEntry>;
  /** Clears the interval + any other resources. Safe to call multiple times. */
  dispose: () => void;
}

/**
 * Build the fully-wired Express app for HTTP mode.
 *
 * The caller is responsible for :
 *   - Running boot guards (env var invariants) BEFORE calling this.
 *   - Calling `.listen()` on the returned app.
 *   - Calling `dispose()` on shutdown.
 */
export function createHardenedOAuthApp(deps: HardenedOAuthAppDeps): HardenedOAuthApp {
  const {
    secrets,
    authManager,
    createMcpServer,
    options,
    host,
    port,
    publicUrl,
    trustedProxies,
    corsOrigin,
    logger,
    requestIdMiddleware,
    tokenVerifier,
    exchangeCode = defaultExchangeCode,
    refreshToken: refreshTokenFn = defaultRefreshToken,
    disableSdkAuthRouter = false,
    disableMcpRoutes = false,
    now = Date.now,
    maxPkceStoreSize = MAX_PKCE_STORE_SIZE_DEFAULT,
    maxStateLength = MAX_STATE_LENGTH_DEFAULT,
    pkceSweepIntervalMs = PKCE_SWEEP_INTERVAL_MS_DEFAULT,
    pkceEntryTtlMs = PKCE_ENTRY_TTL_MS_DEFAULT,
    disablePkceSweep = false,
  } = deps;

  const pkceStore = new Map<string, PkceStoreEntry>();

  // Interval-driven sweep (N0 B2). Skippable in tests to avoid dangling timers.
  let sweepHandle: ReturnType<typeof setInterval> | null = null;
  if (!disablePkceSweep) {
    sweepHandle = setInterval(() => {
      const t = now();
      let evicted = 0;
      for (const [key, value] of pkceStore) {
        if (t - value.createdAt > pkceEntryTtlMs) {
          pkceStore.delete(key);
          evicted++;
        }
      }
      if (evicted > 0) {
        logger.info(`pkceStore: swept ${evicted} expired entries`);
      }
    }, pkceSweepIntervalMs);
    sweepHandle.unref?.();
  }

  const app = express();

  // OBS-04 (2026-08-02) : correlation-id middleware MUST be first — it
  // enters an AsyncLocalStorage scope that every downstream layer
  // (auditLog, winston formats, OAuth handlers, /mcp) reads via
  // getRequestId(). Mounting later would miss any route that short-circuits
  // with `res.json(...)` without calling `next()`.
  if (requestIdMiddleware) {
    app.use(requestIdMiddleware);
  }

  // trust proxy (ADR-0003 D6)
  if (trustedProxies.size > 0) {
    app.set('trust proxy', [...trustedProxies]);
  } else {
    app.set('trust proxy', false);
  }

  app.use((req, _res, next) => {
    const socketIp = req.socket.remoteAddress ?? '';
    const xff = req.headers['x-forwarded-for'];
    const xffString = Array.isArray(xff) ? xff.join(', ') : xff;
    const clientIp = resolveClientIp(socketIp, xffString, trustedProxies);
    (req as Request & { clientIp?: string }).clientIp = clientIp;
    next();
  });

  // Body parsers (N0 B3 BLOCKER — 10 KB cap, safe querystring parser).
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false, limit: '10kb', parameterLimit: 20 }));

  // CORS (N0 I5 + I6). Boot-time guard on wildcard is caller's job.
  app.use((req, res, next) => {
    const requestOrigin = req.headers.origin;
    let allowOrigin: string | null = null;

    if (corsOrigin === '*') {
      allowOrigin = '*';
    } else if (corsOrigin && requestOrigin === corsOrigin) {
      allowOrigin = requestOrigin;
    }

    if (allowOrigin) {
      res.header('Access-Control-Allow-Origin', allowOrigin);
      if (allowOrigin !== '*') {
        res.header('Vary', 'Origin');
      }
    }
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    const allowHeaders =
      allowOrigin === '*'
        ? 'Origin, X-Requested-With, Content-Type, Accept, mcp-protocol-version'
        : 'Origin, X-Requested-With, Content-Type, Accept, Authorization, mcp-protocol-version';
    res.header('Access-Control-Allow-Headers', allowHeaders);

    if (req.method === 'OPTIONS') {
      res.sendStatus(allowOrigin ? 200 : 403);
      return;
    }

    next();
  });

  const httpWritePolicy = {
    mail: !!options.enableSend,
    calendar: !!options.enableWrite,
  };

  const allowedRedirectUris = allRegisteredRedirectUris();
  const registeredScopesString = [...allRegisteredScopes()].join(' ');

  const oauthProvider = new MicrosoftOAuthProvider(authManager, secrets);

  // Bearer middleware. Uses injected verifier in tests, real Graph /me otherwise.
  const effectiveVerifier: TokenVerifier =
    tokenVerifier ??
    (async (token) => {
      await verifyMicrosoftAccessToken(token, secrets.cloudType, secrets.clientId, authManager);
    });
  const bearerAuthMiddleware = createBearerAuthMiddleware(effectiveVerifier);

  // Fixed issuer URL (N4-I1) — never derived from req.get('host').
  const issuerUrl = publicUrl
    ? new URL(publicUrl)
    : new URL(`http://${host || '127.0.0.1'}:${port}`);

  // ─── /.well-known/oauth-authorization-server ───────────────────────────
  app.get('/.well-known/oauth-authorization-server', async (_req, res) => {
    res.set('Cache-Control', 'no-store');
    const scopes = buildScopesFromEndpoints(options.orgMode, options.enabledTools);
    const metadata: Record<string, unknown> = {
      issuer: issuerUrl.origin,
      authorization_endpoint: `${issuerUrl.origin}/authorize`,
      token_endpoint: `${issuerUrl.origin}/token`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: scopes,
    };
    if (options.enableDynamicRegistration) {
      metadata.registration_endpoint = `${issuerUrl.origin}/register`;
    }
    res.json(metadata);
  });

  // ─── /.well-known/oauth-protected-resource[/mcp] (N4-I3) ────────────────
  app.get(
    ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'],
    async (_req, res) => {
      res.set('Cache-Control', 'no-store');
      const scopes = buildScopesFromEndpoints(options.orgMode, options.enabledTools);
      res.json({
        resource: `${issuerUrl.origin}/mcp`,
        authorization_servers: [issuerUrl.origin],
        scopes_supported: scopes,
        bearer_methods_supported: ['header'],
        resource_documentation: `${issuerUrl.origin}`,
      });
    }
  );

  // ─── POST /register (DCR, opt-in) ───────────────────────────────────────
  if (options.enableDynamicRegistration) {
    app.post('/register', createRegisterHandler({ allowedRedirectUris, logger }));
  }

  // ─── /authorize (N4-B1 / N4-B2 / N0-B1 / N0-B2) ─────────────────────────
  app.post('/authorize', createRejectPostAuthorizeHandler({ logger }));
  app.get(
    '/authorize',
    createAuthorizeHandler({
      allowedRedirectUris,
      registeredScopesString,
      knownScopes: () =>
        new Set(
          buildScopesFromEndpoints(options.orgMode, options.enabledTools, httpWritePolicy)
        ),
      logger,
      secrets,
      pkceStore,
      maxPkceStoreSize,
      maxStateLength,
      now,
    })
  );

  // ─── POST /token ────────────────────────────────────────────────────────
  app.post('/token', async (req, res) => {
    try {
      logger.info('Token endpoint called', {
        method: req.method,
        url: req.url,
        contentType: req.get('Content-Type'),
        grant_type: req.body?.grant_type,
      });

      const body = req.body;

      if (!body) {
        logger.error('Token endpoint: Request body is undefined');
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Request body is required',
        });
        return;
      }

      if (!body.grant_type) {
        logger.error('Token endpoint: grant_type is missing', { body });
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'grant_type parameter is required',
        });
        return;
      }

      if (body.grant_type === 'authorization_code') {
        const tenantId = secrets.tenantId || 'common';
        const clientId = secrets.clientId;
        const clientSecret = secrets.clientSecret;

        logger.info('Token endpoint: authorization_code exchange', {
          redirect_uri: body.redirect_uri,
          has_code: !!body.code,
          has_code_verifier: !!body.code_verifier,
          clientId,
          tenantId,
          hasClientSecret: !!clientSecret,
        });

        let serverCodeVerifier: string | undefined;
        if (body.code_verifier) {
          const clientVerifier = body.code_verifier as string;
          const clientChallengeComputed = crypto
            .createHash('sha256')
            .update(clientVerifier)
            .digest('base64url');

          for (const [state, pkceData] of pkceStore) {
            if (pkceData.clientCodeChallenge === clientChallengeComputed) {
              serverCodeVerifier = pkceData.serverCodeVerifier;
              pkceStore.delete(state);
              logger.info('Two-leg PKCE: matched client verifier, using server verifier', {
                state: state.substring(0, 8) + '...',
              });
              break;
            }
          }
        }

        const result = await exchangeCode(
          body.code as string,
          body.redirect_uri as string,
          clientId,
          clientSecret,
          tenantId,
          serverCodeVerifier || (body.code_verifier as string | undefined),
          secrets.cloudType
        );
        res.json(result);
      } else if (body.grant_type === 'refresh_token') {
        const tenantId = secrets.tenantId || 'common';
        const clientId = secrets.clientId;
        const clientSecret = secrets.clientSecret;

        if (clientSecret) {
          logger.info('Refresh endpoint: Using confidential client with client_secret');
        } else {
          logger.info('Refresh endpoint: Using public client without client_secret');
        }

        const result = await refreshTokenFn(
          body.refresh_token as string,
          clientId,
          clientSecret,
          tenantId,
          secrets.cloudType
        );
        res.json(result);
      } else {
        res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: `Grant type '${body.grant_type}' is not supported`,
        });
      }
    } catch (error) {
      logger.error('Token endpoint error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error during token exchange',
      });
    }
  });

  // ─── SDK mcpAuthRouter (fallback for paths we don't hand-roll) ──────────
  if (!disableSdkAuthRouter) {
    app.use(
      mcpAuthRouter({
        provider: oauthProvider,
        issuerUrl: new URL(
          options.baseUrl || process.env.MS365_MCP_BASE_URL || `http://localhost:${port}`
        ),
      })
    );
  }

  // ─── /mcp (Bearer-protected MCP transport) ──────────────────────────────
  if (!disableMcpRoutes) {
    const mcpHandler = (verb: 'get' | 'post') =>
      async (
        req: Request & { microsoftAuth?: { accessToken: string; refreshToken: string } },
        res: Response
      ): Promise<void> => {
        const handler = async (): Promise<void> => {
          const server = createMcpServer();
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
          });
          res.on('close', () => {
            transport.close();
            server.close();
          });
          await server.connect(transport);
          await transport.handleRequest(
            req as unknown as Parameters<typeof transport.handleRequest>[0],
            res as unknown as Parameters<typeof transport.handleRequest>[1],
            verb === 'post' ? req.body : undefined
          );
        };

        try {
          if (req.microsoftAuth) {
            await requestContext.run(
              {
                accessToken: req.microsoftAuth.accessToken,
                refreshToken: req.microsoftAuth.refreshToken,
              },
              handler
            );
          } else {
            await handler();
          }
        } catch (error) {
          logger.error(`Error handling MCP ${verb.toUpperCase()} request:`, error);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: null,
            });
          }
        }
      };

    app.get('/mcp', bearerAuthMiddleware, mcpHandler('get'));
    app.post('/mcp', bearerAuthMiddleware, mcpHandler('post'));
  }

  // ─── health / liveness / readiness (OBS-06 + OBS-08, 2026-08-02) ────────
  app.get('/', (_req, res) => {
    res.send('Microsoft 365 MCP Server is running');
  });

  // OBS-08 : k8s-style liveness vs readiness split.
  //   /live  — the process is alive and the event loop is answering HTTP.
  //            Always 200 here ; a deadlocked process wouldn't run this
  //            handler at all, so there is no failure branch to encode.
  //            An orchestrator uses this to decide "restart the container".
  //   /ready — the service is ready to receive traffic : all three security
  //            components declare themselves initialized. An orchestrator
  //            uses this to decide "route traffic here" (no restart implied
  //            by a 503 — it just stops sending new requests).
  //   /health — OBS-06 original endpoint, kept as a backward-compatible
  //            alias of /ready (same shape, same status code semantics).
  app.get('/live', (_req, res) => {
    res.status(200).json({
      status: 'ok',
      version,
      uptime_s: process.uptime(),
      node_version: process.version,
    });
  });

  const readinessHandler = (_req: Request, res: Response): void => {
    // audit_logger_ready : reuse the RUNTIME-SEC-01 boot-time posture check
    // (permissions, ownership, symlink, non-empty). A throw here means the
    // audit trail cannot be trusted — the service is not ready.
    let auditLoggerReady = true;
    try {
      validateAuditSaltFile();
    } catch {
      auditLoggerReady = false;
    }

    // egress_guard_active : real check on the live `globalThis.fetch`
    // binding — true only when installEgressGuard() has patched it.
    const egressGuardActive = isEgressGuardActive();

    // mcp_server_ready : the /mcp routes were mounted on this app instance.
    const mcpServerReady = !disableMcpRoutes;

    const ready = mcpServerReady && egressGuardActive && auditLoggerReady;
    res.status(ready ? 200 : 503).json({
      status: ready ? 'ok' : 'error',
      version,
      uptime_s: process.uptime(),
      node_version: process.version,
      mcp_server_ready: mcpServerReady,
      egress_guard_active: egressGuardActive,
      audit_logger_ready: auditLoggerReady,
    });
  };

  app.get('/ready', readinessHandler);
  app.get('/health', readinessHandler);

  // ─── global error handler (N4-I2) ───────────────────────────────────────
  app.use(
    (
      err: Error & { status?: number; statusCode?: number },
      req: Request,
      res: Response,
      _next: NextFunction
    ) => {
      const status = err.status ?? err.statusCode ?? 500;
      logger.warn('Express error caught by global handler', {
        status,
        message: err.message,
        client_ip: (req as Request & { clientIp?: string }).clientIp,
      });
      if (!res.headersSent) {
        res.status(status).json({
          error: status >= 500 ? 'server_error' : 'request_error',
          error_description:
            status >= 500
              ? 'Internal server error'
              : err.message?.slice(0, 200) || 'Bad request',
        });
      }
    }
  );

  return {
    app,
    pkceStore,
    dispose: () => {
      if (sweepHandle) {
        clearInterval(sweepHandle);
        sweepHandle = null;
      }
    },
  };
}

/**
 * Placate unused-import lints when a caller passes a custom handler:
 * exposes the constructor so tests can spin a real one alongside the fixture.
 */
export type { RequestHandler };
