/**
 * Extracted HTTP route handlers for the OAuth proxy.
 *
 * Why extracted (cf. N0-O3 cross-review observation 2026-05-10):
 *   The wiring path in src/server.ts was at 0% coverage. Pure modules
 *   (`redirect-uri`, `scope`, `trust-proxy`, `registered-clients`) were
 *   unit-tested at 100%, but the integration — how those modules compose
 *   in real Express handlers, with real request shapes — was untested.
 *   That meant a future refactor of server.ts could silently break the
 *   security contract without any failing test.
 *
 * This module exports factory functions that build Express RequestHandlers
 * from explicit dependencies. The dependencies are injected (not closed-over
 * via class instance) so tests can pass mocks deterministically.
 *
 * server.ts wires these into the real Express app with real deps; tests
 * wire them into a mini Express app with controlled deps and assert behavior.
 */

import crypto from 'node:crypto';
import type { Request, Response, RequestHandler } from 'express';
import { validateRedirectUri } from './redirect-uri.js';
import { intersectScopes, parseScope, serializeScope } from './scope.js';
import { allRegisteredScopes, META_SCOPES } from './registered-clients.js';
import { getCloudEndpoints, type CloudType } from '../cloud-config.js';
import { auditLog } from '../security/audit-logger.js';

export interface RegisterHandlerDeps {
  /** Static allowlist of acceptable redirect_uris (e.g. Claude.ai callbacks). */
  allowedRedirectUris: ReadonlySet<string>;
  /** Logger with .info() / .warn() — pass a mock in tests. */
  logger: { info: (msg: string, meta?: unknown) => void; warn: (msg: string, meta?: unknown) => void };
  /** Optional clock for deterministic client_id in tests. Defaults to Date.now. */
  now?: () => number;
}

export function createRegisterHandler(deps: RegisterHandlerDeps): RequestHandler {
  const { allowedRedirectUris, logger, now = Date.now } = deps;
  return (req: Request, res: Response) => {
    // OBS-02 (2026-08-02) : capture handler wall time so operators can spot
    // slow /register calls in the audit stream. Started at handler entry so
    // both success and reject paths report a comparable duration.
    const started = now();
    const body = (req.body ?? {}) as Record<string, unknown>;
    const requested: unknown = body.redirect_uris;
    if (!Array.isArray(requested) || requested.length === 0) {
      res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: 'redirect_uris is required and must be a non-empty array',
      });
      // OBS-02 : audit the reject. `scopes=[]` because /register has no
      // scope context ; `account=null` because no identity has been
      // established yet. `redirect_uris` values are DELIBERATELY not
      // propagated into the audit event — the emission-site contract in
      // docs/AUDIT_EVENTS.md forbids it.
      auditLog({
        tool: 'oauth.client.register',
        method: 'POST',
        path: '/register',
        scopes: [],
        account: null,
        status: 400,
        duration_ms: now() - started,
      });
      return;
    }
    const invalid = requested.filter(
      (u) => typeof u !== 'string' || !validateRedirectUri(u, allowedRedirectUris)
    );
    if (invalid.length > 0) {
      logger.warn('Rejected /register: redirect_uri not in allowlist', {
        invalid_count: invalid.length,
        client_name: body.client_name,
      });
      res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description:
          'one or more redirect_uris are not in the registered-clients allowlist',
      });
      auditLog({
        tool: 'oauth.client.register',
        method: 'POST',
        path: '/register',
        scopes: [],
        account: null,
        status: 400,
        duration_ms: now() - started,
      });
      return;
    }

    const clientId = `mcp-client-${now()}`;
    logger.info('Client registration accepted', {
      client_id: clientId,
      client_name: body.client_name,
      redirect_uris_count: requested.length,
    });

    res.status(201).json({
      client_id: clientId,
      client_id_issued_at: Math.floor(now() / 1000),
      redirect_uris: requested,
      grant_types: body.grant_types ?? ['authorization_code', 'refresh_token'],
      response_types: body.response_types ?? ['code'],
      token_endpoint_auth_method: body.token_endpoint_auth_method ?? 'none',
      client_name: body.client_name ?? 'MCP Client',
    });
    auditLog({
      tool: 'oauth.client.register',
      method: 'POST',
      path: '/register',
      scopes: [],
      account: null,
      status: 201,
      duration_ms: now() - started,
    });
  };
}

export interface AuthorizeScopeDeps {
  /** Static allowlist of acceptable redirect_uris. */
  allowedRedirectUris: ReadonlySet<string>;
  /** Space-separated string of all scopes any registered client may ever request. */
  registeredScopesString: string;
  /** Closure returning the writePolicy-aware set of known Graph scopes. */
  knownScopes: () => Set<string>;
  /** Logger. */
  logger: { info: (msg: string, meta?: unknown) => void; warn: (msg: string, meta?: unknown) => void };
}

export interface AuthorizeScopeResult {
  /** Effective scope string to forward to AAD, or null if the intersection is empty. */
  effective: string | null;
  /** Underlying Set for tests/audit. */
  set: Set<string>;
}

/**
 * Compute the effective scope to forward to AAD given a requested scope param.
 * Pure function — extracted from /authorize handler so it can be tested in
 * isolation without an HTTP roundtrip.
 *
 * Rule (cf. SPECS-OAUTH-MCP.md §6 step 6 + ADR-0003 D2 + N0 cross-review B1/I2):
 *   1. effective = requested ∩ registered ∩ KNOWN  (Graph permissions path)
 *   2. for each scope in META_SCOPES:
 *        if it's in the requested set AND in registered → add to effective
 *      (bypasses KNOWN because META_SCOPES are OIDC/refresh protocol scopes,
 *       not Graph permissions, and would otherwise be dropped because
 *       endpoints.json doesn't declare them)
 */
export function computeEffectiveScope(
  requestedScope: string | undefined,
  deps: AuthorizeScopeDeps
): AuthorizeScopeResult {
  const knownSet = deps.knownScopes();
  const effective = intersectScopes(requestedScope, deps.registeredScopesString, knownSet);

  const requestedTokens = parseScope(requestedScope);
  // If no scope requested, fall back to "any registered scope" for the META
  // pass — same convention as intersectScopes() RFC 6749 §3.3 fallback.
  const requestedFallback =
    requestedTokens.size === 0 ? allRegisteredScopes() : requestedTokens;
  for (const meta of META_SCOPES) {
    if (requestedFallback.has(meta) && allRegisteredScopes().has(meta)) {
      effective.add(meta);
    }
  }

  return {
    set: effective,
    effective: effective.size > 0 ? serializeScope(effective) : null,
  };
}

export interface ValidateRedirectResult {
  ok: boolean;
  /** Why it failed (only set when ok=false). */
  reason?: 'missing' | 'not_in_allowlist';
}

/**
 * Validate the `redirect_uri` query param of an /authorize call.
 * Returns a structured result so the handler can render local errors with
 * appropriate messages (cf. codex I2 — no Location header before validation).
 */
export function validateAuthorizeRedirectUri(
  redirectUri: string | null,
  allowed: ReadonlySet<string>
): ValidateRedirectResult {
  if (!redirectUri) return { ok: false, reason: 'missing' };
  if (!validateRedirectUri(redirectUri, allowed)) {
    return { ok: false, reason: 'not_in_allowlist' };
  }
  return { ok: true };
}

/**
 * Two-leg PKCE store entry (server↔client challenge + server↔AAD verifier).
 * Extracted from server.ts alongside createAuthorizeHandler so the handler
 * can be tested through Express in isolation (MAINT-TEST-BEHAV / TEST-01).
 */
export interface PkceStoreEntry {
  clientCodeChallenge: string;
  clientCodeChallengeMethod: string;
  serverCodeVerifier: string;
  createdAt: number;
}

export interface RejectPostAuthorizeDeps {
  logger: {
    info: (msg: string, meta?: unknown) => void;
    warn: (msg: string, meta?: unknown) => void;
  };
}

/**
 * HARDENED (N4 B2 BLOCKER fix 2026-06-02): factored 405 interceptor for
 * POST /authorize. OAuth 2.0 RFC 6749 §3.1 says the authorization endpoint
 * MUST support GET; POST is optional. We support only GET and reject POST
 * with 405 because the SDK's mcpAuthRouter would otherwise catch POST
 * /authorize and bypass our hand-rolled PKCE + scope + client_id checks.
 *
 * Extracted from src/server.ts inline handler (MAINT-TEST-BEHAV, 2026-08-02)
 * so the interception can be exercised via a supertest-style behavioral test.
 */
export function createRejectPostAuthorizeHandler(
  deps: RejectPostAuthorizeDeps
): RequestHandler {
  const { logger } = deps;
  return (req: Request, res: Response) => {
    logger.warn('Rejected POST /authorize (only GET is supported)', {
      client_ip: (req as Request & { clientIp?: string }).clientIp,
    });
    res
      .status(405)
      .set('Allow', 'GET')
      .type('text/plain')
      .send(
        'method_not_allowed: /authorize accepts GET only. POST bypasses required PKCE+scope validation.'
      );
    // OBS-02 : 405 rejections are worth auditing — a client hammering POST
    // /authorize is either a misconfigured integration or an adversary
    // probing for the SDK bypass path that N4-B2 closed.
    auditLog({
      tool: 'oauth.authorize.reject',
      method: 'POST',
      path: '/authorize',
      scopes: [],
      account: null,
      status: 405,
      duration_ms: 0,
    });
  };
}

export interface AuthorizeHandlerDeps {
  /** Static allowlist of acceptable redirect_uris. */
  allowedRedirectUris: ReadonlySet<string>;
  /** Space-separated string of all scopes any registered client may ever request. */
  registeredScopesString: string;
  /** Closure returning the writePolicy-aware set of known Graph scopes. */
  knownScopes: () => Set<string>;
  /** Logger. */
  logger: {
    info: (msg: string, meta?: unknown) => void;
    warn: (msg: string, meta?: unknown) => void;
  };
  /** Microsoft client identity + cloud used to build the AAD authorization URL. */
  secrets: { clientId: string; tenantId?: string; cloudType: CloudType };
  /** Shared two-leg PKCE store keyed by OAuth `state`. Must persist across the
   *  matching /token exchange (server.ts owns the singleton). */
  pkceStore: Map<string, PkceStoreEntry>;
  /** Bounded store size (default 10_000). */
  maxPkceStoreSize?: number;
  /** Max `state` param length (default 256). */
  maxStateLength?: number;
  /** Injectable clock — deterministic tests. Defaults to Date.now. */
  now?: () => number;
  /** Injectable server-side PKCE verifier generator. Defaults to crypto.randomBytes. */
  generateServerCodeVerifier?: () => string;
}

/**
 * HARDENED (ADR-0003 D2): /authorize handler extracted from src/server.ts
 * (MAINT-TEST-BEHAV, 2026-08-02). All security invariants preserved verbatim:
 *
 *   - N4 B1 : PKCE mandatory (code_challenge required)
 *   - N0 B1 : method must be S256 (no plain downgrade)
 *   - N0 B2 : `state` bounded to MAX_STATE_LENGTH; pkceStore bounded LRU
 *   - N0 I3 / N4-I1 : no Host header reflection — AAD URL is derived from
 *     secrets.cloudType/tenantId, not from req.get('host')
 *   - codex I2 : errors are LOCAL (no Location header) before redirect_uri
 *     is validated
 *   - N1-I2 : no scope fallback; empty intersection → 400 invalid_scope
 *
 * This is the SAME code that ran inline in server.ts before extraction — the
 * only change is that dependencies are injected instead of closed over via
 * `this`. Server.ts wires it with real deps; tests wire it with mocks.
 */
export function createAuthorizeHandler(deps: AuthorizeHandlerDeps): RequestHandler {
  const {
    allowedRedirectUris,
    registeredScopesString,
    knownScopes,
    logger,
    secrets,
    pkceStore,
    maxPkceStoreSize = 10_000,
    maxStateLength = 256,
    now = Date.now,
    generateServerCodeVerifier = () => crypto.randomBytes(32).toString('base64url'),
  } = deps;

  // OBS-02 : shared audit-emitter for reject paths — factored so all six
  // reject branches emit identical field shapes. `scopes` deliberately stays
  // `[]` because reject events fire before the effective-scope intersection
  // runs (or, for the empty-scope case, when the intersection is provably
  // empty and there is nothing meaningful to advertise).
  const auditReject = (status: number, durationMs: number): void => {
    auditLog({
      tool: 'oauth.authorize.reject',
      method: 'GET',
      path: '/authorize',
      scopes: [],
      account: null,
      status,
      duration_ms: durationMs,
    });
  };

  return (req: Request, res: Response) => {
    const started = now();
    const url = new URL(req.url, `${req.protocol}://${req.get('host') ?? 'localhost'}`);
    const tenantId = secrets.tenantId || 'common';
    const clientId = secrets.clientId;
    const cloudEndpoints = getCloudEndpoints(secrets.cloudType);
    const microsoftAuthUrl = new URL(
      `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/authorize`
    );

    // Validate redirect_uri BEFORE producing any Location header (codex I2).
    const redirectCheck = validateAuthorizeRedirectUri(
      url.searchParams.get('redirect_uri'),
      allowedRedirectUris
    );
    if (!redirectCheck.ok) {
      if (redirectCheck.reason === 'not_in_allowlist') {
        logger.warn('Rejected /authorize: redirect_uri not in allowlist', {
          client_ip: (req as Request & { clientIp?: string }).clientIp,
        });
      }
      res
        .status(400)
        .type('text/plain')
        .send(
          redirectCheck.reason === 'missing'
            ? 'invalid_request: redirect_uri is required'
            : 'invalid_request: redirect_uri is not in the registered-clients allowlist'
        );
      auditReject(400, now() - started);
      return;
    }

    const clientCodeChallenge = url.searchParams.get('code_challenge');
    const clientCodeChallengeMethod = url.searchParams.get('code_challenge_method');
    const state = url.searchParams.get('state');

    if (clientCodeChallengeMethod && clientCodeChallengeMethod !== 'S256') {
      logger.warn('Rejected /authorize: PKCE method not S256', {
        method: clientCodeChallengeMethod,
        client_ip: (req as Request & { clientIp?: string }).clientIp,
      });
      res
        .status(400)
        .type('text/plain')
        .send('invalid_request: code_challenge_method must be S256');
      auditReject(400, now() - started);
      return;
    }

    if (state && state.length > maxStateLength) {
      logger.warn('Rejected /authorize: state too long', {
        length: state.length,
        client_ip: (req as Request & { clientIp?: string }).clientIp,
      });
      res
        .status(400)
        .type('text/plain')
        .send('invalid_request: state parameter exceeds maximum length');
      auditReject(400, now() - started);
      return;
    }

    if (!clientCodeChallenge) {
      logger.warn('Rejected /authorize: missing code_challenge (PKCE mandatory)', {
        client_ip: (req as Request & { clientIp?: string }).clientIp,
      });
      res
        .status(400)
        .type('text/plain')
        .send('invalid_request: code_challenge is required (PKCE mandatory)');
      auditReject(400, now() - started);
      return;
    }

    const allowedParams = [
      'response_type',
      'redirect_uri',
      'state',
      'response_mode',
      'prompt',
      'login_hint',
      'domain_hint',
    ];
    allowedParams.forEach((param) => {
      const value = url.searchParams.get(param);
      if (value) {
        microsoftAuthUrl.searchParams.set(param, value);
      }
    });

    const requestedScope = url.searchParams.get('scope') ?? undefined;
    const scopeResult = computeEffectiveScope(requestedScope, {
      allowedRedirectUris,
      registeredScopesString,
      knownScopes,
      logger,
    });
    if (scopeResult.effective !== null) {
      microsoftAuthUrl.searchParams.set('scope', scopeResult.effective);
    } else {
      logger.warn('Rejected /authorize: empty scope intersection', {
        requested: requestedScope,
        client_ip: (req as Request & { clientIp?: string }).clientIp,
      });
      res
        .status(400)
        .type('text/plain')
        .send('invalid_scope: no requested scope is in the registered/known allowlist');
      auditReject(400, now() - started);
      return;
    }

    if (clientCodeChallenge && state) {
      const serverCodeVerifier = generateServerCodeVerifier();
      const serverCodeChallenge = crypto
        .createHash('sha256')
        .update(serverCodeVerifier)
        .digest('base64url');

      if (pkceStore.size >= maxPkceStoreSize) {
        const oldestKey = pkceStore.keys().next().value;
        if (oldestKey !== undefined) {
          pkceStore.delete(oldestKey);
          logger.warn('pkceStore at capacity — evicted oldest entry', {
            size: maxPkceStoreSize,
          });
        }
      }

      pkceStore.set(state, {
        clientCodeChallenge,
        clientCodeChallengeMethod: clientCodeChallengeMethod || 'S256',
        serverCodeVerifier,
        createdAt: now(),
      });

      microsoftAuthUrl.searchParams.set('code_challenge', serverCodeChallenge);
      microsoftAuthUrl.searchParams.set('code_challenge_method', 'S256');

      logger.info('Two-leg PKCE: stored client challenge, generated server challenge', {
        state: state.substring(0, 8) + '...',
      });
    } else if (clientCodeChallenge) {
      microsoftAuthUrl.searchParams.set('code_challenge', clientCodeChallenge);
      microsoftAuthUrl.searchParams.set('code_challenge_method', 'S256');
    }

    microsoftAuthUrl.searchParams.set('client_id', clientId);

    res.redirect(microsoftAuthUrl.toString());
    // OBS-02 : audit the successful redirect. `scopes` reflects the effective
    // intersection that was actually forwarded to AAD — that is the
    // operator's ground truth for "what did this client just get authorized
    // for". `account` stays null because we only learn the identity later,
    // during the /token exchange + /mcp Bearer verify.
    auditLog({
      tool: 'oauth.authorize.request',
      method: 'GET',
      path: '/authorize',
      scopes: [...scopeResult.set],
      account: null,
      status: 302,
      duration_ms: now() - started,
    });
  };
}
