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

import type { Request, Response, RequestHandler } from 'express';
import { validateRedirectUri } from './redirect-uri.js';
import { intersectScopes, parseScope, serializeScope } from './scope.js';
import { allRegisteredScopes, META_SCOPES } from './registered-clients.js';

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
    const body = (req.body ?? {}) as Record<string, unknown>;
    const requested: unknown = body.redirect_uris;
    if (!Array.isArray(requested) || requested.length === 0) {
      res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: 'redirect_uris is required and must be a non-empty array',
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
