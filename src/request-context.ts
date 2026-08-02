import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

// HARDENED (N0-I4 fix 2026-05-16): canonicalization + validation of trusted
// proxy IPs moved to src/lib/trust-proxy.ts to colocate with normalizeIp
// (same canonical form is required on both sides of the equality check).
export { parseTrustedProxiesEnv } from './lib/trust-proxy.js';

/**
 * Per-request context propagated through Node async boundaries via
 * AsyncLocalStorage. Populated by the HTTP entry middleware before any tool
 * handler runs.
 *
 * Extended per ADR-0003 (Niveau B, 2026-05-10) to carry `clientIp`, the result
 * of `resolveClientIp()` applied with the operator-configured
 * `OUTLOOK_MCP_TRUSTED_PROXIES` set. Replaces the legacy `app.set('trust proxy',
 * true)` global behaviour that codex N1-B1 (conf 96) flagged as a header-spoof
 * vector.
 *
 * Extended for OBS-04 (2026-08-02) with `requestId` : a UUID minted (or
 * echoed from the client's X-Request-Id header) by
 * `createRequestIdMiddleware`. It threads across every audit event, log
 * meta, and downstream ALS continuation of the same HTTP request so an
 * operator can join a Graph audit line to a winston debug line to a client
 * bug report without shipping timing correlations.
 */
export interface RequestContext {
  accessToken?: string;
  refreshToken?: string;
  /**
   * Real client IP after trust-proxy resolution. Equal to `socket.remoteAddress`
   * when the peer is not in TRUSTED_PROXIES, or the closest non-trusted hop
   * walking XFF right-to-left. Empty string in stdio mode (no HTTP).
   */
  clientIp?: string;
  /**
   * Correlation ID assigned by `createRequestIdMiddleware`. UUID v4 shape,
   * either accepted from the client's X-Request-Id header (when it matches
   * a strict UUID pattern) or generated server-side via `crypto.randomUUID`.
   * Undefined in stdio mode.
   */
  requestId?: string;
}

export const requestContext = new AsyncLocalStorage<RequestContext>();

export function getRequestTokens(): RequestContext | undefined {
  return requestContext.getStore();
}

/**
 * Return the current request's correlation id if the current async
 * continuation is running inside a `requestContext.run(...)` scope that
 * carried one. Undefined outside HTTP requests (stdio mode, background
 * timers, tests without a store).
 */
export function getRequestId(): string | undefined {
  return requestContext.getStore()?.requestId;
}

/**
 * RFC 4122 UUID pattern (any version, including v4/v7). We use a strict
 * anchored regex so partial or attacker-padded strings can't leak into the
 * correlation stream. Anything that doesn't match is discarded and a fresh
 * server-generated UUID replaces it.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Return `value` if it is a plausibly-safe UUID, else `undefined`.
 *
 * Exported for tests. Behavioural contract :
 *   - Case-insensitive (upstream servers may uppercase hex nibbles).
 *   - Rejects anything with leading/trailing whitespace, extra chars,
 *     length mismatch, or non-hex characters.
 */
export function coerceClientRequestId(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  if (!UUID_RE.test(value)) return undefined;
  // Normalise to lowercase so audit lines and log meta don't carry two
  // representations of the same id depending on the source.
  return value.toLowerCase();
}

export interface RequestIdMiddlewareOptions {
  /**
   * Test-injectable UUID factory. Defaults to Node's crypto.randomUUID.
   * Deterministic ids make behavioural tests trivial to assert.
   */
  generateId?: () => string;
  /**
   * Header name to read the client-supplied id from and echo back. Default
   * `X-Request-Id` — the de-facto standard used by Heroku, GitHub, Rails,
   * etc.
   */
  headerName?: string;
}

/**
 * Correlation-ID middleware (OBS-04).
 *
 * Behaviour :
 *   1. Read the `X-Request-Id` request header. If it matches a strict UUID
 *      pattern, adopt it verbatim (lowercased). Otherwise generate a fresh
 *      UUID via `crypto.randomUUID` (or the injected `generateId`).
 *   2. Attach the resolved id to `req.request_id` for handlers that read
 *      Express state directly.
 *   3. Echo the id in the response `X-Request-Id` header — clients can then
 *      quote it in bug reports and operators can grep the audit + winston
 *      streams for the same value.
 *   4. Enter an `AsyncLocalStorage` scope carrying `{ ...existingStore,
 *      requestId }` so every downstream `auditLog(...)` and winston format
 *      hook can read it via `getRequestId()` without threading the id
 *      through every function signature.
 *
 * Ordering caveat : mount this FIRST in the Express chain (before any
 * handler that might respond) — Express dispatches layers in registration
 * order, and a handler that never calls `next()` short-circuits any
 * later-registered middleware. The `http-app.ts` factory mounts it right
 * after `trust proxy` for this reason.
 */
export function createRequestIdMiddleware(
  options: RequestIdMiddlewareOptions = {}
): RequestHandler {
  const { generateId = randomUUID, headerName = 'X-Request-Id' } = options;
  const headerLower = headerName.toLowerCase();
  return function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
    // eslint-disable-next-line security/detect-object-injection -- justif: headerLower is a fixed lowercase copy of the operator-supplied headerName (default 'x-request-id') — no attacker path.
    const incoming = req.headers[headerLower];
    // Express collapses duplicates into an array — take the first token only,
    // matching how origin/host are handled elsewhere.
    const candidate = Array.isArray(incoming) ? incoming[0] : incoming;
    const requestId = coerceClientRequestId(candidate) ?? generateId();
    (req as Request & { request_id?: string }).request_id = requestId;
    res.setHeader(headerName, requestId);
    const existing = requestContext.getStore();
    // Merge with any pre-existing store (e.g. a future middleware layered
    // above us that already set accessToken). We create a NEW object so
    // downstream mutations don't retro-mutate the outer scope.
    const merged: RequestContext = { ...(existing ?? {}), requestId };
    requestContext.run(merged, () => next());
  };
}
