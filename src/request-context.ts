import { AsyncLocalStorage } from 'node:async_hooks';

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
 */
export interface RequestContext {
  accessToken: string;
  refreshToken?: string;
  /**
   * Real client IP after trust-proxy resolution. Equal to `socket.remoteAddress`
   * when the peer is not in TRUSTED_PROXIES, or the closest non-trusted hop
   * walking XFF right-to-left. Empty string in stdio mode (no HTTP).
   */
  clientIp?: string;
}

export const requestContext = new AsyncLocalStorage<RequestContext>();

export function getRequestTokens(): RequestContext | undefined {
  return requestContext.getStore();
}

