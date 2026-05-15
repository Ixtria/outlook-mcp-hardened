import { AsyncLocalStorage } from 'node:async_hooks';

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

/**
 * Parse the `OUTLOOK_MCP_TRUSTED_PROXIES` env var (comma-separated IPs) into a
 * frozen Set ready for `resolveClientIp()`. Returns an empty Set if unset or
 * whitespace-only, which makes the trust-proxy algorithm safely fall back to
 * the socket IP regardless of XFF content.
 */
export function parseTrustedProxiesEnv(raw: string | undefined): ReadonlySet<string> {
  if (!raw) return new Set();
  const items = raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return new Set(items);
}
