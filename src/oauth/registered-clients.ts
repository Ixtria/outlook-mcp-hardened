/**
 * Static registry of known MCP clients allowed to talk to outlook-mcp-hardened.
 *
 * Per ADR-0003 (Niveau B), we intentionally do NOT support open dynamic client
 * registration. Each entry below maps a client identity to its exact-match
 * redirect_uri allowlist. New entries require a PR + cross-review (ADR-0001).
 *
 * Why exact-match strings instead of regex / wildcard:
 *   Codex review B1 (BLOCKER conf 96) — wildcard `https://claude.ai/*` is a
 *   code-exfiltration vector. The fixed-callback assumption that justifies
 *   Claude.ai as a trusted public client is destroyed the moment any sub-route
 *   becomes a legitimate destination.
 *
 * Sources of truth for the URIs below:
 *   - Anthropic public docs / tested integration with claude.ai
 *   - Bug Anthropic claude-ai-mcp#82 workaround (endpoints at root path)
 */

export interface RegisteredClient {
  readonly clientName: string;
  readonly redirectUris: ReadonlySet<string>;
  /** Scopes the client is allowed to request (intersected at /authorize). */
  readonly allowedScopes: ReadonlySet<string>;
}

const CLAUDE_AI_REDIRECT_URIS: ReadonlySet<string> = new Set([
  'https://claude.ai/api/mcp/auth_callback',
  'https://claude.com/api/mcp/auth_callback',
]);

const CLAUDE_AI_ALLOWED_SCOPES: ReadonlySet<string> = new Set([
  // Microsoft Graph scopes we expose. The actual intersection at /authorize
  // also passes through writePolicy (read-only by default, write opt-in via
  // --enable-send / --enable-write).
  'User.Read',
  'Mail.Read',
  'Mail.Send',
  'Calendars.Read',
  'Calendars.ReadWrite',
  'offline_access',
]);

const REGISTERED_CLIENTS: ReadonlyMap<string, RegisteredClient> = new Map([
  [
    'claude',
    {
      clientName: 'claude',
      redirectUris: CLAUDE_AI_REDIRECT_URIS,
      allowedScopes: CLAUDE_AI_ALLOWED_SCOPES,
    },
  ],
]);

/**
 * Returns the union of all registered redirect URIs across all known clients.
 * Used as the allowlist passed to `validateRedirectUri()` when we don't (yet)
 * know which client is making the call — for instance at /authorize before we
 * have parsed `client_id`. Caller is responsible for any per-client narrowing.
 */
export function allRegisteredRedirectUris(): ReadonlySet<string> {
  const all = new Set<string>();
  for (const client of REGISTERED_CLIENTS.values()) {
    for (const uri of client.redirectUris) all.add(uri);
  }
  return all;
}

/**
 * Returns the union of all scopes any registered client is allowed to request.
 * The effective per-request scope is further narrowed by writePolicy + RFC 6749
 * §3.3 intersection (cf. `intersectScopes()`).
 */
export function allRegisteredScopes(): ReadonlySet<string> {
  const all = new Set<string>();
  for (const client of REGISTERED_CLIENTS.values()) {
    for (const scope of client.allowedScopes) all.add(scope);
  }
  return all;
}

export function getRegisteredClient(clientName: string): RegisteredClient | undefined {
  return REGISTERED_CLIENTS.get(clientName);
}
