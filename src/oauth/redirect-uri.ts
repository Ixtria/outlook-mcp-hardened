/**
 * redirect_uri validation — strict exact-match against a registered allowlist.
 *
 * Resolves codex review finding B1 (BLOCKER, conf 96, 2026-05-10):
 *   "Wildcard allowlist (`https://claude.ai/*`) destroys the public-client
 *    fixed-callback trust assumption and opens code exfiltration."
 *
 * Also resolves mcp-vault v0.3.4 hygiene fix:
 *   "regex `re.match` accepts trailing `\n` — use `fullmatch`."
 *
 * Rules enforced (cf. SPECS-OAUTH-MCP.md v2 §5):
 *   1. Only `https:` scheme.
 *   2. Reject any control char or whitespace in the input.
 *   3. Reject percent-encoded slash/backslash/null (anti response-splitting).
 *   4. Normalize scheme + host to lowercase; path/query/fragment as-is.
 *   5. EXACT `===` match against allowlist after normalization.
 */

// eslint-disable-next-line no-control-regex -- intentional: blocking control chars in redirect_uri is a security requirement (codex B1 + mcp-vault v0.3.4 hygiene fix)
const CONTROL_OR_WHITESPACE = /[\s\x00-\x1F\x7F]/;
const DANGEROUS_PERCENT = /%2[Ff]|%5[Cc]|%00/;

export function normalizeRedirectUri(input: string): string | null {
  if (!input || CONTROL_OR_WHITESPACE.test(input)) return null;
  if (DANGEROUS_PERCENT.test(input)) return null;

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'https:') return null;

  // Lowercase scheme + host (RFC 3986 §3.1, §3.2.2). Path/query/fragment
  // remain case-sensitive per spec — many web apps depend on this.
  return `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}${parsed.search}${parsed.hash}`;
}

export function validateRedirectUri(input: string, allowlist: ReadonlySet<string>): boolean {
  const normalized = normalizeRedirectUri(input);
  if (normalized === null) return false;
  return allowlist.has(normalized);
}
