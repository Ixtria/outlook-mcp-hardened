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
// %2F/%5C/%00 : path-separator + null bytes (anti response-splitting)
// %0A/%0D     : encoded CR/LF (anti response-splitting / audit-log injection — N0 review I1)
// %2E         : encoded dot (anti `..` smuggling past path normalizers — N0 review I1)
const DANGEROUS_PERCENT = /%2[EeFf]|%5[Cc]|%00|%0[AaDd]/;

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

  // N0 review B1 fix (conf 95, 2026-05-10) : reject any userinfo component.
  // `URL` parses `user:pass@host` and exposes username/password separately, so
  // a naive `protocol+host+pathname` build silently strips them — making
  // `https://attacker@claude.ai/api/mcp/auth_callback` equal to the registered
  // `https://claude.ai/api/mcp/auth_callback` under `===`. That breaks the
  // exact-match contract (SPECS §5 step 5) AND `userinfo` has no legitimate
  // use in an OAuth redirect_uri (RFC 6749 §3.1.2, RFC 3986 §3.2.1).
  if (parsed.username !== '' || parsed.password !== '') return null;

  // Lowercase scheme + host (RFC 3986 §3.1, §3.2.2). Path/query/fragment
  // remain case-sensitive per spec — many web apps depend on this.
  return `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}${parsed.search}${parsed.hash}`;
}

export function validateRedirectUri(input: string, allowlist: ReadonlySet<string>): boolean {
  const normalized = normalizeRedirectUri(input);
  if (normalized === null) return false;
  return allowlist.has(normalized);
}
