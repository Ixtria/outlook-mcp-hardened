/**
 * OAuth 2.0 scope handling — strict intersection per RFC 6749 §3.3.
 *
 * Resolves codex review finding I1 (IMPORTANT, conf 95, 2026-05-10):
 *   "Scope intersection is not normative in SPECS while the migration plan
 *    cites it as a known security fix (mcp-vault B1)."
 *
 * Rule (cf. SPECS-OAUTH-MCP.md v2 §6 step 6 and ADR-0002 D5):
 *   effective_scope = requested ∩ registered ∩ KNOWN
 *
 * If `requested` is empty/undefined, fall back to `registered ∩ KNOWN`
 * (RFC 6749 §3.3: "If the client omits the scope parameter ... the
 *  authorization server MUST ... use a pre-defined default value").
 *
 * No "trusted-redirect exception" (codex I9 — mcp-vault v0.3.4 Option B
 * was explicitly rejected in ADR-0002 D5).
 */

export function parseScope(input: string | undefined): Set<string> {
  if (!input) return new Set();
  const tokens = input.split(/\s+/).filter((t) => t.length > 0);
  return new Set(tokens);
}

export function serializeScope(scopes: ReadonlySet<string>): string {
  return [...scopes].sort().join(' ');
}

export function intersectScopes(
  requested: string | undefined,
  registered: string,
  known: ReadonlySet<string>
): Set<string> {
  const reg = parseScope(registered);
  const req = parseScope(requested);

  // RFC 6749 §3.3 fallback: empty request → use registered as the request.
  const effectiveRequest = req.size === 0 ? reg : req;

  const result = new Set<string>();
  for (const scope of effectiveRequest) {
    if (reg.has(scope) && known.has(scope)) {
      result.add(scope);
    }
  }
  return result;
}
