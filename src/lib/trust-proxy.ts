/**
 * Trusted-proxy client-IP resolution.
 *
 * Resolves codex review finding I8 (IMPORTANT, conf 90, 2026-05-10):
 *   "`X-Forwarded-For` rightmost as a generic rule is probably WRONG and
 *    makes rate-limiting ineffective or bypassable."
 *
 * And reconciles it with mcp-vault v0.3.3 fix I2:
 *   "nginx default `$proxy_add_x_forwarded_for` APPENDS the peer IP,
 *    so the rightmost entry IS the real client when behind nginx default."
 *
 * Both statements are true in different contexts. The right design is an
 * explicit trust-proxy model where the operator declares which peer IPs
 * are trusted reverse proxies, and the algorithm walks the XFF chain
 * right-to-left, skipping trusted-proxy hops, and stops at the first
 * non-trusted hop — which represents the closest non-proxy origin we can
 * still safely attribute to.
 *
 * Cf. SPECS-OAUTH-MCP.md v2 §12 and docs/MODES.md "Mode http-public".
 */

export function resolveClientIp(
  socketIp: string,
  xff: string | undefined,
  trustedProxies: ReadonlySet<string>
): string {
  // 1. If the immediate peer is not a trusted proxy, the XFF header is
  //    attacker-controlled. Trust nothing from it — return socket IP.
  if (!trustedProxies.has(socketIp)) return socketIp;

  // 2. Peer is trusted. Parse XFF.
  if (!xff) return socketIp;
  const hops = xff
    .split(',')
    .map((h) => h.trim())
    .filter((h) => h.length > 0);
  if (hops.length === 0) return socketIp;

  // 3. Walk right-to-left, skipping trusted-proxy hops, stop at first
  //    non-trusted = closest origin we can still attribute.
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = hops[i];
    if (hop !== undefined && !trustedProxies.has(hop)) return hop;
  }

  // 4. Pathological case: every hop is itself a trusted proxy. Fall back
  //    to leftmost — RFC 7239 §5.2 convention for "the original client".
  return hops[0] ?? socketIp;
}
