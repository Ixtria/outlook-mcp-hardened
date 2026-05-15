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

/**
 * Normalize an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) to its IPv4 form.
 * Node's `req.socket.remoteAddress` on a dual-stack listener delivers IPv4
 * peers as `::ffff:A.B.C.D`, which would never match an operator's `A.B.C.D`
 * entry in TRUSTED_PROXIES (N0 review I2, conf 82, 2026-05-10). We strip the
 * prefix so equality is operator-intent rather than transport-detail.
 */
function normalizeIp(ip: string): string {
  if (ip.startsWith('::ffff:')) {
    const stripped = ip.slice(7);
    // Validate it looks like dotted-quad IPv4 (4 octets 0-255). If not, keep
    // original (e.g. `::ffff:abcd::1` exotic form — let it match literally).
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(stripped)) {
      const octets = stripped.split('.').map(Number);
      if (octets.every((o) => o >= 0 && o <= 255)) return stripped;
    }
  }
  return ip;
}

export function resolveClientIp(
  socketIp: string,
  xff: string | undefined,
  trustedProxies: ReadonlySet<string>
): string {
  const peer = normalizeIp(socketIp);

  // 1. If the immediate peer is not a trusted proxy, the XFF header is
  //    attacker-controlled. Trust nothing from it — return socket IP.
  if (!trustedProxies.has(peer)) return peer;

  // 2. Peer is trusted. Parse XFF.
  if (!xff) return peer;
  const hops = xff
    .split(',')
    .map((h) => normalizeIp(h.trim()))
    .filter((h) => h.length > 0);
  if (hops.length === 0) return peer;

  // 3. Walk right-to-left, skipping trusted-proxy hops, stop at first
  //    non-trusted = closest origin we can still attribute.
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = hops[i];
    if (hop !== undefined && !trustedProxies.has(hop)) return hop;
  }

  // 4. Pathological case: every hop is itself a trusted proxy. Fall back
  //    to leftmost — RFC 7239 §5.2 convention for "the original client".
  return hops[0] ?? peer;
}
