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
 * non-trusted hop.
 *
 * Cf. SPECS-OAUTH-MCP.md v2 §12 and docs/MODES.md "Mode http-public".
 */

import { isIP } from 'node:net';

/**
 * Canonicalize an IP literal so equality matches operator-intent rather than
 * transport-detail or human typo. Resolves N0 review I2 + I4.
 *
 * Transformations:
 *   1. Strip the IPv4-mapped IPv6 prefix `::ffff:` when followed by IPv4.
 *   2. For IPv4 dotted-quad: strip leading zeros (`192.168.001.001` →
 *      `192.168.1.1`). Node's `net.isIP()` REJECTS leading-zero forms
 *      outright, so canonicalization MUST precede validation.
 *   3. For IPv6: lowercase the literal (Node delivers lowercase but env
 *      vars may be typed uppercase).
 *
 * Not handled: full RFC 5952 IPv6 canonicalization (`2001:0db8::1` vs
 * `2001:db8::1`). Operators must use the compact form.
 *
 * Returns the input unchanged when it is not a recognizable IP literal.
 */
export function normalizeIp(ip: string): string {
  let candidate = ip;

  // Step 1 : strip ::ffff: prefix
  if (candidate.startsWith('::ffff:')) {
    candidate = candidate.slice(7);
  }

  // Step 2 : if dotted-quad IPv4 pattern, normalize leading zeros.
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(candidate);
  if (ipv4Match) {
    const octets = [ipv4Match[1], ipv4Match[2], ipv4Match[3], ipv4Match[4]].map((o) =>
      Number(o)
    );
    if (octets.every((o) => Number.isInteger(o) && o >= 0 && o <= 255)) {
      return octets.join('.');
    }
    // Octet out of range — pass original (caller decides via isIP=0).
    return ip;
  }

  // Step 3 : IPv6 lowercase, only if recognized.
  if (isIP(candidate) === 6) {
    return candidate.toLowerCase();
  }

  return ip;
}

/**
 * Parse OUTLOOK_MCP_TRUSTED_PROXIES env var into a frozen Set of canonical
 * IP literals. Resolves N0 I4 (conf 80).
 *
 * Invalid entries (non-IP literals — typos, hostnames) are skipped with a
 * stderr warning rather than crashing the server.
 */
export function parseTrustedProxiesEnv(raw: string | undefined): ReadonlySet<string> {
  if (!raw) return new Set();
  const result = new Set<string>();
  for (const token of raw.split(',')) {
    const trimmed = token.trim();
    if (trimmed.length === 0) continue;
    const canonical = normalizeIp(trimmed);
    if (isIP(canonical) === 0) {
      process.stderr.write(
        `[trust-proxy] OUTLOOK_MCP_TRUSTED_PROXIES entry "${trimmed}" is not a valid IP literal. Entry ignored.\n`
      );
      continue;
    }
    result.add(canonical);
  }
  return result;
}

export function resolveClientIp(
  socketIp: string,
  xff: string | undefined,
  trustedProxies: ReadonlySet<string>
): string {
  const peer = normalizeIp(socketIp);

  if (!trustedProxies.has(peer)) return peer;

  if (!xff) return peer;
  const hops = xff
    .split(',')
    .map((h) => normalizeIp(h.trim()))
    .filter((h) => h.length > 0);
  if (hops.length === 0) return peer;

  for (let i = hops.length - 1; i >= 0; i--) {
    // eslint-disable-next-line security/detect-object-injection -- justif: i est un index numérique dans une boucle for bornée par hops.length. Pas d'accès à propriété nommée exploitable.
    const hop = hops[i];
    if (hop !== undefined && !trustedProxies.has(hop)) return hop;
  }

  return hops[0] ?? peer;
}
