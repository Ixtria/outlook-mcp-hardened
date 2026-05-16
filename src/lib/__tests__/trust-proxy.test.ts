import { describe, expect, it, vi } from 'vitest';
import { normalizeIp, parseTrustedProxiesEnv, resolveClientIp } from '../trust-proxy.js';

const TRUSTED: ReadonlySet<string> = new Set(['10.0.0.1', '10.0.0.2', '127.0.0.1']);

describe('resolveClientIp (fix codex I8 — explicit trusted-proxy model)', () => {
  describe('peer not trusted → ignore XFF entirely', () => {
    it('returns socket IP if peer is not in TRUSTED_PROXIES', () => {
      expect(resolveClientIp('9.9.9.9', '1.1.1.1, 2.2.2.2', TRUSTED)).toBe('9.9.9.9');
    });

    it('returns socket IP even if XFF claims a benign IP', () => {
      // Direct attacker connection forging XFF header → header MUST be ignored.
      expect(resolveClientIp('9.9.9.9', '127.0.0.1', TRUSTED)).toBe('9.9.9.9');
    });

    it('returns socket IP if peer is empty (edge case)', () => {
      expect(resolveClientIp('', '1.1.1.1', TRUSTED)).toBe('');
    });
  });

  describe('peer trusted, no XFF', () => {
    it('returns peer IP if XFF is absent', () => {
      expect(resolveClientIp('10.0.0.1', undefined, TRUSTED)).toBe('10.0.0.1');
    });

    it('returns peer IP if XFF is empty string', () => {
      expect(resolveClientIp('10.0.0.1', '', TRUSTED)).toBe('10.0.0.1');
    });

    it('returns peer IP if XFF is only whitespace and commas', () => {
      expect(resolveClientIp('10.0.0.1', ' , , ', TRUSTED)).toBe('10.0.0.1');
    });
  });

  describe('nginx default append (mcp-vault v0.3.3 fix I2 scenario)', () => {
    it('rightmost = real client when nginx APPENDS peer IP', () => {
      // Client behind nginx. nginx with `$proxy_add_x_forwarded_for` appends
      // the client's source IP at the rightmost position seen by the app
      // (peer=10.0.0.1=nginx). So the rightmost non-trusted is the client.
      expect(resolveClientIp('10.0.0.1', 'evil-claim-1, evil-claim-2, 1.2.3.4', TRUSTED)).toBe(
        '1.2.3.4'
      );
    });

    it('chain of two trusted proxies appended in order', () => {
      // App ← nginx-edge(10.0.0.2) ← nginx-internal(10.0.0.1) ← client(1.2.3.4)
      // XFF appended at each hop: "1.2.3.4, 10.0.0.1" (peer = 10.0.0.2 nginx-edge).
      expect(resolveClientIp('10.0.0.2', '1.2.3.4, 10.0.0.1', TRUSTED)).toBe('1.2.3.4');
    });
  });

  describe('peer trusted, XFF has spoofed prepend (codex I8 scenario)', () => {
    it('stops at the first NON-trusted hop walking right-to-left', () => {
      // Attacker sets XFF=evil_claim. nginx appends real client (1.2.3.4)
      // and peer is nginx (10.0.0.1). Algo must walk right→left, skip
      // trusted-proxy hops, and return the first non-trusted = the real
      // origin OR the attacker claim IF it's leftmost (we still go strict
      // right-to-left, see below).
      expect(resolveClientIp('10.0.0.1', 'evil-claim, 1.2.3.4', TRUSTED)).toBe('1.2.3.4');
    });

    it('multiple trusted-proxy hops are skipped right-to-left', () => {
      // App ← p1(10.0.0.1) ← p2(10.0.0.2) ← client(1.2.3.4)
      // If both p1 and p2 are trusted and appended their seen IPs:
      // XFF = "1.2.3.4, 10.0.0.2" with peer=10.0.0.1 → skip 10.0.0.2 (trusted),
      // arrive at 1.2.3.4 (non-trusted) → return 1.2.3.4.
      expect(resolveClientIp('10.0.0.1', '1.2.3.4, 10.0.0.2', TRUSTED)).toBe('1.2.3.4');
    });

    it('all hops trusted (loop back) → fallback to leftmost convention', () => {
      // Pathological: all entries in XFF are also in trusted list. Leftmost is
      // the convention for "the original client" per RFC 7239 §5.2 and most
      // reverse-proxy semantics.
      expect(resolveClientIp('10.0.0.1', '127.0.0.1, 10.0.0.2', TRUSTED)).toBe('127.0.0.1');
    });
  });

  describe('XFF format edge cases', () => {
    it('handles single-entry XFF', () => {
      expect(resolveClientIp('10.0.0.1', '1.2.3.4', TRUSTED)).toBe('1.2.3.4');
    });

    it('handles XFF with trailing comma', () => {
      expect(resolveClientIp('10.0.0.1', '1.2.3.4,', TRUSTED)).toBe('1.2.3.4');
    });

    it('handles XFF with extra whitespace', () => {
      expect(resolveClientIp('10.0.0.1', '  1.2.3.4  ,  10.0.0.2  ', TRUSTED)).toBe('1.2.3.4');
    });

    it('handles XFF with IPv6 in brackets-less form', () => {
      // Note: real-world XFF for IPv6 may include brackets. We treat as opaque
      // string match against TRUSTED, so the operator must list the exact form.
      expect(resolveClientIp('10.0.0.1', '2001:db8::1', TRUSTED)).toBe('2001:db8::1');
    });
  });

  describe('IPv4 leading-zero canonicalization (N0 I4 conf 80)', () => {
    it('matches trusted entry with leading zeros against canonical socket IP', () => {
      // Operator typo: lists 192.168.001.001 in env. Socket delivers 192.168.1.1.
      // Before I4 fix : silent trust failure. After fix : canonicalized on parse,
      // both sides equal.
      const trusted = parseTrustedProxiesEnv('192.168.001.001');
      expect(resolveClientIp('192.168.1.1', '203.0.113.5', trusted)).toBe('203.0.113.5');
    });

    it('canonical entry matches non-canonical socket form', () => {
      // Reverse direction: socket somehow delivers 192.168.001.001 (rare but
      // possible via TLS terminator). normalizeIp on the peer side fixes it.
      const trusted = new Set(['192.168.1.1']);
      expect(resolveClientIp('192.168.001.001', '203.0.113.5', trusted)).toBe('203.0.113.5');
    });
  });

  describe('IPv4-mapped IPv6 (N0 review I2, conf 82)', () => {
    it('socket as IPv4-mapped IPv6 matches IPv4 entry in TRUSTED_PROXIES', () => {
      // Node dual-stack listener delivers `::ffff:10.0.0.1` for an IPv4 peer.
      expect(resolveClientIp('::ffff:10.0.0.1', '1.2.3.4', TRUSTED)).toBe('1.2.3.4');
    });

    it('XFF entry as IPv4-mapped IPv6 also matches IPv4 trusted entry', () => {
      expect(
        resolveClientIp('10.0.0.1', '1.2.3.4, ::ffff:10.0.0.2', TRUSTED)
      ).toBe('1.2.3.4');
    });

    it('preserves real IPv6 addresses untouched', () => {
      // Not an IPv4-mapped form — keep as-is so it can match a real IPv6 entry.
      expect(resolveClientIp('2001:db8::1', undefined, new Set(['2001:db8::1']))).toBe(
        '2001:db8::1'
      );
    });

    it('does not strip prefix from malformed IPv4-mapped string', () => {
      // `::ffff:999.999.999.999` — looks like the prefix but octets invalid.
      // Keep literal so it matches operator-listed literal if exotic.
      expect(
        resolveClientIp('::ffff:999.999.999.999', undefined, new Set(['::ffff:999.999.999.999']))
      ).toBe('::ffff:999.999.999.999');
    });
  });

  describe('IPv6 uppercase normalization (N0 I4)', () => {
    it('matches uppercase IPv6 env entry against lowercase socket form', () => {
      const trusted = parseTrustedProxiesEnv('2001:DB8::1');
      expect(resolveClientIp('2001:db8::1', '203.0.113.5', trusted)).toBe('203.0.113.5');
    });
  });

  describe('attack scenarios (regression tests)', () => {
    it('attacker directly connecting cannot impersonate via XFF', () => {
      // Attacker at 9.9.9.9 not behind a trusted proxy, sets XFF to claim
      // the IP of a trusted bypass-target → MUST be ignored.
      expect(resolveClientIp('9.9.9.9', '127.0.0.1', TRUSTED)).toBe('9.9.9.9');
    });

    it('attacker behind trusted proxy cannot spoof beyond their real IP', () => {
      // Real client 1.2.3.4 sends XFF: "10.0.0.99, 9.9.9.9" trying to claim
      // a different origin. nginx appends → final XFF received by app is
      // "10.0.0.99, 9.9.9.9, 1.2.3.4". Walking right-to-left:
      //   peer 10.0.0.1 (trusted, skip)
      //   1.2.3.4 (untrusted) → STOP. Return 1.2.3.4. Spoof attempt blocked.
      expect(
        resolveClientIp('10.0.0.1', '10.0.0.99, 9.9.9.9, 1.2.3.4', TRUSTED)
      ).toBe('1.2.3.4');
    });
  });
});

describe('normalizeIp', () => {
  it('strips leading zeros from IPv4 octets', () => {
    expect(normalizeIp('192.168.001.001')).toBe('192.168.1.1');
    expect(normalizeIp('010.000.000.001')).toBe('10.0.0.1');
  });

  it('preserves canonical IPv4', () => {
    expect(normalizeIp('192.168.1.1')).toBe('192.168.1.1');
    expect(normalizeIp('127.0.0.1')).toBe('127.0.0.1');
  });

  it('strips ::ffff: prefix from IPv4-mapped IPv6 + canonicalizes', () => {
    expect(normalizeIp('::ffff:192.168.001.001')).toBe('192.168.1.1');
  });

  it('lowercases IPv6', () => {
    expect(normalizeIp('2001:DB8::1')).toBe('2001:db8::1');
    expect(normalizeIp('FE80::1')).toBe('fe80::1');
  });

  it('passes through unknown inputs unchanged (Unix socket paths, etc.)', () => {
    expect(normalizeIp('/var/run/sock')).toBe('/var/run/sock');
    expect(normalizeIp('not-an-ip')).toBe('not-an-ip');
    expect(normalizeIp('')).toBe('');
  });

  it('rejects invalid IPv4 (octet > 255) by passing through as non-canonical', () => {
    // 999.999.999.999 fails net.isIP() → pass-through unchanged.
    expect(normalizeIp('999.999.999.999')).toBe('999.999.999.999');
  });
});

describe('parseTrustedProxiesEnv (N0 I4 fix)', () => {
  it('returns empty Set for undefined / empty / whitespace', () => {
    expect(parseTrustedProxiesEnv(undefined).size).toBe(0);
    expect(parseTrustedProxiesEnv('').size).toBe(0);
    expect(parseTrustedProxiesEnv('   ').size).toBe(0);
    expect(parseTrustedProxiesEnv(',,,').size).toBe(0);
  });

  it('parses single IP and canonicalizes', () => {
    const set = parseTrustedProxiesEnv('192.168.001.001');
    expect(set.has('192.168.1.1')).toBe(true);
    expect(set.has('192.168.001.001')).toBe(false); // entry was canonicalized
    expect(set.size).toBe(1);
  });

  it('parses comma-separated list with whitespace tolerance', () => {
    const set = parseTrustedProxiesEnv('  10.0.0.1 , 10.0.0.2 ,127.0.0.1  ');
    expect(set.has('10.0.0.1')).toBe(true);
    expect(set.has('10.0.0.2')).toBe(true);
    expect(set.has('127.0.0.1')).toBe(true);
    expect(set.size).toBe(3);
  });

  it('skips invalid IP entries with a stderr warning', () => {
    const writeSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const set = parseTrustedProxiesEnv('10.0.0.1,not-an-ip,10.0.0.2,999.999.999.999');
    expect(set.size).toBe(2);
    expect(set.has('10.0.0.1')).toBe(true);
    expect(set.has('10.0.0.2')).toBe(true);
    expect(set.has('not-an-ip')).toBe(false);
    expect(set.has('999.999.999.999')).toBe(false);
    // Two warnings expected (one per invalid entry)
    expect(writeSpy.mock.calls.length).toBeGreaterThanOrEqual(2);
    writeSpy.mockRestore();
  });

  it('IPv6 entries are accepted and lowercased', () => {
    const set = parseTrustedProxiesEnv('2001:DB8::1,fe80::1');
    expect(set.has('2001:db8::1')).toBe(true);
    expect(set.has('fe80::1')).toBe(true);
  });

  it('filters out empty tokens from trailing/double commas', () => {
    const set = parseTrustedProxiesEnv('10.0.0.1,,10.0.0.2,');
    expect(set.size).toBe(2);
  });
});
