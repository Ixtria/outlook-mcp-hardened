/**
 * Property-based tests (Tier 2 adversarial — fast-check).
 *
 * Where unit tests verify hand-picked cases, property-based tests assert
 * INVARIANTS over generated inputs. fast-check generates ~100 random samples
 * per property (configurable) and shrinks failures to a minimal repro. This
 * catches the bugs that hand-picked cases miss : edge-case unicode, weird
 * whitespace, surrogate pairs, integer boundaries, etc.
 *
 * Invariants tested here are the SECURITY CONTRACTS of our pure modules :
 *   1. `validateRedirectUri` : output TRUE implies the input is byte-for-byte
 *      equal (after normalization) to a registered URI. No other input can
 *      slip through.
 *   2. `intersectScopes` : output is always a subset of `requested` ∩
 *      `registered` ∩ `known` (after RFC 6749 §3.3 fallback).
 *   3. `resolveClientIp` : output is either the socket peer (when untrusted)
 *      or some hop from XFF + socket (never invented from thin air).
 *   4. `normalizeIp` : idempotent. Canonical IPs round-trip identity.
 *   5. `parseTrustedProxiesEnv` : every entry in the output Set passes
 *      `net.isIP() != 0`.
 */

import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { isIP } from 'node:net';
import { validateRedirectUri, normalizeRedirectUri } from '../redirect-uri.js';
import { intersectScopes, parseScope, serializeScope } from '../scope.js';
import {
  normalizeIp,
  parseTrustedProxiesEnv,
  resolveClientIp,
} from '../../lib/trust-proxy.js';

const FC_RUNS = 200; // higher than default (100), still fast enough for CI

// ─────────────────────────────────────────────────────────────────────────
// redirect-uri.ts invariants
// ─────────────────────────────────────────────────────────────────────────

describe('validateRedirectUri — property-based invariants', () => {
  const allowlist = new Set([
    'https://claude.ai/api/mcp/auth_callback',
    'https://claude.com/api/mcp/auth_callback',
  ]);

  it('INVARIANT — only inputs whose normalized form is in the allowlist return true', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const accepted = validateRedirectUri(input, allowlist);
        if (accepted) {
          const normalized = normalizeRedirectUri(input);
          expect(normalized).not.toBeNull();
          expect(allowlist.has(normalized as string)).toBe(true);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — empty allowlist always rejects', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        expect(validateRedirectUri(input, new Set())).toBe(false);
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — never accepts a URI containing control chars or whitespace', () => {
    // Build URIs that include random control chars somewhere. They MUST all
    // be rejected regardless of allowlist content.
    fc.assert(
      fc.property(
        fc.constantFrom('\n', '\r', '\t', ' ', '\x00', '\x1F', '\x7F'),
        fc.string(),
        (controlChar, padding) => {
          const malicious = `https://claude.ai/api/mcp/auth_callback${controlChar}${padding}`;
          expect(validateRedirectUri(malicious, allowlist)).toBe(false);
        }
      ),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — never accepts non-https URIs', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('http', 'ftp', 'javascript', 'data', 'file', 'gopher'),
        fc.webPath(),
        (scheme, path) => {
          const uri = `${scheme}://claude.ai${path}`;
          expect(validateRedirectUri(uri, allowlist)).toBe(false);
        }
      ),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — never accepts URIs with userinfo (regression N0-B1)', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z0-9_-]{1,20}$/),
        fc.option(fc.stringMatching(/^[a-z0-9_-]{1,20}$/)),
        (user, pass) => {
          const userinfo = pass !== null ? `${user}:${pass}` : user;
          const malicious = `https://${userinfo}@claude.ai/api/mcp/auth_callback`;
          expect(validateRedirectUri(malicious, allowlist)).toBe(false);
        }
      ),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — never accepts URIs with dangerous percent-encoded sequences', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('%2F', '%2f', '%5C', '%5c', '%00', '%0A', '%0a', '%0D', '%0d', '%2E', '%2e'),
        (badPercent) => {
          const malicious = `https://claude.ai/api/mcp/auth_callback${badPercent}suffix`;
          expect(validateRedirectUri(malicious, allowlist)).toBe(false);
        }
      ),
      { numRuns: FC_RUNS }
    );
  });
});

describe('normalizeRedirectUri — property-based invariants', () => {
  it('INVARIANT — idempotent on non-null output', () => {
    fc.assert(
      fc.property(fc.webUrl({ validSchemes: ['https'] }), (url) => {
        const once = normalizeRedirectUri(url);
        if (once !== null) {
          const twice = normalizeRedirectUri(once);
          expect(twice).toBe(once);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — output always starts with https:// or is null', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const result = normalizeRedirectUri(input);
        if (result !== null) {
          expect(result.startsWith('https://')).toBe(true);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────
// scope.ts invariants
// ─────────────────────────────────────────────────────────────────────────

describe('intersectScopes — property-based invariants', () => {
  const known = new Set(['mcp:read', 'mcp:write', 'Mail.Read', 'Mail.ReadWrite']);

  // Scope grammar : RFC 6749 §3.3 allows %x21 / %x23-5B / %x5D-7E (no SP / DQUOTE / etc)
  const scopeToken = fc.stringMatching(/^[!#-[\]-~]{1,20}$/);
  const scopeString = fc
    .array(scopeToken, { maxLength: 8 })
    .map((tokens) => tokens.join(' '));

  it('INVARIANT — output ⊆ requested ∩ registered ∩ known (when requested non-empty)', () => {
    fc.assert(
      fc.property(scopeString, scopeString, (requested, registered) => {
        const requestedSet = parseScope(requested);
        if (requestedSet.size === 0) return; // §3.3 fallback case tested separately
        const registeredSet = parseScope(registered);
        const result = intersectScopes(requested, registered, known);
        for (const scope of result) {
          expect(requestedSet.has(scope)).toBe(true);
          expect(registeredSet.has(scope)).toBe(true);
          expect(known.has(scope)).toBe(true);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — empty/undefined requested falls back to registered ∩ known', () => {
    fc.assert(
      fc.property(scopeString, (registered) => {
        const registeredSet = parseScope(registered);
        const result = intersectScopes(undefined, registered, known);
        for (const scope of result) {
          expect(registeredSet.has(scope)).toBe(true);
          expect(known.has(scope)).toBe(true);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — output never contains scope outside KNOWN (last-line defense)', () => {
    fc.assert(
      fc.property(scopeString, scopeString, (requested, registered) => {
        const result = intersectScopes(requested, registered, known);
        for (const scope of result) {
          expect(known.has(scope)).toBe(true);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — serializeScope output is sorted', () => {
    fc.assert(
      fc.property(fc.array(scopeToken, { maxLength: 10 }), (tokens) => {
        const set = new Set(tokens);
        const serialized = serializeScope(set);
        const parts = serialized.split(' ').filter(Boolean);
        const sorted = [...parts].sort();
        expect(parts).toEqual(sorted);
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — parseScope ∘ serializeScope = identity on Set inputs', () => {
    fc.assert(
      fc.property(fc.array(scopeToken, { maxLength: 10 }), (tokens) => {
        const set = new Set(tokens);
        const roundtrip = parseScope(serializeScope(set));
        expect(roundtrip).toEqual(set);
      }),
      { numRuns: FC_RUNS }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────
// trust-proxy.ts invariants
// ─────────────────────────────────────────────────────────────────────────

// Generators for IP literals
const ipv4Octet = fc.integer({ min: 0, max: 255 });
const ipv4 = fc.tuple(ipv4Octet, ipv4Octet, ipv4Octet, ipv4Octet).map((o) => o.join('.'));

describe('normalizeIp — property-based invariants', () => {
  it('INVARIANT — idempotent (canonical form maps to itself)', () => {
    fc.assert(
      fc.property(ipv4, (ip) => {
        const once = normalizeIp(ip);
        const twice = normalizeIp(once);
        expect(twice).toBe(once);
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — output is either valid IP (isIP > 0) or original (passthrough)', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const result = normalizeIp(input);
        // Either the result is a valid IP, OR we passed through unchanged.
        const valid = isIP(result);
        if (valid === 0) {
          // Passed through. The original must also have been non-IP-ish OR
          // an IPv4 with out-of-range octets we deliberately preserve.
          expect(result).toBe(input);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — IPv4 leading-zero variants normalize to canonical', () => {
    fc.assert(
      fc.property(ipv4Octet, ipv4Octet, ipv4Octet, ipv4Octet, (a, b, c, d) => {
        const pad = (n: number) => String(n).padStart(3, '0');
        const padded = [a, b, c, d].map(pad).join('.');
        const canonical = [a, b, c, d].join('.');
        expect(normalizeIp(padded)).toBe(canonical);
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — IPv4-mapped IPv6 (::ffff:A.B.C.D) normalizes to bare IPv4', () => {
    fc.assert(
      fc.property(ipv4, (ip) => {
        expect(normalizeIp(`::ffff:${ip}`)).toBe(normalizeIp(ip));
      }),
      { numRuns: FC_RUNS }
    );
  });
});

describe('parseTrustedProxiesEnv — property-based invariants', () => {
  it('INVARIANT — every entry in output Set is a valid IP literal', () => {
    fc.assert(
      fc.property(fc.array(fc.string(), { maxLength: 20 }), (tokens) => {
        const raw = tokens.join(',');
        const result = parseTrustedProxiesEnv(raw);
        for (const entry of result) {
          expect(isIP(entry)).toBeGreaterThan(0);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — IPv4 list round-trips through canonicalization', () => {
    fc.assert(
      fc.property(fc.array(ipv4, { minLength: 1, maxLength: 10 }), (ips) => {
        const raw = ips.join(',');
        const result = parseTrustedProxiesEnv(raw);
        for (const ip of ips) {
          expect(result.has(normalizeIp(ip))).toBe(true);
        }
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — empty/whitespace tokens are filtered out', () => {
    fc.assert(
      fc.property(fc.array(fc.constantFrom('', '   ', '\t'), { maxLength: 20 }), (tokens) => {
        const raw = tokens.join(',');
        expect(parseTrustedProxiesEnv(raw).size).toBe(0);
      }),
      { numRuns: FC_RUNS }
    );
  });
});

describe('resolveClientIp — property-based invariants', () => {
  it('INVARIANT — output is socket peer when untrusted, regardless of XFF content', () => {
    fc.assert(
      fc.property(ipv4, fc.string(), fc.array(ipv4, { maxLength: 5 }), (socket, evilXff, trustedList) => {
        const trusted = new Set(trustedList.map(normalizeIp));
        if (trusted.has(normalizeIp(socket))) return; // skip the trusted case (other prop covers it)
        const result = resolveClientIp(socket, evilXff, trusted);
        expect(result).toBe(normalizeIp(socket));
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — when peer trusted and XFF empty, output is socket peer', () => {
    fc.assert(
      fc.property(ipv4, fc.constantFrom(undefined, ''), (socket, xff) => {
        const trusted = new Set([normalizeIp(socket)]);
        expect(resolveClientIp(socket, xff, trusted)).toBe(normalizeIp(socket));
      }),
      { numRuns: FC_RUNS }
    );
  });

  it('INVARIANT — output is always derived from socket or XFF input (never invented)', () => {
    fc.assert(
      fc.property(
        ipv4,
        fc.array(ipv4, { maxLength: 5 }),
        fc.array(ipv4, { maxLength: 5 }),
        (socket, hops, trustedList) => {
          const trusted = new Set(trustedList.map(normalizeIp));
          const xff = hops.join(', ');
          const result = resolveClientIp(socket, xff, trusted);
          // Result must be either the normalized socket, or one of the hops (normalized).
          const validOutputs = new Set([normalizeIp(socket), ...hops.map(normalizeIp)]);
          expect(validOutputs.has(result)).toBe(true);
        }
      ),
      { numRuns: FC_RUNS }
    );
  });

  it('SECURITY INVARIANT — attacker direct connection never wins XFF spoofing', () => {
    fc.assert(
      fc.property(
        ipv4,
        ipv4,
        fc.array(ipv4, { minLength: 1, maxLength: 5 }),
        (attackerSocket, victimIp, trustedListBase) => {
          // Build trusted list that does NOT include the attacker.
          const trustedList = trustedListBase.filter((ip) => ip !== attackerSocket);
          if (trustedList.length === 0) return;
          const trusted = new Set(trustedList.map(normalizeIp));
          // Attacker tries to forge XFF claiming to be the victim.
          const result = resolveClientIp(attackerSocket, victimIp, trusted);
          // Output must be the attacker's actual socket IP, never the victim's.
          if (normalizeIp(attackerSocket) !== normalizeIp(victimIp)) {
            expect(result).toBe(normalizeIp(attackerSocket));
            expect(result).not.toBe(normalizeIp(victimIp));
          }
        }
      ),
      { numRuns: FC_RUNS }
    );
  });
});
