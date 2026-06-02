/**
 * Tests for the log redactor.
 *
 * Regression suite for N0 BLOCKER B1 fix (2026-06-02). Verifies that the
 * PII patterns we promised to redact actually get redacted, and that the
 * patterns we promised to preserve don't.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { redactSensitive } from '../src/security/log-redactor.js';
import { resetAuditSaltCache } from '../src/security/audit-salt.js';

describe('redactSensitive (N0 B1 fix)', () => {
  beforeEach(() => {
    // Deterministic salt so the email hashes are reproducible across runs.
    process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = '00112233445566778899aabbccddeeff';
    resetAuditSaltCache();
  });

  afterEach(() => {
    delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    resetAuditSaltCache();
  });

  describe('emails — the primary PII concern', () => {
    it('replaces a plain email with [email:HASH]', () => {
      const out = redactSensitive('user is alice@example.com today');
      expect(out).not.toContain('alice@example.com');
      expect(out).toMatch(/\[email:[a-f0-9]{8}\]/);
    });

    it('replaces multiple emails in the same string', () => {
      const out = redactSensitive('to=alice@example.com cc=bob@corp.org');
      expect(out).not.toContain('alice');
      expect(out).not.toContain('bob');
      expect(out).not.toContain('@');
    });

    it('handles dotted local parts (firstname.lastname@…)', () => {
      const out = redactSensitive('Sent by jane.doe@example.com');
      expect(out).not.toContain('jane.doe@example.com');
      expect(out).toMatch(/\[email:[a-f0-9]{8}\]/);
    });

    it('handles + tags (alice+work@…)', () => {
      const out = redactSensitive('Routed to alice+work@example.com');
      expect(out).not.toContain('alice+work');
    });

    it('handles percent-encoded @ in Graph URLs', () => {
      const out = redactSensitive(
        "GET /users('alice%40example.com')/messages"
      );
      expect(out).not.toContain('alice%40example.com');
      expect(out).toContain("/users('[email:");
    });

    it('uses the same hash for plain and percent-encoded forms (correlation)', () => {
      const plain = redactSensitive('alice@example.com');
      const encoded = redactSensitive('alice%40example.com');
      const plainHash = plain.match(/\[email:([a-f0-9]{8})\]/)?.[1];
      const encodedHash = encoded.match(/\[email:([a-f0-9]{8})\]/)?.[1];
      expect(plainHash).toBeDefined();
      expect(plainHash).toBe(encodedHash);
    });

    it('is idempotent (re-running on output produces same output)', () => {
      const once = redactSensitive('alice@example.com');
      const twice = redactSensitive(once);
      expect(twice).toBe(once);
    });

    it('different salt produces different hashes (correlation breaks across installs)', () => {
      const a = redactSensitive('alice@example.com');
      process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = 'ffeeddccbbaa99887766554433221100';
      resetAuditSaltCache();
      const b = redactSensitive('alice@example.com');
      expect(a).not.toBe(b);
    });
  });

  describe('Bearer tokens', () => {
    it('redacts a Bearer token', () => {
      const out = redactSensitive('Authorization: Bearer abc123.def456-secret');
      expect(out).not.toContain('abc123');
      expect(out).toContain('Bearer [redacted]');
    });

    it('redacts Bearer at start of string', () => {
      const out = redactSensitive('Bearer eyJhbGciOiJIUzI1NiJ9');
      expect(out).not.toContain('eyJhbGciOiJIUzI1NiJ9');
    });

    it('preserves non-Bearer text around the redaction', () => {
      const out = redactSensitive('Got 401 with Bearer foo on /me');
      expect(out).toContain('Got 401');
      expect(out).toContain('on /me');
      expect(out).toContain('Bearer [redacted]');
    });
  });

  describe('JWT-shaped strings', () => {
    it('redacts a 3-segment JWT', () => {
      const jwt =
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const out = redactSensitive(`token=${jwt} continuing`);
      expect(out).not.toContain(jwt);
      expect(out).toContain('[JWT redacted]');
      expect(out).toContain('continuing');
    });
  });

  describe('preserved (legitimately) — debuggability', () => {
    it('preserves tool names', () => {
      const out = redactSensitive('Tool list-mail-messages called');
      expect(out).toContain('list-mail-messages');
    });

    it('preserves HTTP methods + status codes', () => {
      const out = redactSensitive('GET /me/messages -> 200');
      expect(out).toContain('GET');
      expect(out).toContain('200');
    });

    it('preserves path templates', () => {
      const out = redactSensitive('Making graph request to /me/calendar/events');
      expect(out).toContain('/me/calendar/events');
    });

    it('preserves tenant IDs (public config)', () => {
      const out = redactSensitive('tenant=common app=12345678-1234-1234');
      expect(out).toContain('common');
      expect(out).toContain('12345678-1234-1234');
    });

    it('preserves emoji + CJK + accented text', () => {
      const out = redactSensitive('café 日本語 🎉 résumé');
      expect(out).toContain('café');
      expect(out).toContain('日本語');
      expect(out).toContain('🎉');
      expect(out).toContain('résumé');
    });
  });

  describe('non-string inputs', () => {
    it('stringifies object inputs before redaction', () => {
      const out = redactSensitive({ to: 'alice@example.com', subject: 'hi' });
      expect(out).not.toContain('alice@example.com');
      expect(out).toContain('subject');
    });

    it('handles null and undefined gracefully', () => {
      expect(redactSensitive(null)).toBe('null');
      expect(redactSensitive(undefined)).toBe('undefined');
    });

    it('handles non-serializable input without throwing', () => {
      const circular: { self?: unknown } = {};
      circular.self = circular;
      expect(() => redactSensitive(circular)).not.toThrow();
    });
  });

  describe('regression — graph-tools.ts logger sinks identified by N0 review', () => {
    it('redacts JSON.stringify(params) with toRecipients', () => {
      const params = {
        toRecipients: [{ emailAddress: { address: 'victim@example.com' } }],
        subject: 'Q4 report',
        body: 'PFA the report',
      };
      const out = redactSensitive(`Tool send-mail called with params: ${JSON.stringify(params)}`);
      expect(out).not.toContain('victim@example.com');
      // The subject + body are preserved (they're not email-shaped) — that's
      // a separate concern documented in CHANGELOG. The PRIMARY leak (email
      // identifiers) is closed.
      expect(out).toContain('Q4 report');
    });

    it('redacts emails in graph nextLink URLs', () => {
      const url =
        "https://graph.microsoft.com/v1.0/users('alice@example.com')/messages?$skip=10";
      const out = redactSensitive(`Fetching page from: ${url}`);
      expect(out).not.toContain('alice@example.com');
    });

    it('redacts emails in $filter query strings', () => {
      const path =
        "/me/messages?$filter=from/emailAddress/address eq 'attacker@example.com'";
      const out = redactSensitive(`Making graph request to ${path}`);
      expect(out).not.toContain('attacker@example.com');
    });
  });
});
