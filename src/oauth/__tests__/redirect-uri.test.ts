import { describe, expect, it } from 'vitest';
import { validateRedirectUri, normalizeRedirectUri } from '../redirect-uri.js';

const CLAUDE_ALLOWLIST: ReadonlySet<string> = new Set([
  'https://claude.ai/api/mcp/auth_callback',
  'https://claude.com/api/mcp/auth_callback',
]);

describe('validateRedirectUri (fix codex B1 — exact-match, no wildcard)', () => {
  describe('happy path', () => {
    it('accepts exact match against allowlist', () => {
      expect(validateRedirectUri('https://claude.ai/api/mcp/auth_callback', CLAUDE_ALLOWLIST)).toBe(
        true
      );
      expect(
        validateRedirectUri('https://claude.com/api/mcp/auth_callback', CLAUDE_ALLOWLIST)
      ).toBe(true);
    });

    it('accepts case-insensitive scheme + host but case-sensitive path', () => {
      expect(validateRedirectUri('HTTPS://CLAUDE.AI/api/mcp/auth_callback', CLAUDE_ALLOWLIST)).toBe(
        true
      );
    });
  });

  describe('rejection — wildcard / subdomain (codex B1 BLOCKER)', () => {
    it('rejects subdomain not in allowlist', () => {
      expect(
        validateRedirectUri('https://evil.claude.ai/api/mcp/auth_callback', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects different path even on allowed host', () => {
      expect(validateRedirectUri('https://claude.ai/api/mcp/other', CLAUDE_ALLOWLIST)).toBe(false);
      expect(validateRedirectUri('https://claude.ai/', CLAUDE_ALLOWLIST)).toBe(false);
    });

    it('rejects different host TLD', () => {
      expect(
        validateRedirectUri('https://claude.com.evil.tld/api/mcp/auth_callback', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects path-traversal style extras', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback/../evil', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects trailing slash mismatch', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback/', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });
  });

  describe('rejection — non-HTTPS (codex B1 + RFC 6749 §3.1.2.1)', () => {
    it('rejects http:// scheme', () => {
      expect(
        validateRedirectUri('http://claude.ai/api/mcp/auth_callback', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects custom schemes', () => {
      expect(
        validateRedirectUri('javascript:alert(1)', CLAUDE_ALLOWLIST)
      ).toBe(false);
      expect(
        validateRedirectUri('data:text/html,<script>', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });
  });

  describe('rejection — control chars / whitespace (mcp-vault v0.3.4 fullmatch hygiene + codex B1)', () => {
    it('rejects trailing newline', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback\n', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects trailing carriage return', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback\r', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects embedded tab', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/\tauth_callback', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects trailing space', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback ', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects null byte', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback\x00', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });
  });

  describe('rejection — percent-encoded path separators (anti response-splitting)', () => {
    it('rejects %2F (encoded /)', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback%2F..', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects %5C (encoded \\)', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback%5C', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects %00 (encoded NULL)', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback%00', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });

    it('rejects case variations of percent encoding', () => {
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback%2f..', CLAUDE_ALLOWLIST)
      ).toBe(false);
      expect(
        validateRedirectUri('https://claude.ai/api/mcp/auth_callback%5c', CLAUDE_ALLOWLIST)
      ).toBe(false);
    });
  });

  describe('rejection — malformed URLs', () => {
    it('rejects empty string', () => {
      expect(validateRedirectUri('', CLAUDE_ALLOWLIST)).toBe(false);
    });

    it('rejects non-URL string', () => {
      expect(validateRedirectUri('not-a-url', CLAUDE_ALLOWLIST)).toBe(false);
    });

    it('rejects relative path', () => {
      expect(validateRedirectUri('/api/mcp/auth_callback', CLAUDE_ALLOWLIST)).toBe(false);
    });
  });

  describe('empty allowlist (registered-only mode without clients)', () => {
    it('rejects everything when allowlist is empty', () => {
      expect(validateRedirectUri('https://claude.ai/api/mcp/auth_callback', new Set())).toBe(false);
    });
  });
});

describe('normalizeRedirectUri', () => {
  it('lowercases scheme + host, preserves path case', () => {
    expect(normalizeRedirectUri('HTTPS://Claude.AI/Api/Mcp/Auth_Callback')).toBe(
      'https://claude.ai/Api/Mcp/Auth_Callback'
    );
  });

  it('returns null for invalid input', () => {
    expect(normalizeRedirectUri('not-a-url')).toBeNull();
    expect(normalizeRedirectUri('')).toBeNull();
    expect(normalizeRedirectUri('https://example.com/path\n')).toBeNull();
  });

  it('returns null for non-HTTPS', () => {
    expect(normalizeRedirectUri('http://example.com')).toBeNull();
  });

  it('preserves query and fragment as-is', () => {
    expect(normalizeRedirectUri('https://EXAMPLE.com/path?a=1&b=2#frag')).toBe(
      'https://example.com/path?a=1&b=2#frag'
    );
  });
});
