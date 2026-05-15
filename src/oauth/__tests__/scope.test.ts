import { describe, expect, it } from 'vitest';
import { intersectScopes, parseScope, serializeScope } from '../scope.js';

const KNOWN_SCOPES: ReadonlySet<string> = new Set(['mcp:read', 'mcp:write']);

describe('parseScope', () => {
  it('returns empty Set for empty/whitespace input', () => {
    expect(parseScope('')).toEqual(new Set());
    expect(parseScope('   ')).toEqual(new Set());
    expect(parseScope(undefined)).toEqual(new Set());
  });

  it('splits on whitespace per RFC 6749 §3.3', () => {
    expect(parseScope('mcp:read mcp:write')).toEqual(new Set(['mcp:read', 'mcp:write']));
  });

  it('normalizes multiple whitespace and trims', () => {
    expect(parseScope('  mcp:read   mcp:write  ')).toEqual(new Set(['mcp:read', 'mcp:write']));
    expect(parseScope('mcp:read\tmcp:write')).toEqual(new Set(['mcp:read', 'mcp:write']));
  });

  it('deduplicates', () => {
    expect(parseScope('mcp:read mcp:read mcp:write')).toEqual(new Set(['mcp:read', 'mcp:write']));
  });
});

describe('serializeScope', () => {
  it('joins with single space, deterministic order (sorted)', () => {
    expect(serializeScope(new Set(['mcp:write', 'mcp:read']))).toBe('mcp:read mcp:write');
  });

  it('returns empty string for empty Set', () => {
    expect(serializeScope(new Set())).toBe('');
  });
});

describe('intersectScopes (fix codex I1 — normative requested ∩ registered ∩ KNOWN)', () => {
  describe('happy path', () => {
    it('keeps only scopes present in all three sets', () => {
      const result = intersectScopes(
        'mcp:read mcp:write',
        'mcp:read mcp:write',
        KNOWN_SCOPES
      );
      expect(result).toEqual(new Set(['mcp:read', 'mcp:write']));
    });

    it('returns subset when requested is narrower than registered', () => {
      const result = intersectScopes('mcp:read', 'mcp:read mcp:write', KNOWN_SCOPES);
      expect(result).toEqual(new Set(['mcp:read']));
    });
  });

  describe('elevation attempts blocked (mcp-vault B1 regression)', () => {
    it('rejects scope NOT registered, even if KNOWN', () => {
      // Client registered with only mcp:read, then asks for mcp:write.
      const result = intersectScopes('mcp:write', 'mcp:read', KNOWN_SCOPES);
      expect(result).toEqual(new Set());
    });

    it('rejects elevation to arbitrary scope (e.g. evil:scope)', () => {
      const result = intersectScopes(
        'mcp:read evil:scope',
        'mcp:read mcp:write',
        KNOWN_SCOPES
      );
      expect(result).toEqual(new Set(['mcp:read']));
    });

    it('rejects all unknown scopes even if requested AND registered', () => {
      // Misconfigured client somehow has unknown scope in registered list →
      // KNOWN filter is the last line of defense.
      const result = intersectScopes(
        'foo:bar mcp:read',
        'foo:bar mcp:read',
        KNOWN_SCOPES
      );
      expect(result).toEqual(new Set(['mcp:read']));
    });
  });

  describe('empty requested', () => {
    it('falls back to registered ∩ KNOWN per RFC 6749 §3.3 (empty request = grant registered)', () => {
      const result = intersectScopes('', 'mcp:read mcp:write', KNOWN_SCOPES);
      expect(result).toEqual(new Set(['mcp:read', 'mcp:write']));
    });

    it('still filters unknown registered scopes', () => {
      const result = intersectScopes('', 'mcp:read evil:scope', KNOWN_SCOPES);
      expect(result).toEqual(new Set(['mcp:read']));
    });
  });

  describe('explicit undefined requested (no scope query param)', () => {
    it('treats undefined like empty string — falls back to registered ∩ KNOWN', () => {
      const result = intersectScopes(undefined, 'mcp:read mcp:write', KNOWN_SCOPES);
      expect(result).toEqual(new Set(['mcp:read', 'mcp:write']));
    });
  });

  describe('empty intersection', () => {
    it('returns empty Set when requested ∩ registered is empty', () => {
      const result = intersectScopes('mcp:write', 'mcp:read', KNOWN_SCOPES);
      expect(result).toEqual(new Set());
    });

    it('returns empty Set when nothing is KNOWN', () => {
      const result = intersectScopes('foo:bar', 'foo:bar', new Set());
      expect(result).toEqual(new Set());
    });
  });

  describe('idempotence', () => {
    it('whitespace variations produce identical results', () => {
      const a = intersectScopes('mcp:read  mcp:write', 'mcp:write mcp:read', KNOWN_SCOPES);
      const b = intersectScopes('mcp:write mcp:read', 'mcp:read mcp:write', KNOWN_SCOPES);
      expect(serializeScope(a)).toBe(serializeScope(b));
    });
  });
});
