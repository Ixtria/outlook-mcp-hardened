import { describe, expect, it } from 'vitest';
import {
  allRegisteredRedirectUris,
  allRegisteredScopes,
  getRegisteredClient,
} from '../registered-clients.js';
import { validateRedirectUri } from '../redirect-uri.js';

describe('registered-clients', () => {
  describe('Claude.ai entry', () => {
    it('exposes Claude.ai callbacks exactly', () => {
      const claude = getRegisteredClient('claude');
      expect(claude).toBeDefined();
      expect(claude?.redirectUris.has('https://claude.ai/api/mcp/auth_callback')).toBe(true);
      expect(claude?.redirectUris.has('https://claude.com/api/mcp/auth_callback')).toBe(true);
    });

    it('does NOT expose wildcard or subdomain variants', () => {
      const claude = getRegisteredClient('claude');
      expect(claude?.redirectUris.has('https://*.claude.ai/api/mcp/auth_callback')).toBe(false);
      expect(claude?.redirectUris.has('https://evil.claude.ai/api/mcp/auth_callback')).toBe(false);
    });

    it('lists Outlook scopes only (no Files.Read, no Sharepoint, no Teams)', () => {
      const claude = getRegisteredClient('claude');
      expect(claude?.allowedScopes.has('Mail.Read')).toBe(true);
      expect(claude?.allowedScopes.has('Calendars.Read')).toBe(true);
      // Codex N1-I2 regression — Files.Read MUST NOT be in the allowlist
      expect(claude?.allowedScopes.has('Files.Read')).toBe(false);
      expect(claude?.allowedScopes.has('Sites.Read.All')).toBe(false);
      expect(claude?.allowedScopes.has('Team.ReadBasic.All')).toBe(false);
    });
  });

  describe('getRegisteredClient', () => {
    it('returns undefined for unknown client', () => {
      expect(getRegisteredClient('unknown')).toBeUndefined();
      expect(getRegisteredClient('')).toBeUndefined();
    });
  });

  describe('integration with validateRedirectUri', () => {
    it('accepts Claude.ai exact-match redirect', () => {
      expect(
        validateRedirectUri(
          'https://claude.ai/api/mcp/auth_callback',
          allRegisteredRedirectUris()
        )
      ).toBe(true);
    });

    it('rejects any subdomain variant (codex B1 regression)', () => {
      expect(
        validateRedirectUri(
          'https://evil.claude.ai/api/mcp/auth_callback',
          allRegisteredRedirectUris()
        )
      ).toBe(false);
    });

    it('rejects userinfo bypass (N0-B1 regression)', () => {
      expect(
        validateRedirectUri(
          'https://attacker@claude.ai/api/mcp/auth_callback',
          allRegisteredRedirectUris()
        )
      ).toBe(false);
    });
  });

  describe('allRegisteredScopes', () => {
    it('excludes Files.Read (codex N1-I2 regression)', () => {
      expect(allRegisteredScopes().has('Files.Read')).toBe(false);
    });

    it('includes Mail/Calendar scopes', () => {
      expect(allRegisteredScopes().has('Mail.Read')).toBe(true);
      expect(allRegisteredScopes().has('Calendars.Read')).toBe(true);
    });
  });
});
