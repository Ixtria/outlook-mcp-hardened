import { describe, expect, it } from 'vitest';
import {
  allRegisteredRedirectUris,
  allRegisteredScopes,
  getRegisteredClient,
  META_SCOPES,
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

    it('includes Mail.ReadWrite for --enable-send write tools (N0 I1 fix)', () => {
      expect(allRegisteredScopes().has('Mail.ReadWrite')).toBe(true);
    });
  });

  describe('META_SCOPES (N0 BLOCKER B1 + IMPORTANT I2 fix)', () => {
    it('contains offline_access (refresh token meta-scope)', () => {
      expect(META_SCOPES.has('offline_access')).toBe(true);
    });

    it('contains User.Read for /me userinfo + multi-account', () => {
      expect(META_SCOPES.has('User.Read')).toBe(true);
    });

    it('contains openid + profile for OIDC compliance', () => {
      expect(META_SCOPES.has('openid')).toBe(true);
      expect(META_SCOPES.has('profile')).toBe(true);
    });

    it('all META_SCOPES are also in CLAUDE_AI_ALLOWED_SCOPES (invariant)', () => {
      const registered = allRegisteredScopes();
      for (const meta of META_SCOPES) {
        expect(registered.has(meta), `${meta} missing from registered`).toBe(true);
      }
    });

    it('does NOT contain Graph permission scopes (those go through KNOWN filter)', () => {
      expect(META_SCOPES.has('Mail.Read')).toBe(false);
      expect(META_SCOPES.has('Mail.ReadWrite')).toBe(false);
      expect(META_SCOPES.has('Calendars.Read')).toBe(false);
    });
  });
});
