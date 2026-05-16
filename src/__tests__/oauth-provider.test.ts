import { describe, expect, it, vi } from 'vitest';
import { MicrosoftOAuthProvider } from '../oauth-provider.js';
import { allRegisteredRedirectUris } from '../oauth/registered-clients.js';
import type AuthManager from '../auth.js';

vi.mock('../logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const mockAuthManager = { setOAuthToken: vi.fn() } as unknown as AuthManager;

const mockSecrets = {
  clientId: 'test-client-id',
  tenantId: 'common',
  cloudType: 'global' as const,
};

describe('MicrosoftOAuthProvider.getClient (N3 mcp-vault C1 CRITICAL regression)', () => {
  it('returns the registered-clients allowlist, NOT a hardcoded localhost callback', async () => {
    const provider = new MicrosoftOAuthProvider(mockAuthManager, mockSecrets);
    const client = await provider.clientsStore.getClient('any-client-id');
    expect(client).toBeDefined();
    expect(client?.redirect_uris).toEqual([...allRegisteredRedirectUris()]);
    // Regression assertion : the hardcoded localhost must NEVER appear here
    expect(client?.redirect_uris).not.toContain('http://localhost:3000/callback');
  });

  it('returned redirect_uris contains exactly Claude.ai entries', async () => {
    const provider = new MicrosoftOAuthProvider(mockAuthManager, mockSecrets);
    const client = await provider.clientsStore.getClient('mcp-client-12345');
    expect(client?.redirect_uris).toContain('https://claude.ai/api/mcp/auth_callback');
    expect(client?.redirect_uris).toContain('https://claude.com/api/mcp/auth_callback');
  });

  it('returned redirect_uris does NOT contain wildcard or subdomain variants', async () => {
    const provider = new MicrosoftOAuthProvider(mockAuthManager, mockSecrets);
    const client = await provider.clientsStore.getClient('test');
    const uris = client?.redirect_uris ?? [];
    expect(uris.some((u) => u.includes('*'))).toBe(false);
    expect(uris.some((u) => u.startsWith('http://'))).toBe(false); // https only
    expect(uris.some((u) => /\bevil\b|attacker/.test(u))).toBe(false);
  });

  it('returns same allowlist regardless of provided client_id (proxy pattern)', async () => {
    // ADR-0003 : we do not persist DCR clients. Every client_id maps to the
    // same static allowlist of trusted callbacks.
    const provider = new MicrosoftOAuthProvider(mockAuthManager, mockSecrets);
    const a = await provider.clientsStore.getClient('mcp-client-1');
    const b = await provider.clientsStore.getClient('mcp-client-2');
    const c = await provider.clientsStore.getClient('attacker-forged-id');
    expect(a?.redirect_uris).toEqual(b?.redirect_uris);
    expect(b?.redirect_uris).toEqual(c?.redirect_uris);
  });

  it('client_id is echoed back as-is (SDK contract)', async () => {
    const provider = new MicrosoftOAuthProvider(mockAuthManager, mockSecrets);
    const client = await provider.clientsStore.getClient('whatever-id');
    expect(client?.client_id).toBe('whatever-id');
  });
});
