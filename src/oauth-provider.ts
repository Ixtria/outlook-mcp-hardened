import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createHash } from 'node:crypto';
import logger from './logger.js';
import AuthManager from './auth.js';
import type { AppSecrets } from './secrets.js';
import { getCloudEndpoints } from './cloud-config.js';
import { allRegisteredRedirectUris } from './oauth/registered-clients.js';

export class MicrosoftOAuthProvider extends ProxyOAuthServerProvider {
  private authManager: AuthManager;

  constructor(authManager: AuthManager, secrets: AppSecrets) {
    const tenantId = secrets.tenantId || 'common';
    const clientId = secrets.clientId;
    const cloudEndpoints = getCloudEndpoints(secrets.cloudType);

    super({
      endpoints: {
        authorizationUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/authorize`,
        tokenUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`,
        revocationUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/logout`,
      },
      verifyAccessToken: async (token: string): Promise<AuthInfo> => {
        try {
          const response = await fetch(`${cloudEndpoints.graphApi}/v1.0/me`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          });

          if (response.ok) {
            const userData = await response.json();
            // HARDENED (N3 mcp-vault M2 2026-05-16): hash UPN before log to
            // avoid PII leak in audit trail. The raw email was previously
            // emitted to stderr at every token verification.
            const upnHash = createHash('sha256')
              .update(String(userData.userPrincipalName ?? '').trim().toLowerCase())
              .digest('hex')
              .slice(0, 16);
            logger.info(`OAuth token verified (user_id_hash=sha256:${upnHash})`);

            await authManager.setOAuthToken(token);

            // HARDENED (N3 mcp-vault M2 2026-05-16): `aud` is intentionally
            // NOT validated locally. Per ADR-0003 (Niveau B, OAuth proxy
            // pattern), AAD-issued tokens target Graph (aud=https://graph
            // .microsoft.com) — that's expected, the token is meant to be
            // relayed to Graph by this server. Adding local aud=our-mcp
            // validation here would break the entire flow. RFC 8707 strict
            // compliance is out of scope per ADR-0003 D2.
            return {
              token,
              clientId,
              scopes: [],
            };
          } else {
            throw new Error(`Token verification failed: ${response.status}`);
          }
        } catch (error) {
          logger.error(`OAuth token verification error: ${error}`);
          throw error;
        }
      },
      // HARDENED (N3 mcp-vault C1 CRITICAL 2026-05-16): wire the static
      // registered-clients allowlist into the SDK provider. The previous
      // hardcoded `redirect_uris: ['http://localhost:3000/callback']` meant
      // any code path inside @modelcontextprotocol/sdk that consulted
      // getClient() for redirect_uri validation would silently bypass our
      // exact-match allowlist (src/oauth/registered-clients.ts). We hand
      // the SDK the same source of truth our hand-rolled /register and
      // /authorize handlers use, so a refactor that swaps which router
      // owns a route cannot regress security.
      getClient: async (client_id: string) => {
        return {
          client_id,
          redirect_uris: [...allRegisteredRedirectUris()],
        };
      },
    });

    this.authManager = authManager;
  }
}
