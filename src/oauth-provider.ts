import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createHash } from 'node:crypto';
import logger from './logger.js';
import AuthManager from './auth.js';
import type { AppSecrets } from './secrets.js';
import { getCloudEndpoints, type CloudType } from './cloud-config.js';
import { allRegisteredRedirectUris } from './oauth/registered-clients.js';

/**
 * Standalone Microsoft access-token verifier.
 *
 * Resolves N0 review IMPORTANT I2 (conf 86, 2026-05-16): the /mcp endpoint
 * previously accepted any string-shaped Bearer header without validation
 * (microsoftBearerTokenAuthMiddleware was pass-through). This function is
 * called by BOTH the SDK provider (via `verifyAccessToken` callback) AND
 * the new /mcp middleware (`createBearerAuthMiddleware`), guaranteeing
 * uniform validation regardless of which router handles the request.
 *
 * Verification strategy : delegate to Microsoft Graph `/me`. If the token
 * is invalid (expired, revoked, wrong audience), Graph returns 401 and we
 * throw. This is the proxy-pattern's authoritative check — we don't
 * decode the JWT ourselves because:
 *   1. AAD-issued tokens target `aud=https://graph.microsoft.com`, not us
 *      (ADR-0003 D2 accepted limitation, RFC 8707 strict compliance out
 *      of scope for Niveau B proxy)
 *   2. Graph `/me` returns immediately on revoked tokens (no JWT-cache
 *      delay)
 *
 * Performance note : adds one round-trip to `graph.microsoft.com` per
 * incoming /mcp request. Mitigation : caller may wrap in a short-TTL cache
 * (60s) at the middleware level if latency becomes an issue. Not done
 * here — correctness > perf, and Graph latency is typically <100ms.
 *
 * PII protection : the user's UPN (email) is hashed before any log emission
 * (N0-I1 fix).
 */
export async function verifyMicrosoftAccessToken(
  token: string,
  cloudType: CloudType,
  clientId: string,
  authManager: AuthManager
): Promise<AuthInfo> {
  const cloudEndpoints = getCloudEndpoints(cloudType);
  const response = await fetch(`${cloudEndpoints.graphApi}/v1.0/me`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Token verification failed: ${response.status}`);
  }

  const userData = await response.json();
  // HARDENED (N0-I1 fix): hash UPN before log to avoid PII leak.
  const upnHash = createHash('sha256')
    .update(String(userData.userPrincipalName ?? '').trim().toLowerCase())
    .digest('hex')
    .slice(0, 16);
  logger.info(`OAuth token verified (user_id_hash=sha256:${upnHash})`);

  await authManager.setOAuthToken(token);

  // HARDENED (N3 mcp-vault M2): `aud` is intentionally NOT validated locally
  // per ADR-0003 (Niveau B proxy pattern). AAD tokens target Graph by design.
  return {
    token,
    clientId,
    scopes: [],
  };
}

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
      verifyAccessToken: (token) =>
        verifyMicrosoftAccessToken(token, secrets.cloudType, clientId, authManager).catch(
          (error) => {
            logger.error(`OAuth token verification error: ${error}`);
            throw error;
          }
        ),
      // HARDENED (N3 mcp-vault C1 CRITICAL 2026-05-16): wire the static
      // registered-clients allowlist into the SDK provider. Defense in depth
      // for any SDK path that consults getClient() for redirect_uri validation.
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
