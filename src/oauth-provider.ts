import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createHash } from 'node:crypto';
import logger from './logger.js';
import AuthManager from './auth.js';
import type { AppSecrets } from './secrets.js';
import { getCloudEndpoints, type CloudType } from './cloud-config.js';
import { allRegisteredRedirectUris } from './oauth/registered-clients.js';
import { auditLog } from './security/audit-logger.js';
import { EgressViolationError } from './security/egress-guard.js';

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
  // OBS-02 (2026-08-02) : wall time so the audit stream carries a latency
  // signal per Bearer verification. Alerting on p95(duration_ms) surfaces a
  // laggy Graph tenant before users complain.
  const started = Date.now();
  let response: Response;
  try {
    response = await fetch(`${cloudEndpoints.graphApi}/v1.0/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch (err) {
    // OBS-02 : the fetch itself failed (DNS, network, or the egress guard
    // synchronously threw EgressViolationError). Emit a dedicated
    // `oauth.egress.violation` line when the cause is a guard rejection so
    // operators can page on it distinctly from garden-variety network flakes.
    if (err instanceof EgressViolationError) {
      auditLog({
        tool: 'oauth.egress.violation',
        method: 'GET',
        path: err.url || `${cloudEndpoints.graphApi}/v1.0/me`,
        scopes: [],
        account: null,
        status: 0,
        duration_ms: Date.now() - started,
      });
    }
    auditLog({
      tool: 'oauth.mcp.reject',
      method: 'GET',
      path: '/mcp',
      scopes: [],
      account: null,
      status: 0,
      duration_ms: Date.now() - started,
    });
    throw err;
  }

  if (!response.ok) {
    // OBS-02 : Graph rejected the token (401/403/…). This is the hot
    // credential-stuffing signal — pair with rate limiting.
    auditLog({
      tool: 'oauth.mcp.reject',
      method: 'GET',
      path: '/mcp',
      scopes: [],
      account: null,
      status: response.status,
      duration_ms: Date.now() - started,
    });
    throw new Error(`Token verification failed: ${response.status}`);
  }

  const userData = await response.json();
  // HARDENED (N0-I1 fix): hash UPN before log to avoid PII leak.
  const upnHash = createHash('sha256')
    .update(String(userData.userPrincipalName ?? '').trim().toLowerCase())
    .digest('hex')
    .slice(0, 16);
  logger.info(`OAuth token verified (user_id_hash=sha256:${upnHash})`);

  // HARDENED (N4 B3 BLOCKER fix 2026-06-02): do NOT call
  // `authManager.setOAuthToken(token)` here. The previous code mutated
  // global AuthManager state (`oauthToken` field + `isOAuthMode=true`),
  // which under any multi-user HTTP scenario meant the LAST request to
  // succeed token verification clobbered the token used by ALL concurrent
  // subsequent tool invocations. Cross-user data leak vector.
  // The token is already propagated through AsyncLocalStorage via
  // `requestContext` (cf. src/request-context.ts), which is per-request
  // by construction. The global setOAuthToken was redundant + dangerous.
  // Single-user perso Jimmy is NOT impacted (no concurrent users), but
  // the OSS publication implicitly suggests HTTP multi-tenant via the
  // "trusted reverse proxy" wording in CLAUDE.md — fail closed here.
  void authManager; // keep param to preserve fn signature for callers

  // OBS-02 : successful verify. `account` carries the raw UPN — auditLog()
  // will HMAC-hash it via hashAccount() before writing to stderr, so no PII
  // hits the log file. `scopes=[]` reflects the ADR-0003 Niveau B stance
  // that we do not decode the JWT to extract scopes locally.
  auditLog({
    tool: 'oauth.mcp.request',
    method: 'GET',
    path: '/mcp',
    scopes: [],
    account:
      typeof userData.userPrincipalName === 'string' && userData.userPrincipalName
        ? userData.userPrincipalName
        : null,
    status: 200,
    duration_ms: Date.now() - started,
  });

  // HARDENED (N3 mcp-vault M2): `aud` is intentionally NOT validated locally
  // per ADR-0003 (Niveau B proxy pattern). AAD tokens target Graph by design.
  return {
    token,
    clientId,
    scopes: [],
  };
}

/**
 * OBS-02 (2026-08-02) : audit wrapper for the AAD token-exchange functions
 * (`exchangeCodeForToken`, `refreshAccessToken`). Preserves the exact call
 * signature of the wrapped function so it can be dropped into
 * `HardenedOAuthAppDeps.exchangeCode` / `.refreshToken` in `server.ts`
 * without touching `src/oauth/http-app.ts`.
 *
 * Contract :
 *   - On success : emit `oauth.token.request` with status=200 and the AAD-
 *     returned `scope` string decomposed into an array (empty if absent).
 *   - On EgressViolationError : emit `oauth.egress.violation` + a
 *     `oauth.token.reject` line with status=502.
 *   - On any other thrown error : emit `oauth.token.reject` with status=500.
 *   - The original error is re-thrown untouched so the /token handler's
 *     error path (server_error envelope) still runs.
 *
 * Sensitive fields (`code`, `code_verifier`, `refresh_token`, `access_token`,
 * `client_secret`) are NEVER read here — auditLog() only sees the numeric
 * status / duration / scope string.
 */
type TokenResponseLike = { scope?: unknown };

export function withTokenExchangeAudit<
  Args extends unknown[],
  R extends TokenResponseLike,
>(fn: (...args: Args) => Promise<R>): (...args: Args) => Promise<R> {
  return async (...args: Args): Promise<R> => {
    const started = Date.now();
    try {
      const result = await fn(...args);
      const scopes =
        typeof result?.scope === 'string'
          ? result.scope.split(/\s+/).filter((s) => s.length > 0)
          : [];
      auditLog({
        tool: 'oauth.token.request',
        method: 'POST',
        path: '/token',
        scopes,
        account: null,
        status: 200,
        duration_ms: Date.now() - started,
      });
      return result;
    } catch (err) {
      if (err instanceof EgressViolationError) {
        auditLog({
          tool: 'oauth.egress.violation',
          method: 'POST',
          path: err.url || '/token',
          scopes: [],
          account: null,
          status: 0,
          duration_ms: Date.now() - started,
        });
        auditLog({
          tool: 'oauth.token.reject',
          method: 'POST',
          path: '/token',
          scopes: [],
          account: null,
          status: 502,
          duration_ms: Date.now() - started,
        });
      } else {
        auditLog({
          tool: 'oauth.token.reject',
          method: 'POST',
          path: '/token',
          scopes: [],
          account: null,
          status: 500,
          duration_ms: Date.now() - started,
        });
      }
      throw err;
    }
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
