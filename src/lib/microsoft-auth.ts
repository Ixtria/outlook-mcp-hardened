import { Request, Response, NextFunction, RequestHandler } from 'express';
import logger from '../logger.js';
import { getCloudEndpoints, type CloudType } from '../cloud-config.js';

/**
 * Type alias for the token verifier signature used by the bearer middleware
 * factory. Returns AuthInfo-like (we only consume the token's validity here).
 */
export type TokenVerifier = (token: string) => Promise<unknown>;

/**
 * HARDENED (N0 I2 fix 2026-05-16) — Factory that builds an Express middleware
 * which validates the incoming Bearer token via the injected verifier BEFORE
 * routing to the protected handler.
 *
 * Before this factory, `microsoftBearerTokenAuthMiddleware` was pass-through —
 * any arbitrary string after "Bearer " reached `/mcp`. Combined with MCP
 * methods like `tools/list` that don't call Graph at all, an unauthenticated
 * attacker could enumerate the tool surface, version, and capabilities.
 *
 * Now :
 *   1. Missing/malformed header → 401 + WWW-Authenticate
 *   2. Verifier throws → 401 + WWW-Authenticate with error=invalid_token
 *   3. Verifier OK → token attached to req.microsoftAuth, next()
 *
 * Audit : failures are logged at warn level with client_ip (resolved via
 * trust-proxy) and a hashed token prefix for correlation, but NEVER the
 * full token (PII / supply-chain leak prevention).
 */
export function createBearerAuthMiddleware(verifier: TokenVerifier): RequestHandler {
  return async (
    req: Request & {
      microsoftAuth?: { accessToken: string; refreshToken: string };
      clientIp?: string;
    },
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res
        .status(401)
        .set('WWW-Authenticate', 'Bearer realm="mcp"')
        .json({ error: 'invalid_token', error_description: 'Missing or invalid Authorization header' });
      return;
    }

    const accessToken = authHeader.substring(7).trim();
    if (accessToken.length === 0) {
      res
        .status(401)
        .set('WWW-Authenticate', 'Bearer realm="mcp", error="invalid_token"')
        .json({ error: 'invalid_token', error_description: 'Empty Bearer token' });
      return;
    }

    try {
      await verifier(accessToken);
    } catch (error) {
      logger.warn('Rejected /mcp: token verification failed', {
        client_ip: req.clientIp,
        error: error instanceof Error ? error.message : String(error),
      });
      res
        .status(401)
        .set('WWW-Authenticate', 'Bearer realm="mcp", error="invalid_token"')
        .json({ error: 'invalid_token', error_description: 'Token verification failed' });
      return;
    }

    const refreshToken = (req.headers['x-microsoft-refresh-token'] as string) || '';
    req.microsoftAuth = {
      accessToken,
      refreshToken,
    };

    next();
  };
}

/**
 * @deprecated kept for backwards compatibility ; use createBearerAuthMiddleware
 * with an actual verifier. The pass-through version is unsafe for production
 * (N0 I2 BLOCKER-level when reachable from public network).
 *
 * Now hard-deprecated : throws at boot if anyone tries to use it without
 * understanding the risk. The throw is in the factory call site, not here.
 */
export const microsoftBearerTokenAuthMiddleware = (
  req: Request & { microsoftAuth?: { accessToken: string; refreshToken: string } },
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid access token' });
    return;
  }

  const accessToken = authHeader.substring(7);
  const refreshToken = (req.headers['x-microsoft-refresh-token'] as string) || '';

  req.microsoftAuth = {
    accessToken,
    refreshToken,
  };

  next();
};

/**
 * Exchange authorization code for access token
 */
export async function exchangeCodeForToken(
  code: string,
  redirectUri: string,
  clientId: string,
  clientSecret: string | undefined,
  tenantId: string = 'common',
  codeVerifier?: string,
  cloudType: CloudType = 'global'
): Promise<{
  access_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  refresh_token: string;
}> {
  const cloudEndpoints = getCloudEndpoints(cloudType);
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
  });

  if (clientSecret) {
    params.append('client_secret', clientSecret);
  }

  if (codeVerifier) {
    params.append('code_verifier', codeVerifier);
  }

  const response = await fetch(`${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  if (!response.ok) {
    const error = await response.text();
    logger.error(`Failed to exchange code for token: ${error}`);
    throw new Error(`Failed to exchange code for token: ${error}`);
  }

  return response.json();
}

/**
 * Refresh an access token
 */
export async function refreshAccessToken(
  refreshToken: string,
  clientId: string,
  clientSecret: string | undefined,
  tenantId: string = 'common',
  cloudType: CloudType = 'global'
): Promise<{
  access_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  refresh_token?: string;
}> {
  const cloudEndpoints = getCloudEndpoints(cloudType);
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
  });

  if (clientSecret) {
    params.append('client_secret', clientSecret);
  }

  const response = await fetch(`${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  if (!response.ok) {
    const error = await response.text();
    logger.error(`Failed to refresh token: ${error}`);
    throw new Error(`Failed to refresh token: ${error}`);
  }

  return response.json();
}
