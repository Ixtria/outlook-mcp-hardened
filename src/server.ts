import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import express, { Request, Response } from 'express';
import logger, { enableConsoleLogging } from './logger.js';
import { registerAuthTools } from './auth-tools.js';
import { registerGraphTools, registerDiscoveryTools } from './graph-tools.js';
import GraphClient from './graph-client.js';
import AuthManager, { buildScopesFromEndpoints } from './auth.js';
import { MicrosoftOAuthProvider, verifyMicrosoftAccessToken } from './oauth-provider.js';
import {
  createBearerAuthMiddleware,
  exchangeCodeForToken,
  refreshAccessToken,
} from './lib/microsoft-auth.js';
import type { CommandOptions } from './cli.ts';
import { getSecrets, type AppSecrets } from './secrets.js';
import { getCloudEndpoints } from './cloud-config.js';
import { requestContext, parseTrustedProxiesEnv } from './request-context.js';
import { allRegisteredRedirectUris, allRegisteredScopes } from './oauth/registered-clients.js';
import {
  computeEffectiveScope,
  createRegisterHandler,
  validateAuthorizeRedirectUri,
} from './oauth/http-routes.js';
import { resolveClientIp } from './lib/trust-proxy.js';
import crypto from 'node:crypto';

/**
 * Maximum PKCE store size (N0 B2 BLOCKER fix 2026-05-16). The store is keyed
 * by attacker-controlled `state`, so we cap the Map to prevent unbounded
 * memory growth from flood attacks. When full, the oldest entry is evicted.
 * 10_000 × ~250 bytes ≈ 2.5 MB upper bound on store memory.
 */
const MAX_PKCE_STORE_SIZE = 10_000;

/**
 * Maximum `state` parameter length (N0 B2 BLOCKER fix 2026-05-16). Bounds the
 * attacker's ability to pad state with megabytes of data. 256 chars is well
 * above any legitimate use (typical OAuth state is 32-64 bytes of entropy).
 */
const MAX_STATE_LENGTH = 256;

/**
 * Periodic pkceStore sweep interval (N0 B2 BLOCKER fix). The original
 * eviction-on-insert pattern leaked entries if /authorize traffic stopped
 * after a flood. This interval-driven sweep runs every minute regardless
 * of request volume.
 */
const PKCE_SWEEP_INTERVAL_MS = 60_000;

/**
 * pkceStore entry TTL (10 minutes). OAuth authorization codes are exchanged
 * within seconds in practice; 10 min is generous slack for slow consent UX.
 */
const PKCE_ENTRY_TTL_MS = 10 * 60 * 1000;

/**
 * Parse HTTP option into host and port components.
 * Supports formats: "host:port", ":port", "port"
 * @param httpOption - The HTTP option value (string or boolean)
 * @returns Object with host (undefined if not specified) and port number
 */
function parseHttpOption(httpOption: string | boolean): { host: string | undefined; port: number } {
  // HARDENED: default bind to 127.0.0.1 instead of all interfaces. An
  // operator who wants to expose the server externally must say so
  // explicitly (e.g. --http 0.0.0.0:3000 behind a trusted reverse proxy).
  if (typeof httpOption === 'boolean') {
    return { host: '127.0.0.1', port: 3000 };
  }

  const httpString = httpOption.trim();

  // Check if it contains a colon (host:port format)
  if (httpString.includes(':')) {
    const [hostPart, portPart] = httpString.split(':');
    const host = hostPart || '127.0.0.1'; // Empty host defaults to localhost
    const port = parseInt(portPart ?? '') || 3000;
    return { host, port };
  }

  // No colon, treat as port only, still default to localhost
  const port = parseInt(httpString) || 3000;
  return { host: '127.0.0.1', port };
}

class MicrosoftGraphServer {
  private authManager: AuthManager;
  private options: CommandOptions;
  private graphClient: GraphClient | null;
  private server: McpServer | null;
  private secrets: AppSecrets | null;
  private version: string = '0.0.0';
  private multiAccount: boolean = false;
  private accountNames: string[] = [];

  // Two-leg PKCE: stores client's code_challenge and server's code_verifier, keyed by OAuth state
  private pkceStore: Map<
    string,
    {
      clientCodeChallenge: string;
      clientCodeChallengeMethod: string;
      serverCodeVerifier: string;
      createdAt: number;
    }
  > = new Map();

  constructor(authManager: AuthManager, options: CommandOptions = {}) {
    this.authManager = authManager;
    this.options = options;
    this.graphClient = null; // Initialized in start() after secrets are loaded
    this.server = null;
    this.secrets = null;
  }

  private createMcpServer(): McpServer {
    const server = new McpServer({
      name: 'Microsoft365MCP',
      version: this.version,
    });

    const shouldRegisterAuthTools = !this.options.http || this.options.enableAuthTools;
    if (shouldRegisterAuthTools) {
      registerAuthTools(server, this.authManager);
    }

    // HARDENED: read-first policy — derive writePolicy from CLI opts.
    const writePolicy = {
      mail: !!this.options.enableSend,
      calendar: !!this.options.enableWrite,
    };
    if (this.options.discovery) {
      registerDiscoveryTools(
        server,
        this.graphClient!,
        this.options.readOnly,
        this.options.orgMode,
        this.authManager,
        this.multiAccount,
        writePolicy
      );
    } else {
      registerGraphTools(
        server,
        this.graphClient!,
        this.options.readOnly,
        this.options.enabledTools,
        this.options.orgMode,
        this.authManager,
        this.multiAccount,
        this.accountNames,
        writePolicy
      );
    }

    return server;
  }

  async initialize(version: string): Promise<void> {
    this.secrets = await getSecrets();
    this.version = version;

    // Detect multi-account mode and cache account names for schema enum
    try {
      this.multiAccount = await this.authManager.isMultiAccount();
      if (this.multiAccount) {
        const accounts = await this.authManager.listAccounts();
        this.accountNames = accounts.map((a) => a.username).filter((u): u is string => !!u);
        logger.info(
          `Multi-account mode detected (${this.accountNames.length} accounts): "account" parameter will be injected into all tool schemas`
        );
      }
    } catch (err) {
      logger.warn(`Failed to detect multi-account mode: ${(err as Error).message}`);
    }

    // HARDENED: TOON output format removed; JSON-only.
    this.graphClient = new GraphClient(this.authManager, this.secrets);

    if (!this.options.http) {
      this.server = this.createMcpServer();
    }

    if (this.options.discovery) {
      logger.info('Discovery mode enabled (experimental) - registering discovery tool only');
    }
  }

  async start(): Promise<void> {
    if (this.options.v) {
      enableConsoleLogging();
    }

    logger.info('Microsoft 365 MCP Server starting...');

    // Debug: Check if secrets are loaded
    logger.info('Secrets Check:', {
      CLIENT_ID: this.secrets?.clientId ? `${this.secrets.clientId.substring(0, 8)}...` : 'NOT SET',
      CLIENT_SECRET: this.secrets?.clientSecret ? 'SET' : 'NOT SET',
      TENANT_ID: this.secrets?.tenantId || 'NOT SET',
      NODE_ENV: process.env.NODE_ENV || 'NOT SET',
    });

    if (this.options.readOnly) {
      logger.info('Server running in READ-ONLY mode. Write operations are disabled.');
    }

    if (this.options.http) {
      const { host, port } = parseHttpOption(this.options.http);

      // HARDENED (ADR-0003 D6 + N0 I3 + N0 I6 boot guards 2026-05-16):
      //
      // 1. Non-loopback bind requires `OUTLOOK_MCP_TRUSTED_PROXIES` (XFF
      //    attribution + req.secure semantics behind TLS terminator).
      // 2. Non-loopback bind requires `OUTLOOK_MCP_PUBLIC_URL` (RFC 8414 §2
      //    forbids reflecting Host header into `issuer` — that's the N0 I3
      //    finding). The URL must be `https://...` for non-loopback deploys.
      // 3. `OUTLOOK_MCP_CORS_ORIGIN=*` is a footgun (N0 I6) — refuse boot
      //    unless `OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true` is also set, an
      //    explicit opt-in that survives operator review.
      const hasTrustedProxies =
        parseTrustedProxiesEnv(process.env.OUTLOOK_MCP_TRUSTED_PROXIES).size > 0;
      const publicUrl = process.env.OUTLOOK_MCP_PUBLIC_URL ?? this.options.baseUrl;
      const isLoopbackBind = host === '127.0.0.1' || host === '::1' || host === 'localhost';

      if (!isLoopbackBind && !hasTrustedProxies) {
        const msg =
          `Refusing to start HTTP server bound to "${host}" without ` +
          `OUTLOOK_MCP_TRUSTED_PROXIES. Set the env var to the comma-separated ` +
          `list of trusted reverse-proxy IPs, or bind to 127.0.0.1. ` +
          `See docs/adr/0003-pivot-niveau-b-oauth-proxy-hardened.md D6 and ` +
          `docs/MODES.md "http-public".`;
        logger.error(msg);
        throw new Error(msg);
      }

      if (!isLoopbackBind && !publicUrl) {
        const msg =
          `Refusing to start HTTP server bound to "${host}" without ` +
          `OUTLOOK_MCP_PUBLIC_URL. Discovery endpoints (/.well-known/oauth-*) ` +
          `MUST advertise the public https:// origin, not the Host header ` +
          `(RFC 8414 §2). Set OUTLOOK_MCP_PUBLIC_URL=https://mcp.example.com`;
        logger.error(msg);
        throw new Error(msg);
      }

      if (publicUrl && !isLoopbackBind && !publicUrl.startsWith('https://')) {
        const msg =
          `OUTLOOK_MCP_PUBLIC_URL must use https:// for non-loopback deployments ` +
          `(got: "${publicUrl}"). RFC 8414 §2 + RFC 9728 §3.1 require https:// issuers.`;
        logger.error(msg);
        throw new Error(msg);
      }

      if (
        process.env.OUTLOOK_MCP_CORS_ORIGIN === '*' &&
        process.env.OUTLOOK_MCP_CORS_ALLOW_WILDCARD !== 'true'
      ) {
        const msg =
          `Refusing to start with OUTLOOK_MCP_CORS_ORIGIN=* — wildcard CORS to ` +
          `a Bearer-protected resource is a footgun. If you really need it, ` +
          `set OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true to acknowledge the risk.`;
        logger.error(msg);
        throw new Error(msg);
      }

      // HARDENED (N0 B2 BLOCKER fix 2026-05-16): interval-driven pkceStore
      // sweep. Independent of request volume, so the store cannot accumulate
      // stale entries after a flood subsides.
      const pkceSweepHandle = setInterval(() => {
        const now = Date.now();
        let evicted = 0;
        for (const [key, value] of this.pkceStore) {
          if (now - value.createdAt > PKCE_ENTRY_TTL_MS) {
            this.pkceStore.delete(key);
            evicted++;
          }
        }
        if (evicted > 0) {
          logger.info(`pkceStore: swept ${evicted} expired entries`);
        }
      }, PKCE_SWEEP_INTERVAL_MS);
      pkceSweepHandle.unref(); // do not keep the event loop alive solely for this

      const app = express();
      // HARDENED (ADR-0003 D6, codex N1-B1 conf 96 + N0-B2 conf 92):
      // Replace permissive `trust proxy=true` (which trusts XFF from any peer)
      // with an explicit operator-managed IP allowlist. Express semantics:
      //   - `false` → ignore ALL X-Forwarded-* (used when no proxy is configured)
      //   - `string[] of IPs` → trust those IPs only; preserves `req.secure`
      //     correctly via X-Forwarded-Proto, which the discovery endpoints
      //     need to emit `https://` issuers behind a TLS-terminating proxy
      //     (N0-B2 RFC 8414 §2 / RFC 9728 §3.1).
      const trustedProxies = parseTrustedProxiesEnv(process.env.OUTLOOK_MCP_TRUSTED_PROXIES);
      if (trustedProxies.size > 0) {
        app.set('trust proxy', [...trustedProxies]);
      } else {
        app.set('trust proxy', false);
      }
      app.use((req, _res, next) => {
        const socketIp = req.socket.remoteAddress ?? '';
        const xff = req.headers['x-forwarded-for'];
        // Express collapses duplicate headers; in practice this is a string.
        const xffString = Array.isArray(xff) ? xff.join(', ') : xff;
        const clientIp = resolveClientIp(socketIp, xffString, trustedProxies);
        (req as Request & { clientIp?: string }).clientIp = clientIp;
        next();
      });
      // HARDENED (N0 B3 BLOCKER fix 2026-05-16): explicit body size + parser
      // safety. OAuth requests are tiny (a few KB at most). `extended: false`
      // uses Node's safer `querystring` parser (no qs prototype-pollution
      // surface). `parameterLimit: 20` is well above any legitimate use.
      app.use(express.json({ limit: '10kb' }));
      app.use(express.urlencoded({ extended: false, limit: '10kb', parameterLimit: 20 }));

      // HARDENED (N0 I5 + I6 fix 2026-05-16):
      //
      // CORS posture : DEFAULT-DENY. MCP clients (Claude Desktop, Claude Code,
      // mcp-inspector) are NOT browsers — they don't apply SOP and don't need
      // CORS approval. Allowing CORS to a Bearer-protected resource only
      // helps browser-context attackers chain "exfiltrated Bearer token →
      // cross-origin call to /mcp" (codex-style threat model, see N0 I5).
      //
      // I5 fix : the previous port-agnostic localhost allowlist matched
      // `http://localhost:1337` against `http://localhost` — any local app
      // (malicious Electron, browser extension) on any port reflected as
      // valid origin. Now we either deny entirely (default) or accept ONLY
      // the exact origin string the operator listed.
      //
      // I6 fix : '*' is now refused at boot (above) unless the operator
      // explicitly opts in via OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true.
      const configuredOrigin = process.env.OUTLOOK_MCP_CORS_ORIGIN;

      app.use((req, res, next) => {
        const requestOrigin = req.headers.origin;
        let allowOrigin: string | null = null;

        if (configuredOrigin === '*') {
          // Wildcard explicitly approved via OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true
          // (else boot refused above). In wildcard mode the browser refuses
          // to send Authorization anyway, so Allow-Headers MUST exclude it.
          allowOrigin = '*';
        } else if (configuredOrigin && requestOrigin === configuredOrigin) {
          // Exact-origin match. Includes port + path-less host (origin is
          // always scheme://host:port per RFC 6454).
          allowOrigin = requestOrigin;
        }
        // No fallback to "localhost any port" — that was N0 I5.

        if (allowOrigin) {
          res.header('Access-Control-Allow-Origin', allowOrigin);
          if (allowOrigin !== '*') {
            res.header('Vary', 'Origin');
          }
        }
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        // Allow-Headers : Authorization included EXCEPT in wildcard mode
        // (the browser would refuse to send it with '*' anyway, but some
        // non-browser clients honor '*' — we make the contract explicit).
        const allowHeaders =
          allowOrigin === '*'
            ? 'Origin, X-Requested-With, Content-Type, Accept, mcp-protocol-version'
            : 'Origin, X-Requested-With, Content-Type, Accept, Authorization, mcp-protocol-version';
        res.header('Access-Control-Allow-Headers', allowHeaders);

        if (req.method === 'OPTIONS') {
          res.sendStatus(allowOrigin ? 200 : 403);
          return;
        }

        next();
      });

      // HARDENED (ADR-0003): writePolicy resolved here for /authorize scope
      // intersection. Same shape as the createMcpServer() local — kept in sync
      // because the HTTP handler needs it without coupling to createMcpServer's
      // scope.
      const httpWritePolicy = {
        mail: !!this.options.enableSend,
        calendar: !!this.options.enableWrite,
      };

      // HARDENED (N0-I3 conf 82): hoist once. Static registry → safe to cache
      // for the lifetime of the HTTP server. Avoids per-request Set rebuild
      // and ensures /register and /authorize see the exact same view.
      const allowedRedirectUris = allRegisteredRedirectUris();
      const registeredScopesString = [...allRegisteredScopes()].join(' ');

      const oauthProvider = new MicrosoftOAuthProvider(this.authManager, this.secrets!);

      // HARDENED (N0 I2 fix 2026-05-16): /mcp Bearer middleware now VALIDATES
      // the token via the same verifier as the SDK provider (Graph /me round-
      // trip). Before this fix, the middleware was pass-through — any string
      // after "Bearer " reached the MCP route handlers, exposing tools/list
      // and other MCP utility methods to unauthenticated enumeration.
      const secrets = this.secrets!;
      const authManager = this.authManager;
      const bearerAuthMiddleware = createBearerAuthMiddleware(async (token) => {
        await verifyMicrosoftAccessToken(token, secrets.cloudType, secrets.clientId, authManager);
      });

      // OAuth Authorization Server Discovery
      app.get('/.well-known/oauth-authorization-server', async (req, res) => {
        // HARDENED (N0 I3 fix 2026-05-16): prefer OUTLOOK_MCP_PUBLIC_URL over
        // reflected Host header. RFC 8414 §2 forbids non-https issuers; the
        // Host header is attacker-controlled and may be empty/spoofed.
        // Boot guard above ensures publicUrl is present + https:// for any
        // non-loopback bind, so this fallback to req.get('host') only fires
        // for safe local dev contexts.
        const url = publicUrl
          ? new URL(publicUrl)
          : new URL(`${req.secure ? 'https' : 'http'}://${req.get('host')}`);
        res.set('Cache-Control', 'no-store'); // N0 I3 — prevent CDN caching wrong issuer

        const scopes = buildScopesFromEndpoints(this.options.orgMode, this.options.enabledTools);

        const metadata: Record<string, unknown> = {
          issuer: url.origin,
          authorization_endpoint: `${url.origin}/authorize`,
          token_endpoint: `${url.origin}/token`,
          response_types_supported: ['code'],
          response_modes_supported: ['query'],
          grant_types_supported: ['authorization_code', 'refresh_token'],
          token_endpoint_auth_methods_supported: ['none'],
          code_challenge_methods_supported: ['S256'],
          scopes_supported: scopes,
        };

        if (this.options.enableDynamicRegistration) {
          metadata.registration_endpoint = `${url.origin}/register`;
        }

        res.json(metadata);
      });

      // OAuth Protected Resource Discovery
      app.get('/.well-known/oauth-protected-resource', async (req, res) => {
        // HARDENED (N0 I3 fix 2026-05-16): same as oauth-authorization-server
        // discovery — prefer OUTLOOK_MCP_PUBLIC_URL.
        const url = publicUrl
          ? new URL(publicUrl)
          : new URL(`${req.secure ? 'https' : 'http'}://${req.get('host')}`);
        res.set('Cache-Control', 'no-store');

        const scopes = buildScopesFromEndpoints(this.options.orgMode, this.options.enabledTools);

        res.json({
          resource: `${url.origin}/mcp`,
          authorization_servers: [url.origin],
          scopes_supported: scopes,
          bearer_methods_supported: ['header'],
          resource_documentation: `${url.origin}`,
        });
      });

      if (this.options.enableDynamicRegistration) {
        // HARDENED (ADR-0003 D2, codex N1-B2 conf 94): /register handler
        // extracted into src/oauth/http-routes.ts for unit-testable wiring
        // (N0-O3 cross-review). Allowlist + logger injected as deps.
        app.post(
          '/register',
          createRegisterHandler({ allowedRedirectUris, logger })
        );
      }

      // HARDENED (N4 B2 BLOCKER fix 2026-06-02): refuse POST /authorize
      // outright. OAuth 2.0 RFC 6749 §3.1 says the authorization endpoint
      // MUST support GET; POST is optional. We support only GET and reject
      // POST with 405. Why : the SDK mcpAuthRouter mounted below catches
      // POST /authorize and (a) doesn't validate client_id against our
      // registered-clients allowlist, (b) doesn't enforce scope intersection,
      // (c) doesn't enforce PKCE — all of which our hand-rolled GET handler
      // does. Without this 405 interceptor, an attacker bypasses ALL our
      // hardening by sending POST instead of GET.
      app.post('/authorize', (req, res) => {
        logger.warn('Rejected POST /authorize (only GET is supported)', {
          client_ip: (req as Request & { clientIp?: string }).clientIp,
        });
        res
          .status(405)
          .set('Allow', 'GET')
          .type('text/plain')
          .send(
            'method_not_allowed: /authorize accepts GET only. POST bypasses required PKCE+scope validation.'
          );
      });

      // Authorization endpoint - redirects to Microsoft
      // Implements two-leg PKCE: client↔server and server↔Microsoft are independent
      app.get('/authorize', async (req, res) => {
        const url = new URL(req.url!, `${req.protocol}://${req.get('host')}`);
        const tenantId = this.secrets?.tenantId || 'common';
        const clientId = this.secrets!.clientId;
        const cloudEndpoints = getCloudEndpoints(this.secrets!.cloudType);
        const microsoftAuthUrl = new URL(
          `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/authorize`
        );

        // HARDENED (ADR-0003 D2, codex B1 + I2): validate redirect_uri via
        // extracted helper. Errors are LOCAL (no Location header) — anti
        // open-redirect (codex I2).
        const redirectCheck = validateAuthorizeRedirectUri(
          url.searchParams.get('redirect_uri'),
          allowedRedirectUris
        );
        if (!redirectCheck.ok) {
          if (redirectCheck.reason === 'not_in_allowlist') {
            logger.warn('Rejected /authorize: redirect_uri not in allowlist', {
              client_ip: (req as Request & { clientIp?: string }).clientIp,
            });
          }
          res
            .status(400)
            .type('text/plain')
            .send(
              redirectCheck.reason === 'missing'
                ? 'invalid_request: redirect_uri is required'
                : 'invalid_request: redirect_uri is not in the registered-clients allowlist'
            );
          return;
        }

        // Extract client's PKCE parameters (from claude.ai or other MCP client)
        const clientCodeChallenge = url.searchParams.get('code_challenge');
        const clientCodeChallengeMethod = url.searchParams.get('code_challenge_method');
        const state = url.searchParams.get('state');

        // HARDENED (N0 B1 BLOCKER conf 88 2026-05-16): refuse PKCE method=plain.
        // Discovery advertises `code_challenge_methods_supported: ['S256']` only
        // — accepting `plain` here would be a silent downgrade defeating
        // PKCE's protection for public clients (RFC 7636 §4.4 explicitly
        // discourages plain).
        if (clientCodeChallengeMethod && clientCodeChallengeMethod !== 'S256') {
          logger.warn('Rejected /authorize: PKCE method not S256', {
            method: clientCodeChallengeMethod,
            client_ip: (req as Request & { clientIp?: string }).clientIp,
          });
          res
            .status(400)
            .type('text/plain')
            .send('invalid_request: code_challenge_method must be S256');
          return;
        }

        // HARDENED (N0 B2 BLOCKER conf 92 2026-05-16): bound the `state`
        // string length to prevent attackers padding it to MB to amplify
        // the pkceStore OOM vector.
        if (state && state.length > MAX_STATE_LENGTH) {
          logger.warn('Rejected /authorize: state too long', {
            length: state.length,
            client_ip: (req as Request & { clientIp?: string }).clientIp,
          });
          res
            .status(400)
            .type('text/plain')
            .send('invalid_request: state parameter exceeds maximum length');
          return;
        }

        // HARDENED (N4 B1 BLOCKER fix 2026-06-02): PKCE is MANDATORY for
        // public clients per RFC 9700 §2.1.1 (OAuth Security Best Current
        // Practices). Our discovery advertises `code_challenge_methods_
        // supported: ['S256']` only — accepting a PKCE-less request would
        // be a silent contract violation, allowing AAD to fall back to
        // non-PKCE flow if the app registration permits it. Fail closed.
        if (!clientCodeChallenge) {
          logger.warn('Rejected /authorize: missing code_challenge (PKCE mandatory)', {
            client_ip: (req as Request & { clientIp?: string }).clientIp,
          });
          res
            .status(400)
            .type('text/plain')
            .send('invalid_request: code_challenge is required (PKCE mandatory)');
          return;
        }

        // Forward parameters that Microsoft OAuth 2.0 v2.0 supports,
        // but NOT code_challenge/code_challenge_method — we generate our own for Microsoft.
        // NOTE: `scope` is handled separately below (intersection, not forward-as-is).
        const allowedParams = [
          'response_type',
          'redirect_uri',
          'state',
          'response_mode',
          'prompt',
          'login_hint',
          'domain_hint',
        ];

        allowedParams.forEach((param) => {
          const value = url.searchParams.get(param);
          if (value) {
            microsoftAuthUrl.searchParams.set(param, value);
          }
        });

        // HARDENED (ADR-0003 D2): scope intersection delegated to the
        // extracted computeEffectiveScope() helper (src/oauth/http-routes.ts).
        // Combines requested ∩ registered ∩ KNOWN + META_SCOPES bypass for
        // OIDC/refresh protocol scopes (N0-B1/I2 fix).
        const requestedScope = url.searchParams.get('scope') ?? undefined;
        const scopeResult = computeEffectiveScope(requestedScope, {
          allowedRedirectUris,
          registeredScopesString,
          knownScopes: () =>
            new Set(
              buildScopesFromEndpoints(
                this.options.orgMode,
                this.options.enabledTools,
                httpWritePolicy
              )
            ),
          logger,
        });
        if (scopeResult.effective !== null) {
          microsoftAuthUrl.searchParams.set('scope', scopeResult.effective);
        } else {
          logger.warn('Rejected /authorize: empty scope intersection', {
            requested: requestedScope,
            client_ip: (req as Request & { clientIp?: string }).clientIp,
          });
          res
            .status(400)
            .type('text/plain')
            .send('invalid_scope: no requested scope is in the registered/known allowlist');
          return;
        }

        // Two-leg PKCE: if the client sent a code_challenge, store it and generate
        // a separate PKCE pair for the server↔Microsoft leg
        if (clientCodeChallenge && state) {
          const serverCodeVerifier = crypto.randomBytes(32).toString('base64url');
          const serverCodeChallenge = crypto
            .createHash('sha256')
            .update(serverCodeVerifier)
            .digest('base64url');

          // HARDENED (N0 B2 BLOCKER fix 2026-05-16): bounded LRU semantics
          // before insertion to prevent OOM via state-flood. JS Map preserves
          // insertion order, so deleting the first key is equivalent to
          // evicting the oldest.
          if (this.pkceStore.size >= MAX_PKCE_STORE_SIZE) {
            const oldestKey = this.pkceStore.keys().next().value;
            if (oldestKey !== undefined) {
              this.pkceStore.delete(oldestKey);
              logger.warn('pkceStore at capacity — evicted oldest entry', {
                size: MAX_PKCE_STORE_SIZE,
              });
            }
          }

          this.pkceStore.set(state, {
            clientCodeChallenge,
            clientCodeChallengeMethod: clientCodeChallengeMethod || 'S256',
            serverCodeVerifier,
            createdAt: Date.now(),
          });

          // Send our server-generated code_challenge to Microsoft
          microsoftAuthUrl.searchParams.set('code_challenge', serverCodeChallenge);
          microsoftAuthUrl.searchParams.set('code_challenge_method', 'S256');

          logger.info('Two-leg PKCE: stored client challenge, generated server challenge', {
            state: state.substring(0, 8) + '...',
          });
        } else if (clientCodeChallenge) {
          // HARDENED (N0 B1 fix 2026-05-16): no state to key on (Claude Code
          // stdio path) — forward challenge but FORCE method=S256. Plain
          // was already rejected at the top of this handler, so the only
          // way to land here with a non-S256 method is the absence of the
          // method param entirely, in which case S256 is the correct default.
          microsoftAuthUrl.searchParams.set('code_challenge', clientCodeChallenge);
          microsoftAuthUrl.searchParams.set('code_challenge_method', 'S256');
        }

        // Use our Microsoft app's client_id
        microsoftAuthUrl.searchParams.set('client_id', clientId);

        // HARDENED (ADR-0003, codex N1-I2 conf 98): the historical fallback
        // `User.Read Files.Read Mail.Read` is REMOVED. If the scope intersection
        // above produced an empty set, we already returned 400 invalid_scope.
        // Files.Read is out of scope for an Outlook-only MCP and must never
        // leak into the consent request.

        // Redirect to Microsoft's authorization page
        res.redirect(microsoftAuthUrl.toString());
      });

      // Token exchange endpoint
      app.post('/token', async (req, res) => {
        try {
          // Log token endpoint call (redact sensitive data)
          logger.info('Token endpoint called', {
            method: req.method,
            url: req.url,
            contentType: req.get('Content-Type'),
            grant_type: req.body?.grant_type,
          });

          const body = req.body;

          // Add debugging and validation
          if (!body) {
            logger.error('Token endpoint: Request body is undefined');
            res.status(400).json({
              error: 'invalid_request',
              error_description: 'Request body is required',
            });
            return;
          }

          if (!body.grant_type) {
            logger.error('Token endpoint: grant_type is missing', { body });
            res.status(400).json({
              error: 'invalid_request',
              error_description: 'grant_type parameter is required',
            });
            return;
          }

          if (body.grant_type === 'authorization_code') {
            const tenantId = this.secrets?.tenantId || 'common';
            const clientId = this.secrets!.clientId;
            const clientSecret = this.secrets?.clientSecret;

            logger.info('Token endpoint: authorization_code exchange', {
              redirect_uri: body.redirect_uri,
              has_code: !!body.code,
              has_code_verifier: !!body.code_verifier,
              clientId,
              tenantId,
              hasClientSecret: !!clientSecret,
            });

            // Two-leg PKCE: check if we have a stored PKCE mapping for this exchange
            // We need to find the matching state — it's not sent in the token request,
            // but the code is unique per authorization, so we verify the client's
            // code_verifier against all stored challenges and use the server's verifier
            let serverCodeVerifier: string | undefined;

            if (body.code_verifier) {
              // Look through pkceStore for a matching client code_challenge
              const clientVerifier = body.code_verifier as string;
              const clientChallengeComputed = crypto
                .createHash('sha256')
                .update(clientVerifier)
                .digest('base64url');

              for (const [state, pkceData] of this.pkceStore) {
                if (pkceData.clientCodeChallenge === clientChallengeComputed) {
                  // Client's code_verifier matches stored code_challenge — two-leg PKCE
                  serverCodeVerifier = pkceData.serverCodeVerifier;
                  this.pkceStore.delete(state);
                  logger.info('Two-leg PKCE: matched client verifier, using server verifier', {
                    state: state.substring(0, 8) + '...',
                  });
                  break;
                }
              }
            }

            const result = await exchangeCodeForToken(
              body.code as string,
              body.redirect_uri as string,
              clientId,
              clientSecret,
              tenantId,
              serverCodeVerifier || (body.code_verifier as string | undefined),
              this.secrets!.cloudType
            );
            res.json(result);
          } else if (body.grant_type === 'refresh_token') {
            const tenantId = this.secrets?.tenantId || 'common';
            const clientId = this.secrets!.clientId;
            const clientSecret = this.secrets?.clientSecret;

            // Log whether using public or confidential client
            if (clientSecret) {
              logger.info('Refresh endpoint: Using confidential client with client_secret');
            } else {
              logger.info('Refresh endpoint: Using public client without client_secret');
            }

            const result = await refreshAccessToken(
              body.refresh_token as string,
              clientId,
              clientSecret,
              tenantId,
              this.secrets!.cloudType
            );
            res.json(result);
          } else {
            res.status(400).json({
              error: 'unsupported_grant_type',
              error_description: `Grant type '${body.grant_type}' is not supported`,
            });
          }
        } catch (error) {
          logger.error('Token endpoint error:', error);
          res.status(500).json({
            error: 'server_error',
            error_description: 'Internal server error during token exchange',
          });
        }
      });

      // HARDENED (N3 mcp-vault M1 2026-05-16): the SDK's `mcpAuthRouter`
      // registers its own /.well-known, /register, /authorize, /token handlers.
      // Our hand-rolled hardenings (registered above) are matched FIRST by
      // Express because they were registered earlier. mcpAuthRouter only ever
      // sees a request if our handlers did not respond — practically: edge
      // SDK-specific paths (e.g. dynamic /.well-known variants we don't cover).
      //
      // For ANY path mcpAuthRouter handles, the provider's getClient() is
      // consulted to validate redirect_uri. That's why oauth-provider.ts
      // getClient() must return the registered-clients allowlist (N3 C1 fix)
      // — it's the defense-in-depth filet de sécurité.
      app.use(
        mcpAuthRouter({
          provider: oauthProvider,
          issuerUrl: new URL(
            this.options.baseUrl || process.env.MS365_MCP_BASE_URL || `http://localhost:${port}`
          ),
        })
      );

      // Microsoft Graph MCP endpoints with bearer token auth
      // Handle both GET and POST methods as required by MCP Streamable HTTP specification
      app.get(
        '/mcp',
        bearerAuthMiddleware,
        async (
          req: Request & { microsoftAuth?: { accessToken: string; refreshToken: string } },
          res: Response
        ) => {
          const handler = async () => {
            const server = this.createMcpServer();
            const transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: undefined, // Stateless mode
            });

            res.on('close', () => {
              transport.close();
              server.close();
            });

            await server.connect(transport);
            await transport.handleRequest(req as any, res as any, undefined);
          };

          try {
            if (req.microsoftAuth) {
              await requestContext.run(
                {
                  accessToken: req.microsoftAuth.accessToken,
                  refreshToken: req.microsoftAuth.refreshToken,
                },
                handler
              );
            } else {
              await handler();
            }
          } catch (error) {
            logger.error('Error handling MCP GET request:', error);
            if (!res.headersSent) {
              res.status(500).json({
                jsonrpc: '2.0',
                error: {
                  code: -32603,
                  message: 'Internal server error',
                },
                id: null,
              });
            }
          }
        }
      );

      app.post(
        '/mcp',
        bearerAuthMiddleware,
        async (
          req: Request & { microsoftAuth?: { accessToken: string; refreshToken: string } },
          res: Response
        ) => {
          const handler = async () => {
            const server = this.createMcpServer();
            const transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: undefined, // Stateless mode
            });

            res.on('close', () => {
              transport.close();
              server.close();
            });

            await server.connect(transport);
            await transport.handleRequest(req as any, res as any, req.body);
          };

          try {
            if (req.microsoftAuth) {
              await requestContext.run(
                {
                  accessToken: req.microsoftAuth.accessToken,
                  refreshToken: req.microsoftAuth.refreshToken,
                },
                handler
              );
            } else {
              await handler();
            }
          } catch (error) {
            logger.error('Error handling MCP POST request:', error);
            if (!res.headersSent) {
              res.status(500).json({
                jsonrpc: '2.0',
                error: {
                  code: -32603,
                  message: 'Internal server error',
                },
                id: null,
              });
            }
          }
        }
      );

      // Health check endpoint
      app.get('/', (req, res) => {
        res.send('Microsoft 365 MCP Server is running');
      });

      if (host) {
        app.listen(port, host, () => {
          logger.info(`Server listening on ${host}:${port}`);
          logger.info(`  - MCP endpoint: http://${host}:${port}/mcp`);
          logger.info(`  - OAuth endpoints: http://${host}:${port}/auth/*`);
          logger.info(
            `  - OAuth discovery: http://${host}:${port}/.well-known/oauth-authorization-server`
          );
        });
      } else {
        app.listen(port, () => {
          logger.info(`Server listening on all interfaces (0.0.0.0:${port})`);
          logger.info(`  - MCP endpoint: http://localhost:${port}/mcp`);
          logger.info(`  - OAuth endpoints: http://localhost:${port}/auth/*`);
          logger.info(
            `  - OAuth discovery: http://localhost:${port}/.well-known/oauth-authorization-server`
          );
        });
      }
    } else {
      const transport = new StdioServerTransport();
      await this.server!.connect(transport);
      logger.info('Server connected to stdio transport');
    }
  }
}

export default MicrosoftGraphServer;
