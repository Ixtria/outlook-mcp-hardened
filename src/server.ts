import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import logger, { enableConsoleLogging } from './logger.js';
import { registerAuthTools } from './auth-tools.js';
import { registerGraphTools, registerDiscoveryTools } from './graph-tools.js';
import GraphClient from './graph-client.js';
import AuthManager from './auth.js';
import type { CommandOptions } from './cli.ts';
import { getSecrets, type AppSecrets } from './secrets.js';
import { createRequestIdMiddleware, parseTrustedProxiesEnv } from './request-context.js';
import { createHardenedOAuthApp } from './oauth/http-app.js';
import { withTokenExchangeAudit } from './oauth-provider.js';
import { exchangeCodeForToken, refreshAccessToken } from './lib/microsoft-auth.js';

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
      const trustedProxies = parseTrustedProxiesEnv(process.env.OUTLOOK_MCP_TRUSTED_PROXIES);
      const publicUrl = process.env.OUTLOOK_MCP_PUBLIC_URL ?? this.options.baseUrl;
      const isLoopbackBind = host === '127.0.0.1' || host === '::1' || host === 'localhost';

      if (!isLoopbackBind && trustedProxies.size === 0) {
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

      // HARDENED (TEST-01, MAINT-TEST-BEHAV 2026-08-02): the entire HTTP
      // wiring — trust proxy, CORS, body parsers, /.well-known/*, /register,
      // /authorize, /token, /mcp, global error handler, interval-driven
      // pkceStore sweep — is now built by `createHardenedOAuthApp` in
      // `src/oauth/http-app.ts`. Tests exercise the exact same factory
      // (`test/helpers/oauth-server-fixture.ts` + `test/e2e/oauth-routes.test.ts`).
      // The only server-side responsibilities that remain here are : run the
      // boot-time env-var invariants above, then `.listen()` the built app.
      const { app } = createHardenedOAuthApp({
        secrets: this.secrets!,
        authManager: this.authManager,
        createMcpServer: () => this.createMcpServer(),
        options: {
          orgMode: this.options.orgMode,
          enabledTools: this.options.enabledTools,
          enableSend: this.options.enableSend,
          enableWrite: this.options.enableWrite,
          enableDynamicRegistration: this.options.enableDynamicRegistration,
          baseUrl: this.options.baseUrl,
        },
        host: host ?? '127.0.0.1',
        port,
        publicUrl,
        trustedProxies,
        corsOrigin: process.env.OUTLOOK_MCP_CORS_ORIGIN,
        logger,
        // OBS-04 (2026-08-02) : correlation id — echoed via `X-Request-Id`
        // and propagated through AsyncLocalStorage so `auditLog()` and the
        // winston request_id format read the same value for every event
        // emitted during one HTTP request.
        requestIdMiddleware: createRequestIdMiddleware(),
        // OBS-02 (2026-08-02) : wrap the AAD token-exchange calls so both
        // `authorization_code` and `refresh_token` grants emit an
        // `oauth.token.request` / `oauth.token.reject` audit line. The
        // wrapper is defined in oauth-provider.ts so http-app.ts stays
        // audit-agnostic ; server.ts is the composition root that decides
        // "production wiring gets audited".
        exchangeCode: withTokenExchangeAudit(exchangeCodeForToken),
        refreshToken: withTokenExchangeAudit(refreshAccessToken),
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
