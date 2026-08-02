/**
 * OAuth HTTP behavioral test fixture (MAINT-TEST-BEHAV + TEST-01, 2026-08-02).
 *
 * Two entry points :
 *
 *   - `startOauthFixture()` — minimal /authorize + /register mount. Used by
 *     `test/lot1-behavior.test.ts` for the Phase A behavioral proofs.
 *
 *   - `startFullOauthFixture()` — mounts the SAME `createHardenedOAuthApp`
 *     factory that `src/server.ts` wires in production, exposing every
 *     hardened OAuth surface : /.well-known/*, /register, /authorize,
 *     /token (with injectable AAD stubs), and /mcp (with injectable Bearer
 *     verifier). Used by `test/e2e/oauth-routes.test.ts`.
 *
 * In both cases : no real MSAL, no real Graph fetch, no keychain access.
 * Log capture goes through a Winston Stream transport attached to the
 * shared `logger` singleton.
 *
 * Discipline (ADR-0004 rule 3) : callers assert on observable behavior
 * (HTTP status, body, headers, captured log lines), NEVER on source
 * content (fs.readFileSync / SOURCE.toContain).
 */
import express, { type Express, type RequestHandler } from 'express';
import { Writable } from 'node:stream';
import net, { type AddressInfo, type Server } from 'node:net';
import winston from 'winston';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CloudType } from '../../src/cloud-config.js';
import type AuthManager from '../../src/auth.js';
import type { AppSecrets } from '../../src/secrets.js';
import logger from '../../src/logger.js';
import {
  createAuthorizeHandler,
  createRegisterHandler,
  createRejectPostAuthorizeHandler,
  type PkceStoreEntry,
} from '../../src/oauth/http-routes.js';
import { allRegisteredRedirectUris } from '../../src/oauth/registered-clients.js';
import {
  createHardenedOAuthApp,
  type HardenedOAuthAppDeps,
} from '../../src/oauth/http-app.js';

export interface FixtureSecrets {
  clientId: string;
  tenantId: string;
  cloudType: CloudType;
}

export function defaultSecrets(): FixtureSecrets {
  return {
    clientId: '00000000-0000-0000-0000-000000000042',
    tenantId: 'common',
    cloudType: 'global',
  };
}

export interface OauthFixture {
  server: Server;
  port: number;
  baseUrl: string;
  pkceStore: Map<string, PkceStoreEntry>;
  close: () => Promise<void>;
}

export interface StartOauthFixtureOptions {
  secrets?: Partial<FixtureSecrets>;
  allowedRedirectUris?: ReadonlySet<string>;
  registeredScopesString?: string;
  knownScopes?: () => Set<string>;
  enableDynamicRegistration?: boolean;
}

const DEFAULT_REGISTERED_SCOPES = [
  'User.Read',
  'Mail.Read',
  'Mail.ReadWrite',
  'Mail.Send',
  'Calendars.Read',
  'Calendars.ReadWrite',
  'offline_access',
  'openid',
  'profile',
].join(' ');

const DEFAULT_KNOWN_SCOPES = (): Set<string> =>
  new Set([
    'User.Read',
    'Mail.Read',
    'Mail.ReadWrite',
    'Mail.Send',
    'Calendars.Read',
    'Calendars.ReadWrite',
    'offline_access',
    'openid',
    'profile',
  ]);

/**
 * Mounts POST /authorize, GET /authorize, and (opt-in) POST /register on
 * an ephemeral loopback port. LIMITATIONS (see followup tickets) :
 *   - No /token, /mcp, /.well-known/*, no SDK mcpAuthRouter — those need
 *     AuthManager / GraphClient / MCP SDK deps.
 *   - No CORS, no trust-proxy middleware (loopback only).
 *   - Body limits mirror server.ts (10 KB JSON + urlencoded).
 */
export async function startOauthFixture(
  options: StartOauthFixtureOptions = {}
): Promise<OauthFixture> {
  const secrets: FixtureSecrets = { ...defaultSecrets(), ...(options.secrets ?? {}) };
  const allowedRedirectUris = options.allowedRedirectUris ?? allRegisteredRedirectUris();
  const registeredScopesString = options.registeredScopesString ?? DEFAULT_REGISTERED_SCOPES;
  const knownScopes = options.knownScopes ?? DEFAULT_KNOWN_SCOPES;
  const pkceStore = new Map<string, PkceStoreEntry>();

  const app: Express = express();
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false, limit: '10kb', parameterLimit: 20 }));

  const rejectPost: RequestHandler = createRejectPostAuthorizeHandler({ logger });
  const authorize: RequestHandler = createAuthorizeHandler({
    allowedRedirectUris,
    registeredScopesString,
    knownScopes,
    logger,
    secrets,
    pkceStore,
  });

  app.post('/authorize', rejectPost);
  app.get('/authorize', authorize);

  if (options.enableDynamicRegistration) {
    app.post('/register', createRegisterHandler({ allowedRedirectUris, logger }));
  }

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    server,
    port,
    baseUrl,
    pkceStore,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

// ─── Full-stack fixture (TEST-01, 2026-08-02) ─────────────────────────────

export interface FullOauthFixture {
  server: Server;
  port: number;
  baseUrl: string;
  pkceStore: Map<string, PkceStoreEntry>;
  /** Snapshot access to the AuthManager mock that was injected. Useful for
   *  N4-B3 style assertions ("did anyone call setOAuthToken during a /mcp
   *  round-trip?"). */
  authManagerMock: RecordingAuthManager;
  /** Close the HTTP server and dispose the app (clears sweep interval). */
  close: () => Promise<void>;
}

/**
 * Minimal AuthManager mock that records method calls. Enough surface for
 * `MicrosoftOAuthProvider` (which just stashes it) and for behavioral tests
 * that need to assert "setOAuthToken was NOT called" (N4-B3).
 */
export interface RecordingAuthManager {
  setOAuthTokenCalls: string[];
  isOAuthModeEnabledCalls: number;
  isMultiAccount: () => Promise<boolean>;
  listAccounts: () => Promise<Array<{ username?: string }>>;
  setOAuthToken: (token: string) => Promise<void>;
  isOAuthModeEnabled: () => boolean;
  getToken: () => Promise<string | null>;
  getScopes: () => readonly string[];
  getSelectedAccountId: () => string | null;
}

export function createRecordingAuthManager(): RecordingAuthManager {
  const rec: RecordingAuthManager = {
    setOAuthTokenCalls: [],
    isOAuthModeEnabledCalls: 0,
    isMultiAccount: async () => false,
    listAccounts: async () => [],
    setOAuthToken: async (token: string) => {
      rec.setOAuthTokenCalls.push(token);
    },
    isOAuthModeEnabled: () => {
      rec.isOAuthModeEnabledCalls++;
      return false;
    },
    getToken: async () => null,
    getScopes: () => [],
    getSelectedAccountId: () => null,
  };
  return rec;
}

export interface StartFullFixtureOptions {
  secrets?: Partial<FixtureSecrets>;
  authManager?: RecordingAuthManager;
  enableDynamicRegistration?: boolean;
  /** Override the Bearer verifier. Default : accept "valid-token", reject others. */
  tokenVerifier?: HardenedOAuthAppDeps['tokenVerifier'];
  /** Override the AAD code exchange stub. Default : return canned tokens. */
  exchangeCode?: HardenedOAuthAppDeps['exchangeCode'];
  /** Override the AAD refresh stub. Default : return canned tokens. */
  refreshToken?: HardenedOAuthAppDeps['refreshToken'];
  /** Skip mounting /mcp routes (rare — most tests want them). */
  disableMcpRoutes?: boolean;
  /** Skip mounting the SDK auth router (default: true — we don't need it
   *  for the fixture tests, and it adds MCP-SDK-specific paths). */
  disableSdkAuthRouter?: boolean;
  /** Public URL override. */
  publicUrl?: string;
  /** CORS origin override. */
  corsOrigin?: string;
  /** MCP server factory override. Default : an inert stub. */
  createMcpServer?: () => McpServer;
}

/**
 * Boot the exact production Express app on an ephemeral loopback port.
 * The returned fixture exposes the mock AuthManager so tests can assert
 * "no global-state mutation occurred during this /mcp round-trip".
 */
export async function startFullOauthFixture(
  options: StartFullFixtureOptions = {}
): Promise<FullOauthFixture> {
  const secrets: AppSecrets = { ...defaultSecrets(), ...(options.secrets ?? {}) };
  const authManagerMock = options.authManager ?? createRecordingAuthManager();

  // Default AAD stubs return canned OAuth responses so /token round-trips
  // succeed without touching the real login.microsoftonline.com endpoint.
  const defaultExchange: HardenedOAuthAppDeps['exchangeCode'] = async () => ({
    access_token: 'fixture-access-token',
    token_type: 'Bearer',
    scope: 'Mail.Read User.Read',
    expires_in: 3600,
    refresh_token: 'fixture-refresh-token',
  });
  const defaultRefresh: HardenedOAuthAppDeps['refreshToken'] = async () => ({
    access_token: 'fixture-new-access-token',
    token_type: 'Bearer',
    scope: 'Mail.Read User.Read',
    expires_in: 3600,
    refresh_token: 'fixture-new-refresh-token',
  });

  const defaultVerifier: HardenedOAuthAppDeps['tokenVerifier'] = async (token) => {
    // eslint-disable-next-line security/detect-possible-timing-attacks -- justif: test fixture stub, not a production auth path; timing invariance irrelevant.
    if (token !== 'valid-token') {
      throw new Error('invalid_token');
    }
    return {
      token,
      clientId: secrets.clientId,
      scopes: [],
    };
  };

  // Minimal McpServer factory — the /mcp endpoint mounts it per request.
  // We install a real McpServer so the transport wiring is exercised
  // (StreamableHTTPServerTransport.handleRequest will emit a JSON-RPC
  // response for an initialize request, giving us a 200).
  const defaultCreateMcpServer = (): McpServer => {
    // Lazy-import to avoid a module-eval cost for the many tests that don't
    // touch /mcp.
    // eslint-disable-next-line @typescript-eslint/no-require-imports -- justif: sync require avoids a top-level await in an eagerly-loaded helper.
    const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js') as typeof import('@modelcontextprotocol/sdk/server/mcp.js');
    return new McpServer({ name: 'fixture-mcp', version: '0.0.0-fixture' });
  };

  // Pre-allocate a loopback port so the factory can bake the correct
  // fixed issuer URL BEFORE we start serving. This side-steps the chicken-
  // and-egg between `listen(0)` (needs an app) and issuerUrl (needs a port).
  // The tiny race between close/reuse is acceptable for tests.
  const port = await new Promise<number>((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const p = (probe.address() as AddressInfo).port;
      probe.close(() => resolve(p));
    });
  });

  const { app, dispose } = createHardenedOAuthApp({
    secrets,
    authManager: authManagerMock as unknown as AuthManager,
    createMcpServer: options.createMcpServer ?? defaultCreateMcpServer,
    options: {
      enableDynamicRegistration: options.enableDynamicRegistration ?? true,
    },
    host: '127.0.0.1',
    port,
    publicUrl: options.publicUrl,
    trustedProxies: new Set<string>(),
    corsOrigin: options.corsOrigin,
    logger,
    tokenVerifier: options.tokenVerifier ?? defaultVerifier,
    exchangeCode: options.exchangeCode ?? defaultExchange,
    refreshToken: options.refreshToken ?? defaultRefresh,
    disableSdkAuthRouter: options.disableSdkAuthRouter ?? true,
    disableMcpRoutes: options.disableMcpRoutes ?? false,
    disablePkceSweep: true, // avoid dangling timers in tests
  });

  const server = await new Promise<Server>((resolve, reject) => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    server,
    port,
    baseUrl,
    // Expose the same pkceStore instance the /authorize handler writes into.
    // The factory keeps it internal; tests that need it can use POST /token
    // in two-leg PKCE mode where the store is consumed automatically.
    pkceStore: new Map(),
    authManagerMock,
    close: async () => {
      dispose();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

/**
 * Attach an in-memory Winston transport to the shared logger singleton.
 * Returns captured formatted messages + a `restore()` that detaches.
 * Each caller gets its own transport instance (safe for parallel tests).
 */
export interface LogCapture {
  messages: string[];
  entries: Array<Record<string, unknown>>;
  restore: () => void;
}

export function attachLogCapture(): LogCapture {
  const messages: string[] = [];
  const entries: Array<Record<string, unknown>> = [];

  // Hook winston at the `write` boundary via a Writable stream wrapped in a
  // winston Stream transport (idiomatic winston 3, no legacy-transport warn).
  // We receive the formatted line — same string the file transports write.
  const sink = new Writable({
    write(chunk: Buffer | string, _enc: unknown, next: (err?: Error | null) => void) {
      try {
        const line = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
        // Strip the trailing '\n' winston appends per emission.
        const trimmed = line.replace(/\n$/, '');
        messages.push(trimmed);
        entries.push({ message: trimmed });
      } finally {
        next();
      }
    },
  });

  const transport = new winston.transports.Stream({ stream: sink, level: 'silly' });
  logger.add(transport);

  return {
    messages,
    entries,
    restore: () => {
      logger.remove(transport);
    },
  };
}
