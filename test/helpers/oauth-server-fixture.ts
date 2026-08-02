/**
 * OAuth HTTP behavioral test fixture (MAINT-TEST-BEHAV, 2026-08-02).
 * Foundation for Workflow 2 (SEC-01 / TEST-01) behavioral tests.
 *
 * Spins a real Express app on an ephemeral port using the same route
 * factories `src/server.ts` wires in production (`createAuthorizeHandler`,
 * `createRejectPostAuthorizeHandler`) — so any regression in those handlers
 * or in the server.ts wiring fails the behavioral tests. No real MSAL, no
 * real Graph fetch, no keychain access. Log capture goes through a Winston
 * Stream transport attached to the shared `logger` singleton.
 *
 * Discipline (ADR-0004 rule 3) : callers assert on observable behavior
 * (HTTP status, body, headers, captured log lines), NEVER on source
 * content (fs.readFileSync / SOURCE.toContain).
 */
import express, { type Express, type RequestHandler } from 'express';
import { Writable } from 'node:stream';
import type { AddressInfo, Server } from 'node:net';
import winston from 'winston';
import type { CloudType } from '../../src/cloud-config.js';
import logger from '../../src/logger.js';
import {
  createAuthorizeHandler,
  createRegisterHandler,
  createRejectPostAuthorizeHandler,
  type PkceStoreEntry,
} from '../../src/oauth/http-routes.js';
import { allRegisteredRedirectUris } from '../../src/oauth/registered-clients.js';

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
