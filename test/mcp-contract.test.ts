/**
 * MCP protocol contract test (TEST-03, 2026-08-02).
 *
 * Verifies that the server we build in production (`McpServer` +
 * `registerAuthTools` + `registerGraphTools`) respects the MCP protocol
 * contract when connected to a real SDK `Client` over an in-process
 * transport pair. Behavioral only per ADR-0004 rule 3 — no assertion on
 * source text.
 *
 * What we assert (observable via the client wire):
 *   1. Initialize handshake completes and reports serverInfo + capabilities.
 *   2. `capabilities.tools` is declared, `resources`/`prompts` are NOT
 *      (we don't register any — regressions that silently expose them
 *      would be caught here).
 *   3. `tools/list` returns a non-empty array where every entry has
 *      { name:string, description:string, inputSchema:JSONSchema }.
 *   4. Each inputSchema is a JSON Schema draft-07 object that Ajv can
 *      compile — proves the zod → JSON-Schema conversion the SDK does
 *      per tool still produces valid schemas after every code change.
 *   5. `resources/list` and `prompts/list` reject (MCP -32601 method
 *      not found, per spec, when the server didn't declare the capability).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

// Silence server-side info logging noise.
vi.mock('../src/logger.js', () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
  enableConsoleLogging: vi.fn(),
}));

// Small deterministic endpoint fixture — one GET (mail), one POST (mail
// send), one GET calendar, one GET utility. This exercises both the
// read-first policy and the OData param injection paths in graph-tools.
vi.mock('../src/generated/client.js', () => ({
  api: {
    endpoints: [
      {
        alias: 'list-mail-messages',
        method: 'GET',
        path: '/me/messages',
        description: 'List mail messages',
        parameters: [],
      },
      {
        alias: 'send-mail',
        method: 'POST',
        path: '/me/sendMail',
        description: 'Send mail',
        parameters: [],
      },
      {
        alias: 'list-calendar-events',
        method: 'GET',
        path: '/me/events',
        description: 'List calendar events',
        parameters: [],
      },
      {
        alias: 'get-current-user',
        method: 'GET',
        path: '/me',
        description: 'Get current user',
        parameters: [],
      },
    ],
  },
}));

// Deferred import so the vi.mock() calls above are honored (ESM hoist).
const { registerAuthTools } = await import('../src/auth-tools.js');
const { registerGraphTools } = await import('../src/graph-tools.js');

type MinimalAuthManager = {
  isOAuthModeEnabled: () => boolean;
  getTokenForAccount: () => Promise<string>;
  listAccounts: () => Promise<Array<{ username: string; homeAccountId: string }>>;
  getSelectedAccountId: () => string | null;
  testLogin: () => Promise<{ success: boolean }>;
  acquireTokenByDeviceCode: () => Promise<string>;
  logout: () => Promise<void>;
  selectAccount: () => Promise<void>;
  removeAccount: () => Promise<boolean>;
  getUseInteractiveAuth: () => boolean;
  acquireTokenInteractive: () => Promise<void>;
};

function buildAuthManagerStub(): MinimalAuthManager {
  // Registration path only reads static config; handlers close over the
  // manager but we never call the tools in this contract test. Returning
  // reject/no-op stubs is sufficient and makes accidental invocation
  // observable.
  return {
    isOAuthModeEnabled: () => false,
    getTokenForAccount: () => Promise.reject(new Error('stub')),
    listAccounts: () => Promise.resolve([]),
    getSelectedAccountId: () => null,
    testLogin: () => Promise.resolve({ success: false }),
    acquireTokenByDeviceCode: () => Promise.reject(new Error('stub')),
    logout: () => Promise.resolve(),
    selectAccount: () => Promise.resolve(),
    removeAccount: () => Promise.resolve(false),
    getUseInteractiveAuth: () => false,
    acquireTokenInteractive: () => Promise.resolve(),
  };
}

interface Harness {
  server: McpServer;
  client: Client;
  close: () => Promise<void>;
}

async function startHarness(): Promise<Harness> {
  const server = new McpServer({ name: 'Microsoft365MCP', version: '0.0.0-test' });
  const authManager = buildAuthManagerStub();
  // Cast to `unknown` first — the register* signatures want the real
  // concrete classes; our stub covers every method used at registration
  // time. Any breakage would surface as a runtime tool-call error, not a
  // registration failure.
  registerAuthTools(server, authManager as unknown as import('../src/auth.js').default);
  registerGraphTools(
    server,
    {} as unknown as import('../src/graph-client.js').default,
    /* readOnly */ false,
    /* enabledToolsPattern */ undefined,
    /* orgMode */ false,
    authManager as unknown as import('../src/auth.js').default,
    /* multiAccount */ false,
    /* accountNames */ [],
    /* writePolicy */ { mail: true, calendar: true }
  );

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);

  const client = new Client({ name: 'contract-test', version: '0.0.0' });
  await client.connect(clientTransport);

  return {
    server,
    client,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

describe('MCP protocol contract', () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await startHarness();
  });

  afterEach(async () => {
    await harness.close();
  });

  it('completes the initialize handshake and exposes serverInfo', () => {
    // client.connect() drives the initialize round-trip. If the handshake
    // failed connect() would have rejected and beforeEach would have
    // thrown — so getServerVersion being populated proves the exchange.
    const version = harness.client.getServerVersion();
    expect(version).toBeDefined();
    expect(version?.name).toBe('Microsoft365MCP');
    expect(version?.version).toBe('0.0.0-test');
  });

  it('advertises the tools capability but not resources or prompts', () => {
    const caps = harness.client.getServerCapabilities();
    expect(caps).toBeDefined();
    // McpServer only exposes a capability when at least one item of that
    // kind was registered. registerAuthTools + registerGraphTools only
    // register tools, so the other two MUST stay undefined — a regression
    // that accidentally wired a prompts/resources handler would flip these
    // and this assertion would catch it.
    expect(caps?.tools).toBeDefined();
    expect(caps?.resources).toBeUndefined();
    expect(caps?.prompts).toBeUndefined();
  });

  it('returns tools with a valid { name, description, inputSchema } shape', async () => {
    const result = await harness.client.listTools();
    expect(Array.isArray(result.tools)).toBe(true);
    expect(result.tools.length).toBeGreaterThan(0);

    for (const tool of result.tools) {
      expect(typeof tool.name).toBe('string');
      expect(tool.name.length).toBeGreaterThan(0);
      // MCP spec: description is optional but every one of our tools sets
      // one (auth-tools hard-codes strings, graph-tools falls back to a
      // synthesized description). A missing description is a regression.
      expect(typeof tool.description).toBe('string');
      expect(tool.description!.length).toBeGreaterThan(0);
      expect(tool.inputSchema).toBeDefined();
      expect(tool.inputSchema.type).toBe('object');
    }
  });

  it('exposes both auth tools and graph tools by name', async () => {
    const { tools } = await harness.client.listTools();
    const names = new Set(tools.map((t) => t.name));
    // Auth tool registered by registerAuthTools.
    expect(names.has('login')).toBe(true);
    // Graph tools from our mocked endpoints set.
    expect(names.has('list-mail-messages')).toBe(true);
    expect(names.has('list-calendar-events')).toBe(true);
    expect(names.has('get-current-user')).toBe(true);
    // send-mail is gated by writePolicy.mail=true (we passed true above)
    // and is a POST, so it must appear when the operator opted in.
    expect(names.has('send-mail')).toBe(true);
  });

  it('every inputSchema is a JSON Schema Ajv can compile', async () => {
    const { tools } = await harness.client.listTools();
    // Ajv strict mode off: MCP inputSchemas may include descriptive keys
    // ($schema drafts, additionalProperties variants) that strict mode
    // flags — we care about *compilability*, not stylistic strictness.
    const ajv = new Ajv({ strict: false, allErrors: true });
    addFormats(ajv);

    for (const tool of tools) {
      // Ajv.compile throws on structural errors (unknown keywords in
      // strict mode, malformed $ref, invalid type unions, …). A tool
      // whose zod → JSON-Schema conversion produced garbage would fail
      // here — that's the regression this test guards against.
      expect(() => ajv.compile(tool.inputSchema), `tool ${tool.name}`).not.toThrow();
    }
  });

  it('rejects resources/list because the server did not declare the capability', async () => {
    // MCP servers built by McpServer refuse method calls whose capability
    // was never registered. The SDK client surfaces this as a rejected
    // promise (JSON-RPC error -32601 method not found, or the SDK's own
    // "server does not support ..." guard). We only need to observe that
    // no result comes back — the exact error text is SDK-versioned.
    await expect(harness.client.listResources()).rejects.toThrow();
  });

  it('rejects prompts/list because the server did not declare the capability', async () => {
    await expect(harness.client.listPrompts()).rejects.toThrow();
  });
});
