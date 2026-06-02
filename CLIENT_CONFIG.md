# CLIENT_CONFIG — wire any MCP client to `outlook-mcp-hardened`

This document is **client-agnostic**. The MCP protocol is a standard ; any compliant client can connect. We provide concrete snippets for the most common clients, but the underlying contract is what matters — adapt it to whatever your agent runtime expects.

For the MCP protocol itself, see [modelcontextprotocol.io/specification](https://modelcontextprotocol.io/specification).

## The two transports

MCP defines two standard transports :

| Transport | When to use | Connection model |
|---|---|---|
| **stdio** | Local agent on the same machine as the server. Process-bound, no network exposure. | Client spawns the server as a child process. The server reads JSON-RPC from stdin, writes responses to stdout. Logs go to stderr (audit log uses stderr by design). |
| **Streamable HTTP** | Remote agent over HTTPS (browser, distributed system). | Client opens an HTTP connection, sends JSON-RPC over POST, optionally receives Server-Sent Events for streaming. |

`outlook-mcp-hardened` supports both. Stdio is the default ; HTTP is opt-in via `--http <host:port>`.

## Stdio configuration

### Generic pattern

Whatever runtime you use, it needs to know three things :

1. **Command** : `outlook-mcp-hardened` (or `npx -y @ixtria/outlook-mcp-hardened`)
2. **Arguments** : zero or more flags (`--enable-send`, `--enable-write`, etc.)
3. **Environment** : `MS365_MCP_CLIENT_ID`, `MS365_MCP_TENANT_ID` (unless set globally)

### Example : Claude Desktop

Configuration file location :

- **macOS** : `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows** : `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux** : `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "outlook": {
      "command": "outlook-mcp-hardened",
      "args": [],
      "env": {
        "MS365_MCP_CLIENT_ID": "00000000-0000-0000-0000-000000000000",
        "MS365_MCP_TENANT_ID": "common"
      }
    }
  }
}
```

To opt-in to writes :

```json
"args": ["--enable-send", "--enable-write"]
```

### Example : Claude Code (CLI)

In `.claude.json` or via `claude mcp add` :

```json
{
  "mcpServers": {
    "outlook": {
      "type": "stdio",
      "command": "outlook-mcp-hardened",
      "env": {
        "MS365_MCP_CLIENT_ID": "00000000-0000-0000-0000-000000000000",
        "MS365_MCP_TENANT_ID": "common"
      }
    }
  }
}
```

### Example : Cline (VS Code extension)

In Cline settings → MCP servers :

```json
{
  "outlook": {
    "command": "outlook-mcp-hardened",
    "args": [],
    "env": {
      "MS365_MCP_CLIENT_ID": "...",
      "MS365_MCP_TENANT_ID": "..."
    }
  }
}
```

### Example : Continue (VS Code / JetBrains)

In `~/.continue/config.json` :

```json
{
  "mcpServers": [
    {
      "name": "outlook",
      "transport": {
        "type": "stdio",
        "command": "outlook-mcp-hardened",
        "args": [],
        "env": {
          "MS365_MCP_CLIENT_ID": "...",
          "MS365_MCP_TENANT_ID": "..."
        }
      }
    }
  ]
}
```

### Example : `mcp-inspector` (official debug tool)

```bash
npx @modelcontextprotocol/inspector outlook-mcp-hardened
# → opens a web UI on http://localhost:5173 to introspect tools, resources, prompts
```

With env vars :

```bash
MS365_MCP_CLIENT_ID=... MS365_MCP_TENANT_ID=... \
  npx @modelcontextprotocol/inspector outlook-mcp-hardened --enable-send
```

### Example : a custom Node.js agent

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const transport = new StdioClientTransport({
  command: 'outlook-mcp-hardened',
  args: [],
  env: {
    MS365_MCP_CLIENT_ID: process.env.MS365_MCP_CLIENT_ID!,
    MS365_MCP_TENANT_ID: process.env.MS365_MCP_TENANT_ID!,
  },
});

const client = new Client({ name: 'my-agent', version: '0.1.0' });
await client.connect(transport);

const tools = await client.listTools();
console.log(tools);
```

### Example : a custom Python agent (`mcp` SDK)

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

params = StdioServerParameters(
    command="outlook-mcp-hardened",
    args=[],
    env={
        "MS365_MCP_CLIENT_ID": "...",
        "MS365_MCP_TENANT_ID": "...",
    },
)

async with stdio_client(params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        print(tools)
```

### Example : `openclaw` / `Hermès` (local LLM front-ends)

These local-LLM runtimes vary in their MCP wiring. The pattern is the same : provide the binary path + env + args. Refer to your runtime's docs for the exact JSON schema. The server contract is :

- Binary : the absolute path to `outlook-mcp-hardened` (find via `which outlook-mcp-hardened`)
- Args : `[]` for read-only ; `["--enable-send"]` etc. for writes
- Env : Microsoft client ID + tenant ID

## HTTP configuration

The HTTP transport is for **remote** clients, typically through a reverse proxy that terminates TLS.

### Server side

Start the server :

```bash
# Loopback for local testing (no auth required from clients on the same host)
outlook-mcp-hardened --http 127.0.0.1:3000

# Public bind behind reverse proxy
OUTLOOK_MCP_PUBLIC_URL=https://outlook-mcp.example.com \
OUTLOOK_MCP_TRUSTED_PROXIES=10.0.0.1 \
outlook-mcp-hardened --http 0.0.0.0:3000
```

The server exposes :

- `POST /mcp` — Streamable HTTP MCP endpoint (Bearer-protected with a Microsoft Graph token)
- `GET /.well-known/oauth-authorization-server` — OAuth 2.1 AS discovery (RFC 8414)
- `GET /.well-known/oauth-protected-resource[/mcp]` — protected resource discovery (RFC 9728)
- `GET /authorize`, `POST /token` — OAuth proxy endpoints
- `POST /register` — RFC 7591 dynamic client registration (allowlist-validated)

### Client side : generic Streamable HTTP

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const transport = new StreamableHTTPClientTransport(
  new URL('https://outlook-mcp.example.com/mcp'),
  {
    requestInit: {
      headers: {
        Authorization: `Bearer ${microsoftGraphAccessToken}`,
      },
    },
  }
);

const client = new Client({ name: 'my-remote-agent', version: '0.1.0' });
await client.connect(transport);
```

### Obtaining the Bearer token (HTTP mode)

The client must already have a Microsoft Graph access token for the user it wants to act as. Either :

1. **Discover via OAuth** : the client follows the [MCP authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) — fetches `/.well-known/oauth-authorization-server`, registers via `/register` (if needed), runs the auth code flow via `/authorize` + `/token`, then uses the resulting access token in `Authorization: Bearer`.
2. **Inject manually** : if the client already has a Graph token from another flow, pass it directly in the Bearer header. This bypasses our OAuth proxy but `outlook-mcp-hardened` will still validate the token against Graph `/me` before allowing any tool call.

The hardened OAuth proxy enforces, at every step :

- Exact-match `redirect_uri` (no wildcards)
- PKCE S256 mandatory
- Scope intersection (`requested ∩ registered ∩ KNOWN`)
- Trust-proxy resolved client IP (no XFF spoofing)
- Rate limits per IP
- POST `/authorize` → 405 (only GET is accepted, closes SDK bypass)

See [`SECURITY.md`](./SECURITY.md) for the full posture.

## Verifying the connection

Once wired, the client should be able to :

1. Initialize the MCP session (`initialize` request)
2. List tools (`tools/list`) — you should see ~58 Outlook tools
3. Call a read-only tool : `list-mail-messages` with default args
4. Receive a JSON response with a list of recent messages

If `list-mail-messages` returns an empty list, you're authenticated but your mailbox is empty in the time window queried. If it returns `401 Unauthorized`, the access token is invalid — run `outlook-mcp-hardened --login` again on the server host.

## Troubleshooting

See [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) for common errors and their fixes.

## Adding a new client

If you wire `outlook-mcp-hardened` to a new MCP client that's not listed here, please open a PR adding a snippet to this file ! The community benefits when each adapter is documented in one place.
