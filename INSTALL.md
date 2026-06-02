# INSTALL — `@ixtria/outlook-mcp-hardened`

Comprehensive setup guide. Covers three execution modes : **stdio** (local agent), **http-loopback** (local HTTP testing), **http-public** (remote deployment behind reverse proxy).

For a quick start, see [`README.md`](./README.md). For the security model of each mode, see [`docs/MODES.md`](./docs/MODES.md).

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| Node.js | 20 LTS | 22 LTS |
| OS | Linux, macOS, Windows | Linux with `libsecret` for keychain |
| Microsoft tenant | Azure Entra ID | Single-tenant app registration |
| Network | Outbound HTTPS to `login.microsoftonline.com` + `graph.microsoft.com` | Same, behind allowlist firewall |

### Optional native dependencies

- **Linux** : `libsecret-1-0` for `keytar` keychain integration. Without it, tokens fall back to a 0600-permissioned file. Install via `apt install libsecret-1-0` (Debian/Ubuntu), `dnf install libsecret` (Fedora), `pacman -S libsecret` (Arch).
- **macOS** : Keychain integration works out of the box.
- **Windows** : Credential Manager via `keytar` works out of the box.

## 1 — Install the binary

```bash
# Global install (recommended for stdio mode)
npm install -g @ixtria/outlook-mcp-hardened

# Or one-shot via npx (slower but no global pollution)
npx -y @ixtria/outlook-mcp-hardened --login
```

Verify :

```bash
outlook-mcp-hardened --help
```

## 2 — Azure App Registration (one-time, per tenant)

You **can** run with the built-in public client for quick local testing, but **any production / non-trivial use should register your own app** so the consent screen names your organisation and you control the scopes.

### 2.1 — Register the app

1. Sign in to [Azure portal](https://portal.azure.com) → **Microsoft Entra ID → App registrations → New registration**.
2. **Name** : `outlook-mcp-hardened` (or similar).
3. **Supported account types** :
   - *Single tenant* — your organisation only (recommended for SME)
   - *Multitenant + personal* — only if you intentionally want consumer accounts
4. **Redirect URI** :
   - For **stdio + device code flow** (default) : leave empty.
   - For **browser-based flow** (`--auth-browser`) : add `Public client/native` redirect `http://localhost:3000/auth/callback`.
5. Click **Register**. Note the **Application (client) ID** and **Directory (tenant) ID** from the Overview page.

### 2.2 — Configure API permissions

Under **API permissions → Add a permission → Microsoft Graph → Delegated permissions**, add :

**Always required :**
- `User.Read`
- `Mail.Read`
- `Calendars.Read`
- `offline_access`
- `openid`
- `profile`

**Only if you plan to use `--enable-send` :**
- `Mail.Send`
- `Mail.ReadWrite`

**Only if you plan to use `--enable-write` :**
- `Calendars.ReadWrite`

Click **Grant admin consent for &lt;tenant&gt;** if your tenant requires it.

### 2.3 — Enable public client flows

Under **Authentication → Advanced settings → Allow public client flows** → **Yes**. Required for device code flow (the safest UX for CLI tools — no client secret needed).

### 2.4 — Optional : confidential client (server-to-server)

If you really need a confidential client (some advanced scenarios), under **Certificates & secrets → New client secret**. Note the value (shown ONCE). Then set `MS365_MCP_CLIENT_SECRET` in your env. **Most users do NOT need this.**

## 3 — Configure environment

Create `.env` in your working directory, or export the variables in your shell profile :

```dotenv
# Required
MS365_MCP_CLIENT_ID=<your app registration client id>
MS365_MCP_TENANT_ID=<your directory tenant id>

# Optional — confidential client (advanced, usually not needed)
# MS365_MCP_CLIENT_SECRET=<secret value>

# Optional — sovereign clouds
# MS365_MCP_CLOUD_TYPE=global   # default
# MS365_MCP_CLOUD_TYPE=gcc      # US Gov Community Cloud
# MS365_MCP_CLOUD_TYPE=gccHigh  # US Gov GCC High
# MS365_MCP_CLOUD_TYPE=china    # 21Vianet (China)

# Optional — log level
# LOG_LEVEL=info  # info | warn | error | debug

# Optional — logs directory (XDG_STATE_HOME default is ~/.local/state/outlook-mcp/logs)
# OUTLOOK_MCP_LOGS_DIR=/var/log/outlook-mcp

# HTTP-public mode ONLY (required for non-loopback bind)
# OUTLOOK_MCP_PUBLIC_URL=https://outlook-mcp.example.com
# OUTLOOK_MCP_TRUSTED_PROXIES=10.0.0.1,10.0.0.2
# OUTLOOK_MCP_CORS_ORIGIN=https://app.example.com   # exact origin only
# OUTLOOK_MCP_RATELIMIT_PER_MIN=100
```

For sovereign / Government clouds, see [`src/cloud-config.ts`](./src/cloud-config.ts) for the full list of endpoints.

### Alternative : Azure Key Vault as secret store

If you prefer not to keep secrets in env files :

```dotenv
MS365_MCP_KEYVAULT_URL=https://your-keyvault.vault.azure.net/
```

Authenticate to Azure via `DefaultAzureCredential` (managed identity, Azure CLI, env vars — see [Azure SDK docs](https://learn.microsoft.com/en-us/javascript/api/overview/azure/identity-readme)). Secrets must be named :

- `ms365-mcp-client-id`
- `ms365-mcp-tenant-id`
- `ms365-mcp-client-secret` (optional)
- `ms365-mcp-cloud-type` (optional, default `global`)

## 4 — First authentication

```bash
outlook-mcp-hardened --login
```

You'll see :

```
[outlook-mcp] To sign in, use a web browser to open the page
https://microsoft.com/devicelogin and enter the code ABC123XYZ
to authenticate.
```

Open the URL, enter the code, complete authentication. The token is then cached :

- **macOS** : in Keychain under service `outlook-mcp-hardened`
- **Linux** with `libsecret` : in your Secret Service (GNOME Keyring, KWallet, etc.)
- **Linux without `libsecret`** : in a 0600-permissioned JSON file under `$XDG_STATE_HOME/outlook-mcp/`
- **Windows** : in Credential Manager

Verify :

```bash
outlook-mcp-hardened --verify-login
# → Token OK, user: alice@example.com
```

## 5 — Pick an execution mode

### Mode A — stdio (default, recommended for local agents)

```bash
outlook-mcp-hardened                          # read-only
outlook-mcp-hardened --enable-send            # opt-in mail writes
outlook-mcp-hardened --enable-write           # opt-in calendar writes
outlook-mcp-hardened --enable-send --enable-write
```

The server speaks MCP over stdin/stdout. Wire any MCP-compliant client to the binary path. See [`CLIENT_CONFIG.md`](./CLIENT_CONFIG.md) for examples.

### Mode B — http-loopback (local HTTP testing only)

```bash
outlook-mcp-hardened --http 127.0.0.1:3000
```

The server listens on `127.0.0.1:3000` only. OAuth discovery served at :

- `http://127.0.0.1:3000/.well-known/oauth-authorization-server`
- `http://127.0.0.1:3000/.well-known/oauth-protected-resource`
- `http://127.0.0.1:3000/.well-known/oauth-protected-resource/mcp`

This mode is for **testing the OAuth flow locally** (e.g., with `mcp-inspector`'s HTTP transport). It is NOT a secure remote deployment — anything that can reach `127.0.0.1` on your host can hit `/mcp` without auth.

### Mode C — http-public (remote deployment, behind reverse proxy)

Required configuration (boot guard refuses to start otherwise) :

```dotenv
OUTLOOK_MCP_PUBLIC_URL=https://outlook-mcp.example.com
OUTLOOK_MCP_TRUSTED_PROXIES=10.0.0.1
```

```bash
# Bind to all interfaces (the reverse proxy is in front)
outlook-mcp-hardened --http 0.0.0.0:3000
```

The reverse proxy (nginx, Caddy, etc.) MUST :

- Terminate TLS with a valid certificate
- Inject `X-Forwarded-Proto: https`
- Inject `X-Forwarded-For` correctly (append the client IP, do not blindly trust the client's value)
- List its own outbound IP in `OUTLOOK_MCP_TRUSTED_PROXIES`

For nginx + Caddy templates, hardened systemd unit, monitoring, and rollback procedures, see [`docs/HANDOFF_INFRA.md`](./docs/HANDOFF_INFRA.md). Ready-to-deploy templates in [`deploy/`](./deploy/) :

- [`deploy/outlook-mcp.service`](./deploy/outlook-mcp.service) — hardened systemd unit
- [`deploy/outlook-mcp.env.example`](./deploy/outlook-mcp.env.example) — env file template
- [`deploy/nginx-outlook-mcp.conf`](./deploy/nginx-outlook-mcp.conf) — nginx reverse proxy
- [`deploy/Caddyfile`](./deploy/Caddyfile) — Caddy alternative (TLS automatic)
- [`deploy/Dockerfile`](./deploy/Dockerfile) + [`deploy/docker-compose.yml`](./deploy/docker-compose.yml) — container deployment

#### Boot guards

The server refuses to start in HTTP mode if :

- `host` ≠ loopback (`127.0.0.1`, `::1`, `localhost`) AND `OUTLOOK_MCP_TRUSTED_PROXIES` is unset
- `host` ≠ loopback AND `OUTLOOK_MCP_PUBLIC_URL` is unset
- `OUTLOOK_MCP_PUBLIC_URL` does not start with `https://` for non-loopback bind
- `OUTLOOK_MCP_CORS_ORIGIN=*` without `OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true` (explicit opt-in to the wildcard footgun)

## 6 — Logout (optional)

```bash
outlook-mcp-hardened --logout
```

Removes the token from the keychain / file. Subsequent `--login` starts fresh.

## 7 — Multi-account

If you sign in with multiple accounts (e.g., personal + work) :

```bash
outlook-mcp-hardened --list-accounts
# → 1. alice@personal.com (active)
# → 2. alice@work.example.com

outlook-mcp-hardened --select-account 2

outlook-mcp-hardened --remove-account 1
```

In multi-account mode, every tool gains an `account` parameter (enum of registered accounts) so the agent can pick which mailbox to act on.

## Next steps

- [`CLIENT_CONFIG.md`](./CLIENT_CONFIG.md) — wire your specific MCP client (Claude Desktop, Cline, Continue, mcp-inspector, custom)
- [`USAGE.md`](./USAGE.md) — common workflows
- [`API_REFERENCE.md`](./API_REFERENCE.md) — full tool catalog
- [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) — when things go wrong

## Uninstall

```bash
outlook-mcp-hardened --logout                 # clear token cache
npm uninstall -g @ixtria/outlook-mcp-hardened # remove the binary
rm -rf "$XDG_STATE_HOME/outlook-mcp"          # or ~/.local/state/outlook-mcp
```

The Azure App Registration on the Microsoft side remains until you delete it from the Azure portal.
