# TROUBLESHOOTING — common errors and fixes

Sorted by error message / symptom. Each entry says what's happening, why, and what to do.

## Authentication

### `Token verification failed: 401`

**Symptom** : the server returns 401 on every `/mcp` call, or `--verify-login` fails.

**Cause** : your cached access token is expired (typical lifetime 1h) and the refresh token was either revoked, evicted, or never persisted (e.g., `offline_access` scope was missing during initial consent).

**Fix** :

```bash
outlook-mcp-hardened --logout    # clear stale cache
outlook-mcp-hardened --login     # fresh device code flow
```

If the issue persists after re-login, your Azure App Registration is likely missing the `offline_access` permission — re-check [INSTALL.md §2.2](./INSTALL.md).

### `No accounts found. Please login first.`

**Symptom** : every tool call fails with this message.

**Cause** : the token cache is empty AND the server is not running in HTTP mode (HTTP mode resolves tokens from incoming `Authorization: Bearer` headers per-request).

**Fix** : `outlook-mcp-hardened --login`. Or if you're testing HTTP mode, ensure your client sends a valid Bearer header.

### `keytar not available, falling back to file-based credential storage`

**Symptom** : on first run, this WARN appears.

**Cause** : the optional `keytar` native module failed to load. On Linux, this means `libsecret-1-0` is not installed. On all platforms, this can also mean the prebuilt binary doesn't match your Node version.

**Impact** : tokens are stored in `~/.config/outlook-mcp/token-cache.json` with mode 0600 instead of in the OS keychain. Slightly weaker confidentiality on a multi-user host where root can read your home dir.

**Fix (Linux)** :

```bash
apt install libsecret-1-0       # Debian/Ubuntu
dnf install libsecret           # Fedora
pacman -S libsecret             # Arch
npm rebuild keytar              # rebuild native binding
```

If you don't want keytar at all, this fallback is documented and supported — just be aware of the file-mode confidentiality model.

### `--login` hangs after the device code is shown

**Symptom** : you opened the URL, entered the code, completed auth in the browser, but the CLI process doesn't return.

**Cause** : the browser completed flow but the CLI's polling loop hasn't yet picked up the result (timing window) ; or your tenant requires Conditional Access policies (MFA, compliant device, etc.) that the device code flow doesn't satisfy.

**Fix** :

1. Wait ~30 seconds for the next poll cycle.
2. If still hung, Ctrl+C and try `outlook-mcp-hardened --auth-browser` instead (uses the loopback redirect flow).
3. If Conditional Access blocks it, you'll see an explicit AAD error message. Adjust the policy in Azure portal or use a compliant client device.

### `AADSTS50020: User account from identity provider does not exist in tenant`

**Cause** : you signed in with a personal Microsoft account but the App Registration is single-tenant.

**Fix** : either sign in with an account from your registered tenant, OR change the App Registration to "Accounts in any organizational directory and personal Microsoft accounts" — but understand the consent screen will warn users.

## Networking

### `EgressViolationError: hostname not in allowlist`

**Symptom** : the server crashes at startup or on a specific tool call with `EgressViolationError`.

**Cause** : something in the code or a dependency tried to fetch a host other than `login.microsoftonline.com` or `graph.microsoft.com`. **This is intentional**.

**Fix** : depends on what's hitting the network.

- If it's a known-good dep update (e.g., `@azure/msal-node` calling a new AAD endpoint), file an issue — we may need to extend the allowlist consciously.
- If you can't tell, run with `-v` and the error stack will tell you which call site triggered.
- If you're sure this is hostile (a malicious package phoning home), the egress guard did its job — investigate the dep that triggered.

### `ECONNREFUSED` / `ENOTFOUND` on Microsoft endpoints

**Cause** : DNS resolution failed, your firewall blocks outbound, you're behind a corporate proxy that requires HTTP_PROXY env vars, or you typed the wrong cloud type (e.g., `MS365_MCP_CLOUD_TYPE=china` when you're actually on global).

**Fix** :

```bash
# Test connectivity
curl -v https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration

# If you're behind a proxy
export HTTPS_PROXY=http://corp-proxy.example.com:8080
outlook-mcp-hardened --login
```

If on a sovereign cloud, set `MS365_MCP_CLOUD_TYPE` accordingly (`global`, `gcc`, `gccHigh`, `china`).

## HTTP mode boot guards

### `Refusing to start HTTP server bound to "0.0.0.0" without OUTLOOK_MCP_TRUSTED_PROXIES`

**Cause** : you tried to expose the server on a non-loopback interface without telling it which IPs are trusted reverse proxies.

**Fix** : set `OUTLOOK_MCP_TRUSTED_PROXIES=<nginx_or_caddy_ip>` before starting. If you really want raw exposure (NOT recommended), `OUTLOOK_MCP_TRUSTED_PROXIES=0.0.0.0` would trust any peer, but you'd be opening yourself to XFF spoofing for rate-limit attribution.

### `Refusing to start HTTP server bound to "0.0.0.0" without OUTLOOK_MCP_PUBLIC_URL`

**Cause** : non-loopback bind needs the issuer URL declared at boot (RFC 8414).

**Fix** : `OUTLOOK_MCP_PUBLIC_URL=https://outlook-mcp.example.com outlook-mcp-hardened --http 0.0.0.0:3000`.

### `OUTLOOK_MCP_PUBLIC_URL must use https://`

**Cause** : OAuth discovery endpoints MUST publish `https://` issuer for non-loopback per RFC 8414 §2.

**Fix** : put a TLS-terminating reverse proxy in front and set the public URL accordingly.

### `Refusing to start with OUTLOOK_MCP_CORS_ORIGIN=*`

**Cause** : wildcard CORS to a Bearer-protected resource is a footgun. We refuse at boot unless explicit opt-in.

**Fix** : either set a specific origin (`OUTLOOK_MCP_CORS_ORIGIN=https://app.example.com`) or, if you really know what you're doing, `OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true`.

### `OUTLOOK_MCP_AUDIT_SALT_HEX is set in production`

**Cause** : the test-only env var (used to pin a deterministic salt in tests) is set with `NODE_ENV=production`. This would disable the per-installation random salt.

**Fix** : unset the env var (likely leaked from a CI fixture or Docker base image into your prod env). Let the server generate + persist a fresh salt to `$XDG_STATE_HOME/outlook-mcp/audit-salt`.

## OAuth proxy errors (HTTP mode)

### `400 invalid_request: code_challenge is required (PKCE mandatory)`

**Cause** : your MCP client tried to start the auth code flow without PKCE.

**Fix** : update your client. PKCE S256 is mandatory per RFC 9700 §2.1.1 for public clients. Every recent MCP client supports it ; check your client config for an option you might have disabled.

### `400 invalid_request: code_challenge_method must be S256`

**Cause** : your client sent `code_challenge_method=plain`. We refuse — `plain` defeats the protection PKCE provides for public clients.

**Fix** : configure your client to use S256.

### `400 invalid_request: redirect_uri is not in the registered-clients allowlist`

**Cause** : your client is using a callback URI that's not in our static allowlist. The current allowlist (see `src/oauth/registered-clients.ts`) is :

- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`

**Fix** : if your MCP client legitimately uses a different callback, open a PR adding it to `registered-clients.ts` with cross-review. We deliberately don't accept wildcards.

### `400 invalid_scope: no requested scope is in the registered/known allowlist`

**Cause** : your client asked for a scope that's not in the union of (registered client allowlist ∩ writePolicy-derived known scopes).

**Fix** : either reduce the requested scope to what's enabled (`Mail.Read`, `Calendars.Read`, etc.), or start the server with `--enable-send` / `--enable-write` to expand the writePolicy.

### `405 Method Not Allowed: /authorize accepts GET only`

**Cause** : your client sent a POST to `/authorize`. RFC 6749 allows GET-only, and we explicitly refuse POST to close an SDK bypass (see CHANGELOG N4-B2).

**Fix** : configure your client for GET. Most modern OAuth clients default to GET.

## Multi-account

### Tool returns data from the wrong mailbox

**Cause** : in multi-account mode, you didn't pass an `account` parameter, so the active account was used.

**Fix** :

```
outlook-mcp-hardened --list-accounts        # see which one is active
outlook-mcp-hardened --select-account 2    # switch
```

Or pass `account=alice@work.example.com` in every tool call.

## Logging

### Where are the logs ?

```
$XDG_STATE_HOME/outlook-mcp/logs/             # if XDG_STATE_HOME is set
~/.local/state/outlook-mcp/logs/              # default on Linux
$OUTLOOK_MCP_LOGS_DIR/                        # explicit override
```

Files :
- `mcp-server.log` — info/warn/error from the server itself
- `error.log` — errors only
- The **audit JSON stream** goes to stderr by design (so it survives stdio MCP framing).

### I see `[email:abc12345]` in the logs

**That's correct** — the log redactor scrubs email addresses to a per-installation HMAC hash. The 8-hex correlation handle lets you join `mcp-server.log` entries to the audit JSON stream (which has the full 32-hex hmac-sha256 prefix) without leaking PII to anyone reading the log file.

### I want to disable the redactor temporarily (debugging)

You can't. By design. If you need raw logs for development, work in a test environment with a known dummy email.

## Build / development

### `npm run generate` fails with "No versions available"

**Cause** : your global `.npmrc` has `min-release-age=<days>` and the requested `openapi-zod-client` version is too recent.

**Fix** :

```bash
NPM_CONFIG_MIN_RELEASE_AGE=0 npm run generate
```

Documented in [`CLAUDE.md`](./CLAUDE.md).

### `vi.fn() is not a constructor` in cli.test.ts after vitest upgrade

**Cause** : Vitest 4 changed auto-mock construct behavior.

**Fix** : already applied — use `class MockCommand` instead of `vi.fn(() => mockCommand)`. If you wrote a new test that hit this, mirror the pattern from `test/cli.test.ts`.

## When all else fails

1. **Re-run with `-v`** : `outlook-mcp-hardened -v` enables console logging in addition to file logs.
2. **Check the audit JSON stream on stderr** : it shows exactly which Graph call was attempted with what scopes and what status.
3. **Test the underlying Graph endpoint with curl** :
   ```bash
   curl -H "Authorization: Bearer $(cat ~/.config/outlook-mcp/token-cache.json | jq -r '.AccessToken | values[].secret')" \
     https://graph.microsoft.com/v1.0/me
   ```
   If this fails, the problem is with the token or Graph access, not our server.
4. **Open an issue** with :
   - `outlook-mcp-hardened --version`
   - The exact command you ran
   - The audit JSON line(s) preceding the error
   - The relevant `mcp-server.log` excerpt (after [email:...] redaction — safe to share)

We answer fast.

## Security incident reporting

If you find a vulnerability rather than a bug, follow [`SECURITY.md`](./SECURITY.md). DO NOT open a public issue.
