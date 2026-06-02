# HANDOFF_INFRA — production HTTP-public deployment

Operational handoff document for deploying `outlook-mcp-hardened` behind a TLS-terminating reverse proxy with a hardened systemd service. Audience : the operator who controls the server (`infra` peer in the Ixtria bus, or any third-party operator).

For application-level configuration (env vars, write policy, multi-account), see [`INSTALL.md`](../INSTALL.md). This document covers **only** the deployment-shape concerns : DNS, TLS, reverse proxy, systemd unit, monitoring, rollback.

---

## Architecture

```
                   ┌──────────────┐
   user / agent ───▶  DNS  ────────▶  outlook-mcp.example.com (A/AAAA records)
                   └──────────────┘
                           │
                           ▼
                   ┌──────────────────────────────┐
                   │  Reverse proxy (host A)       │
                   │  - Let's Encrypt TLS          │
                   │  - HSTS + CSP + sec headers   │
                   │  - X-Forwarded-* propre       │
                   │  - rate limit per IP          │
                   │  - request body cap 32 KB     │
                   └──────────────┬───────────────┘
                                  │ http (loopback or trusted LAN)
                                  ▼
                   ┌──────────────────────────────┐
                   │  outlook-mcp-hardened         │
                   │  - systemd unit durci         │
                   │  - bind 127.0.0.1:3000        │
                   │  - OUTLOOK_MCP_TRUSTED_       │
                   │    PROXIES=<proxy_ip>         │
                   │  - OUTLOOK_MCP_PUBLIC_URL=    │
                   │    https://outlook-mcp.exam   │
                   │    ple.com                    │
                   └──────────────┬───────────────┘
                                  │ https outbound (egress allowlist)
                                  ▼
                   ┌──────────────────────────────┐
                   │  Microsoft AAD + Graph        │
                   │  login.microsoftonline.com    │
                   │  graph.microsoft.com          │
                   └──────────────────────────────┘
```

The reverse proxy and the MCP server can run on the same host (simpler, recommended for SME) or on separate hosts (LAN-trusted segment). Both modes are supported.

---

## Prerequisites

| Resource | Requirement |
|---|---|
| Host | Linux x86_64 (Debian 12+, Ubuntu 22.04+, RHEL 9+ tested) with systemd ≥ 247 |
| RAM | ≥ 512 MB free (the server hits ~150 MB steady, plus 512 MB MemoryMax hard cap) |
| Node.js | ≥ 20 LTS (system-wide via nodesource repo OR via `nvm` for the `outlook-mcp` user) |
| Reverse proxy | nginx ≥ 1.18 OR Caddy ≥ 2.4 (configs provided for both) |
| TLS | Let's Encrypt via certbot (nginx) or Caddy automatic |
| DNS | A and/or AAAA record for `outlook-mcp.<your-domain>` pointing to the reverse proxy host |
| Azure | App Registration in Microsoft Entra ID (per [INSTALL.md §2](../INSTALL.md)) |
| Firewall | Outbound HTTPS to `*.microsoftonline.com` + `graph.microsoft.com` open ; inbound 443 from the public Internet |

---

## Step-by-step deployment

### 1 — DNS

Create an A (IPv4) and/or AAAA (IPv6) record :

```
outlook-mcp.example.com.    300  IN  A     <reverse-proxy-public-ip>
outlook-mcp.example.com.    300  IN  AAAA  <reverse-proxy-public-ipv6>
```

Wait for propagation (`dig +short outlook-mcp.example.com`).

### 2 — Reverse proxy + TLS

#### Option A : nginx + certbot

```bash
sudo apt install nginx certbot python3-certbot-nginx
sudo cp deploy/nginx-outlook-mcp.conf /etc/nginx/sites-available/outlook-mcp
# Edit the file : replace outlook-mcp.example.com with your actual domain
sudo $EDITOR /etc/nginx/sites-available/outlook-mcp

sudo ln -s /etc/nginx/sites-available/outlook-mcp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get the certificate (this will modify the nginx config to add SSL)
sudo certbot --nginx -d outlook-mcp.example.com

# Verify HTTPS works (will still 502 — the upstream isn't up yet)
curl -I https://outlook-mcp.example.com/
```

#### Option B : Caddy (TLS automatic)

```bash
sudo apt install caddy
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo $EDITOR /etc/caddy/Caddyfile   # replace example.com with your domain
sudo systemctl reload caddy

# Caddy will obtain a Let's Encrypt cert on first request
curl -I https://outlook-mcp.example.com/
```

### 3 — Create the unprivileged user

```bash
sudo useradd --system --home /var/lib/outlook-mcp --shell /usr/sbin/nologin outlook-mcp
sudo install -d -o outlook-mcp -g outlook-mcp -m 0700 /var/lib/outlook-mcp
sudo install -d -o outlook-mcp -g outlook-mcp -m 0700 /var/log/outlook-mcp
```

### 4 — Install the binary

#### Option A : npm global

```bash
sudo npm install -g @ixtria/outlook-mcp-hardened
which outlook-mcp-hardened    # /usr/bin/outlook-mcp-hardened (or wherever your global prefix is)
```

#### Option B : clone + build (more auditable)

```bash
sudo -u outlook-mcp git clone https://github.com/Ixtria/outlook-mcp-hardened /var/lib/outlook-mcp/source
cd /var/lib/outlook-mcp/source
sudo -u outlook-mcp git checkout v0.3.0    # pin to a released tag
sudo -u outlook-mcp npm ci
sudo -u outlook-mcp npm run build
# In your systemd unit, change ExecStart to:
#   ExecStart=/usr/bin/node /var/lib/outlook-mcp/source/dist/index.js --http 127.0.0.1:3000
```

### 5 — Create the environment file

```bash
sudo cp deploy/outlook-mcp.env.example /etc/outlook-mcp.env
sudo $EDITOR /etc/outlook-mcp.env       # fill in MS365_MCP_CLIENT_ID + TENANT_ID
sudo chown root:outlook-mcp /etc/outlook-mcp.env
sudo chmod 0640 /etc/outlook-mcp.env
```

### 6 — Install the systemd unit

```bash
sudo cp deploy/outlook-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload

# Sanity check : analyse hardening posture
sudo systemd-analyze security outlook-mcp.service
# Target : score ≤ 2.5, rating "OK" or better
```

### 7 — First authentication (manual, one-shot)

The systemd service runs unattended. Before that, you need to acquire the initial token via the device-code flow :

```bash
sudo -u outlook-mcp env $(grep -v '^#' /etc/outlook-mcp.env | xargs -d '\n') \
  XDG_STATE_HOME=/var/lib/outlook-mcp \
  outlook-mcp-hardened --login
```

Open the URL printed, enter the code, complete authentication in your browser. The token cache is written to `/var/lib/outlook-mcp/...`.

Verify :

```bash
sudo -u outlook-mcp env XDG_STATE_HOME=/var/lib/outlook-mcp \
  outlook-mcp-hardened --verify-login
# → Token OK, user: <your-email>@<tenant>
```

### 8 — Start the service

```bash
sudo systemctl enable --now outlook-mcp
sudo systemctl status outlook-mcp
```

Verify :

```bash
# Health check via reverse proxy
curl https://outlook-mcp.example.com/
# Microsoft 365 MCP Server is running

# OAuth discovery
curl -s https://outlook-mcp.example.com/.well-known/oauth-authorization-server | jq
# → issuer must be exactly https://outlook-mcp.example.com (RFC 8414 §2)

# Protected resource discovery
curl -s https://outlook-mcp.example.com/.well-known/oauth-protected-resource/mcp | jq

# Verify the boot guards refused a misconfiguration (negative test)
# Stop the service, unset OUTLOOK_MCP_TRUSTED_PROXIES, try to start it.
# It should refuse with a clear error message pointing at ADR-0003 D6.
```

---

## Monitoring

### Logs

| Stream | Location | Format |
|---|---|---|
| Application logs (info/warn/error) | journald (`journalctl -u outlook-mcp`) + `/var/log/outlook-mcp/mcp-server.log` | structured text, **PII-redacted** |
| Audit trail (one line per Graph call) | journald stderr stream | structured JSON, HMAC-hashed account |
| nginx access | `/var/log/nginx/outlook-mcp.access.log` | nginx combined |
| nginx errors | `/var/log/nginx/outlook-mcp.error.log` | nginx error format |
| Caddy access | `/var/log/caddy/outlook-mcp.access.log` | JSON |

To extract the audit stream :

```bash
journalctl -u outlook-mcp -o cat | grep -E '^\{.*"tool":' | jq -c '.'
```

### Key metrics to alert on

| Metric | Threshold | Action |
|---|---|---|
| `outlook-mcp.service` restart loop | > 5 restarts in 60s (handled by `StartLimit*`) | systemd auto-fails the service ; check `journalctl -xeu outlook-mcp` |
| 5xx rate at the reverse proxy | > 1 % over 5 min | check `/var/log/nginx/outlook-mcp.error.log` and the journald stream |
| Audit stream goes silent | no `tool` line in 1 hour during business hours | service stuck or token expired ; run `--verify-login` |
| `EgressViolationError` in journald | any occurrence | a dependency tried to fetch a non-Microsoft host. Investigate immediately. |
| `pkceStore at capacity` warning | sustained over 10 min | possible DoS flood ; check `OUTLOOK_MCP_RATELIMIT_PER_MIN` + nginx rate_limit zone |
| TLS certificate expiry | < 14 days | certbot/Caddy should auto-renew ; investigate if not |
| Disk usage `/var/log/outlook-mcp` | > 80 % | rotate via logrotate (template below) |

### logrotate

```bash
sudo tee /etc/logrotate.d/outlook-mcp > /dev/null <<'EOF'
/var/log/outlook-mcp/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    notifempty
    missingok
    create 0600 outlook-mcp outlook-mcp
    sharedscripts
    postrotate
        systemctl reload outlook-mcp 2>/dev/null || true
    endscript
}
EOF
```

---

## Rollback

### Quick rollback (same version, restart)

```bash
sudo systemctl restart outlook-mcp
sudo systemctl status outlook-mcp
```

### Rollback to previous npm version

```bash
sudo systemctl stop outlook-mcp
sudo npm install -g @ixtria/outlook-mcp-hardened@<previous-version>
sudo systemctl start outlook-mcp
```

Available versions :

- `0.1.0` — initial hardening fork (basic egress + audit)
- `0.2.0` — OAuth proxy hardened (ADR-0003), Tier 0/1/2 audit
- `0.3.0` — pre-publication audit complete (current)

### Rollback from git checkout install

```bash
sudo systemctl stop outlook-mcp
cd /var/lib/outlook-mcp/source
sudo -u outlook-mcp git checkout v0.2.0   # or previous tag
sudo -u outlook-mcp npm ci
sudo -u outlook-mcp npm run build
sudo systemctl start outlook-mcp
```

### Full rollback (server unhealthy, return to plain Microsoft Graph access)

Stop the systemd service and remove the reverse-proxy site config. Users fall back to their Microsoft Graph clients (Outlook Web, Outlook desktop, etc.) — `outlook-mcp-hardened` is **not** in the critical path of mail delivery, it only provides an MCP layer on top of Graph.

```bash
sudo systemctl stop outlook-mcp
sudo systemctl disable outlook-mcp
sudo rm /etc/nginx/sites-enabled/outlook-mcp  # or comment out the site block in Caddyfile
sudo nginx -t && sudo systemctl reload nginx
```

The token cache remains in `/var/lib/outlook-mcp` and can be reused later if you re-enable the service.

---

## Backup

What to back up :

- `/etc/outlook-mcp.env` — secrets (client ID, tenant ID, optional client secret)
- `/var/lib/outlook-mcp/outlook-mcp/audit-salt` — per-installation HMAC salt. **If you lose this, all historical audit log entries become un-correlatable to new ones (intentional pseudonymity boundary).**
- `/var/lib/outlook-mcp/outlook-mcp/...token-cache...` — optional. The token cache can be regenerated by re-running `--login`, so backup is convenience, not necessity.

Recommended : encrypted off-host backup via your existing operational pipeline (Borg, restic, rsync to encrypted storage, etc.).

---

## Security posture verification

Run after deployment to confirm the hardening is active :

```bash
# 1. systemd hardening score
sudo systemd-analyze security outlook-mcp.service
# Expected: total exposure level ≤ 2.5

# 2. TLS posture (use external tools)
nmap --script ssl-enum-ciphers -p 443 outlook-mcp.example.com
# Expected: only TLS 1.2 + 1.3, no weak ciphers
curl -s https://www.ssllabs.com/ssltest/  # SSL Labs grade ≥ A

# 3. Security headers
curl -sI https://outlook-mcp.example.com/ | grep -iE 'strict-transport|content-security|frame-options|content-type-options|referrer-policy'
# Expected: all 5 headers present

# 4. OAuth discovery emits exact PUBLIC_URL as issuer (not Host header reflection)
curl -s https://outlook-mcp.example.com/.well-known/oauth-authorization-server | jq -r .issuer
# Expected: exactly https://outlook-mcp.example.com (no trailing slash, no port, no Host injection)

# 5. Boot guards refuse misconfiguration (negative test on a staging copy)
# Set OUTLOOK_MCP_TRUSTED_PROXIES to empty in /etc/outlook-mcp.env and try to restart.
# Service must refuse to start with an explicit error.

# 6. Egress allowlist holds
sudo journalctl -u outlook-mcp -n 100 | grep -i EgressViolationError
# Expected: empty (no violations seen)

# 7. PII redactor active
sudo journalctl -u outlook-mcp -n 1000 | grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+' | head
# Expected: empty (no raw email in logs — they should be `[email:HASH]`)

# 8. npm audit on the installed copy
cd /var/lib/outlook-mcp/source 2>/dev/null && sudo -u outlook-mcp npm audit --omit=dev
# Expected: 0 vulnerabilities at release time
```

If any of these fails, **do not put the deployment in production until fixed**.

---

## Known operational limitations

- **Single-user design** — one running instance serves one Microsoft account. To run multiple operators on the same host, deploy multiple systemd unit instances (`outlook-mcp@alice.service`, `outlook-mcp@bob.service`) with separate XDG_STATE_HOME dirs and separate Azure App Registrations if isolation requires it.

- **Token expiry handling** — the device-code flow refresh token is good for ~90 days by default (configurable in Azure AD). When it expires, the service starts returning 401 on `/mcp`. Re-run `--login` manually (cf. step 7).

- **Graph throttling** — outlook-mcp does not retry-with-backoff on Microsoft Graph 429. The MCP client (LLM agent) sees the throttle. Set agent-side retry policy if you have heavy workloads.

- **No multi-account in HTTP mode** — multi-account is a stdio/CLI feature ; HTTP mode operates with the single token cached in XDG_STATE_HOME.

- **`mcpAuthRouter` SDK fallback** — for any OAuth endpoint we don't hand-roll, the `@modelcontextprotocol/sdk` router handles it. We've defensively wired `getClient()` to the registered-clients allowlist (N3 C1 fix) and intercepted `POST /authorize` with 405 (N4 B2 fix). v0.4 will drop the SDK mount entirely. Until then, **do not deploy v0.3.x if you don't trust the SDK package itself** — `npm audit` is your primary signal.

---

## Contact + escalation

| Scenario | Channel |
|---|---|
| Functional bug in `outlook-mcp-hardened` | GitHub issue : https://github.com/Ixtria/outlook-mcp-hardened/issues |
| Security vulnerability | GitHub Private Vulnerability Reporting OR `security@ixtria.ch` (see [SECURITY.md](../SECURITY.md)) |
| Operational incident on a specific deployment | depends on your org — Ixtria internal channels for Ixtria deployments |
| Microsoft Graph degradation | https://status.office.com/ |
| Let's Encrypt outage (cert renewal failed) | https://letsencrypt.status.io/ |

---

## Appendix : `systemd-analyze security` interpretation

Expected output (approximate, with the unit as shipped) :

```
→ Overall exposure level for outlook-mcp.service: 1.7 OK 🙂

Setting / Description                                             Exposure
ProtectHome=true …                                                       ✓
ProtectSystem=strict …                                                   ✓
PrivateTmp=true …                                                        ✓
PrivateDevices=true …                                                    ✓
NoNewPrivileges=true …                                                   ✓
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 …                       ✓
SystemCallFilter=@system-service …                                       ✓
CapabilityBoundingSet= …                                                 ✓
RestrictNamespaces=true …                                                ✓
MemoryDenyWriteExecute=true …                                            ✓
…
```

Score interpretation :

- **0.0 - 1.0** — "Safe" (top tier, comparable to systemd-resolved)
- **1.0 - 2.5** — "OK" (recommended target for outlook-mcp)
- **2.5 - 4.0** — "Medium exposure" (acceptable for non-network-facing services)
- **4.0+** — "Exposed" (do not deploy as-is)
