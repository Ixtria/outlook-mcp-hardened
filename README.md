# `@ixtria/outlook-mcp-hardened`

[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A520-green.svg)](https://nodejs.org/)
[![mcp](https://img.shields.io/badge/protocol-MCP-purple.svg)](https://modelcontextprotocol.io/)
[![tests](https://img.shields.io/badge/tests-380%20passing-brightgreen.svg)](#testing)
[![security audit](https://img.shields.io/badge/security--audit-Tier%200%2B1%2B2%20%E2%9C%93-success.svg)](./SECURITY.md)
[![Security audit](https://img.shields.io/badge/security-see%20SECURITY.md-informational.svg)](./SECURITY.md)

A **security-hardened**, **client-agnostic** Model Context Protocol (MCP) server for **Microsoft Outlook** (Mail + Calendar). Designed for self-hosting by independent professionals, small teams, and anyone who needs Outlook through MCP **without trusting a third-party SaaS bridge**.

> ⚠️ **Status 2026-08-02** : projet en remédiation sécurité active suite audit stratégique. Voir [`docs/plans/2026-08-02-audit-maintenance-strategique.md`](./docs/plans/2026-08-02-audit-maintenance-strategique.md) et [`TICKETS.md`](./TICKETS.md). La posture "hardened" reste défendable niveau **OSS solo-mainteneur security-serious** ; les contrôles runtime (audit trail OAuth, coverage server.ts, backlog Dependabot) sont en cours de fiabilisation — ne pas prendre les badges d'anciennes versions pour argent comptant tant que Lot 1 n'est pas mergé.

Apache-2.0, no telemetry, no phone-home, OS keychain for tokens, audited egress allowlist. Built on the official [MCP SDK](https://github.com/modelcontextprotocol/typescript-sdk) and `@azure/msal-node`. Fork of [`@softeria/ms-365-mcp-server`](https://github.com/softeria/ms-365-mcp-server) with the surface narrowed and the boundaries instrumented.

> **Not affiliated with Microsoft, Anthropic, or Softeria.** Independent project published by [Ixtria SA](https://ixtria.ch).

---

## Why this fork

| | upstream `ms-365-mcp-server` | `@ixtria/outlook-mcp-hardened` |
|---|---|---|
| Scope | Mail, Calendar, Files, Excel, Teams, SharePoint, OneNote, Planner, Contacts, To-Do, Directory | **Mail + Calendar only** |
| Endpoints | 202 | **58** (filtered at build time, whitelisted in `endpoints.json`) |
| Default write policy | write tools registered | **read-only by default** — `--enable-send` / `--enable-write` opt-in required |
| Outbound network | trust the network | **hardcoded allowlist** : `login.microsoftonline.com`, `graph.microsoft.com`. Any other fetch → `EgressViolationError` |
| Token storage | env var or file | **OS keychain** (`keytar`) when available, file fallback with restricted perms |
| Audit trail | none | **JSON line on stderr** per outbound Graph call (tool, method, path, scopes, **HMAC-SHA256-hashed account**, status, duration). **OAuth events (`/authorize`, `/token`, `/register`, verify fail) non couverts en v0.3 — voir tickets OBS-02 / TEST-06.** |
| Email body returned to LLM | raw | wrapped in `<untrusted_content>` with Unicode-obfuscation strip + tag neutralisation (defense against [Plane-14 steganography attacks](https://en.wikipedia.org/wiki/Tags_(Unicode_block))) |
| OAuth ingress (HTTP mode) | passthrough | **hardened proxy** : exact-match `redirect_uri`, PKCE S256 mandatory, scope intersection, trust-proxy IP allowlist, [ADR-0003](docs/adr/0003-pivot-niveau-b-oauth-proxy-hardened.md) |
| Logs PII | raw emails / bodies | **redacted** : emails → `[email:HASH]` (correlatable to audit-log entries), Bearer tokens → `[redacted]`, JWTs → `[JWT redacted]` |
| Telemetry | none | **contractually zero** — no analytics, no phone-home in first-party code. (License-checker CI job enforces permissive licenses ; automated phone-home detection on new deps is roadmap, cf. ticket SEC-05.) |
| License | MIT | Apache-2.0 (MIT attribution retained) |

## Quick start

### Stdio (local — Claude Desktop, Claude Code, Continue, Cline, mcp-inspector, custom)

```bash
npm install -g @ixtria/outlook-mcp-hardened
outlook-mcp-hardened --login          # one-time device code flow
outlook-mcp-hardened                   # read-only by default
```

Then point any MCP-compliant client at the binary via stdio. See [`CLIENT_CONFIG.md`](./CLIENT_CONFIG.md) for examples of generic stdio + HTTP configurations.

### HTTP (remote — behind a reverse proxy)

```bash
# loopback only — local testing
outlook-mcp-hardened --http 127.0.0.1:3000

# public deployment — boot guards refuse 0.0.0.0 without TRUSTED_PROXIES + PUBLIC_URL
OUTLOOK_MCP_TRUSTED_PROXIES=10.0.0.1 \
OUTLOOK_MCP_PUBLIC_URL=https://outlook-mcp.example.com \
outlook-mcp-hardened --http 0.0.0.0:3000
```

See [`docs/MODES.md`](./docs/MODES.md) for the full execution-mode matrix and [`INSTALL.md`](./INSTALL.md) for end-to-end deployment.

### Write opt-in (default is read-only)

```bash
outlook-mcp-hardened --enable-send     # Mail.Send + Mail.ReadWrite tools
outlook-mcp-hardened --enable-write    # Calendars.ReadWrite tools
outlook-mcp-hardened --enable-send --enable-write
```

## Security posture

| Surface | Defense |
|---|---|
| Outbound network | Hardcoded host allowlist with synchronous validation BEFORE every `fetch`. `EgressViolationError` crashes the process at boot if a non-Graph dependency tries to reach out. |
| Account identifiers in logs | HMAC-SHA256 with per-installation salt persisted to `$XDG_STATE_HOME/outlook-mcp/audit-salt` (mode 0600, `O_NOFOLLOW` open). Pseudonymity survives log leak. |
| Email-borne prompt injection | `<untrusted_content>` wrapper with Unicode-obfuscation strip (U+00AD, U+180E, U+2060-2069, U+FE00-FE0F, U+E0000-U+E007F) + tag-neutralisation with `\p{Default_Ignorable_Code_Point}` tolerance. |
| OAuth proxy (HTTP mode) | Exact-match `redirect_uri` allowlist (no wildcards). PKCE S256 mandatory. Scope intersection (`requested ∩ registered ∩ KNOWN`). POST `/authorize` → 405 (closes SDK bypass). Discovery issuer fixed at boot, never reflected from `Host`. |
| Trust proxy / `X-Forwarded-For` | Operator-managed IP allowlist via `OUTLOOK_MCP_TRUSTED_PROXIES`. IPv4 leading-zeros canonicalised. IPv4-mapped IPv6 normalised. Walk XFF right-to-left, stop at first non-trusted hop. |
| PKCE store (HTTP mode) | Bounded LRU (10k entries) + `setInterval` sweep every 60s + state length cap 256 bytes. Closes the DoS-by-flood vector. |
| Body parsers | `express.json({ limit: '10kb' })` + `express.urlencoded({ extended: false, parameterLimit: 20 })`. No `qs` nested-key prototype-pollution surface. |
| Bearer middleware (`/mcp`) | Token validated via `Microsoft Graph /me` round-trip on every request. Forged tokens rejected with `WWW-Authenticate: Bearer error="invalid_token"`. |
| Express error handler | Global catch-all returns minimal JSON `{error, error_description ≤200 chars}`. No stack traces, no filesystem paths, no Express version leaked. |
| Token storage | OS keychain via `keytar` (optional dep) with file fallback (mode 0600). MSAL device-code flow by default. |
| Filesystem | Logs at `$XDG_STATE_HOME/outlook-mcp/logs/` (mode 0700). Salt + cache write with `O_NOFOLLOW | O_EXCL`. |

### Audit history

- **Tier 0 — CI/CD automated** : CodeQL, Semgrep (OWASP + JWT + Node + Secrets), OSV-Scanner, Gitleaks, Dependabot, ESLint-plugin-security, license-checker. Weekly cron + per-PR + per-push.
- **Tier 1 — Multi-school LLM cross-reviews** : 4 rounds (commits b60a690 → 70e8a40). N0 Claude `pr-review-toolkit:code-reviewer`, N3 [`mcp-vault`](https://github.com/Ixtria/mcp-vault) peer review via [`agent-hub`](https://github.com/Ixtria/agent-hub), N4 expert-OAuth-adversarial sub-agent. **8 BLOCKERS + 16 IMPORTANT fixés**, fixes [tracés ligne-à-ligne dans le code](docs/plans/).
- **Tier 2 — Adversarial active** : property-based testing avec `fast-check` (200 random inputs × 24 propriétés, 0 invariant cassé), OWASP ZAP baseline scan en CI.
- **Tier 3 — Audit humain expert** : non effectué. Le retour N4 simule au mieux ce niveau mais ne le remplace pas pour un déploiement à des tiers.

Full audit trail : [`docs/plans/2026-05-16-security-audit-pre-publication.md`](./docs/plans/2026-05-16-security-audit-pre-publication.md).

## What this fork does **not** protect against

- **A malicious MCP client running locally** — if the agent on the operator's machine is compromised, that agent can invoke any registered tool. The fork shrinks the blast radius via read-only defaults and explicit write opt-ins, but it does not police the agent itself.
- **Microsoft Graph throttling** — there is no local rate limiter for outbound calls. Graph enforces its own throttling and we surface the error.
- **Multi-tenant SaaS isolation** — one running instance serves one operator. Concurrent users per instance are not designed for.
- **Content policy / DLP** — what an operator (or an agent on their behalf) sends in a reply is between them and their compliance team.
- **A novel vulnerability in `@azure/msal-node`, `@modelcontextprotocol/sdk`, `express`, or `winston`** — `npm audit` is wired into CI but a 0-day in upstream is out of our control.

For a full STRIDE breakdown : [`docs/threat-model/2026-05-10-oauth-as-threat-model.md`](./docs/threat-model/2026-05-10-oauth-as-threat-model.md).

## Documentation

| Document | Audience |
|---|---|
| [`INSTALL.md`](./INSTALL.md) | Operators — full setup, Azure App Registration, env vars, 3 execution modes |
| [`CLIENT_CONFIG.md`](./CLIENT_CONFIG.md) | Operators — wire any MCP client to this server (stdio or HTTP) |
| [`USAGE.md`](./USAGE.md) | Operators — common workflows (list mail, send reply, calendar, multi-account) |
| [`API_REFERENCE.md`](./API_REFERENCE.md) | Operators + integrators — full tool catalog with scopes, params, examples |
| [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) | Operators — common errors, diagnostics, fixes |
| [`docs/MODES.md`](./docs/MODES.md) | Operators + reviewers — execution-mode security matrix (stdio / http-loopback / http-public) |
| [`SECURITY.md`](./SECURITY.md) | Security researchers — disclosure policy, supported versions, threat model |
| [`docs/adr/`](./docs/adr/) | Reviewers — architectural decision records |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Contributors — review workflow, quality gates, commit conventions |
| [`CHANGELOG.md`](./CHANGELOG.md) | Everyone — release-by-release security + breaking changes |

## Testing

```bash
npm test                       # 380 tests across 34 files
npm run test:coverage          # with v8 coverage report
```

Coverage is enforced ≥ 80% on security-critical modules :

| Module | Lines | Branches |
|---|---|---|
| `src/oauth/**` | 100 % | ≥ 92 % |
| `src/security/**` | ≥ 92 % | ≥ 86 % |
| `src/lib/trust-proxy.ts` | 100 % | ≥ 94 % |
| `src/request-context.ts` | 100 % | 100 % |

Property-based tests in [`src/oauth/__tests__/property-based.test.ts`](./src/oauth/__tests__/property-based.test.ts) verify security invariants over 200 random inputs per property (fast-check) :

- `validateRedirectUri` : never accepts URIs containing control chars, non-https schemes, userinfo, or dangerous percent-encoded sequences.
- `intersectScopes` : output always ⊆ `requested ∩ registered ∩ known`.
- `resolveClientIp` : an attacker connecting directly (not behind a trusted proxy) never wins XFF spoofing.

## Supply chain

```bash
npm audit                  # runs against production deps ; see SECURITY.md for current status
```

Direct production dependencies (8) :

- `@azure/msal-node` ^5.2.2 — Microsoft official OAuth/MSAL library
- `@modelcontextprotocol/sdk` ^1.29.0 — official MCP TypeScript SDK
- `commander` ^11.1.0, `dotenv` ^17.0.1, `express` ^5.2.1, `open` ^11.0.0, `winston` ^3.17.0, `zod` ^3.24.2

Optional dependencies for enhanced features (auto-detected at runtime) :

- `keytar` ^7.9.0 — OS keychain integration (Linux libsecret, macOS Keychain, Windows Credential Manager)
- `@azure/identity` ^4.5.0 + `@azure/keyvault-secrets` ^4.9.0 — Azure Key Vault as alternate secret store

License compliance enforced in CI : MIT, Apache-2.0, BSD-2/3-Clause, ISC, CC0-1.0, Unlicense, 0BSD, BlueOak-1.0.0, Python-2.0 only. GPL/AGPL refused.

## Roadmap

### v0.3.x (current cycle)

- ✅ OAuth proxy hardened (ADR-0003)
- ✅ Multi-school cross-review with 8 BLOCKERS fixed
- ✅ Property-based + ZAP CI
- ✅ HMAC+salt audit pseudonymity
- ✅ HTTP-public deployment kit ([`docs/HANDOFF_INFRA.md`](./docs/HANDOFF_INFRA.md) + [hardened systemd unit](./deploy/outlook-mcp.service) + [nginx](./deploy/nginx-outlook-mcp.conf) / [Caddy](./deploy/Caddyfile) templates + [Docker](./deploy/Dockerfile))
- ⏳ `/token` endpoint RFC 6749 §5.2 compliance (currently 500 instead of 400 invalid_grant)
- ⏳ pkceStore graceful shutdown

### v0.4 (planned)

- Architectural refactor : drop `mcpAuthRouter` mount, all OAuth endpoints hand-rolled (eliminates SDK-imported attack surface)
- HMAC verifier cache (60s TTL) to reduce Graph `/me` round-trips
- Multi-account isolation per request (currently global state — single-user-only)

### Out of scope

- Other M365 surfaces (Files, Excel, Teams, SharePoint, OneNote) — by design
- Mode HTTP without reverse proxy in front (TLS termination delegated)
- Token introspection RFC 7662 (JWT self-contained, no use case)

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). Cross-review obligatoire avant merge sur les surfaces sécurité ; ADRs requises pour les décisions architecturales.

## Security reports

Voir [`SECURITY.md`](./SECURITY.md). Channels :

- GitHub Private Vulnerability Reporting (preferred)
- `security@ixtria.ch`

Reproduction-runtime preferred (V3 anti-hallucination schema documented in [`docs/adr/0001-cross-llm-review-grid.md`](./docs/adr/0001-cross-llm-review-grid.md)). Coordinated disclosure within 48h acknowledgement, 10 business days remediation timeline.

## License

[Apache-2.0](./LICENSE). Derivative of [`ms-365-mcp-server`](https://github.com/softeria/ms-365-mcp-server) (MIT, © 2025 Softeria) — see `LICENSE` for full attribution.

---

*Built and audited by [Ixtria SA](https://ixtria.ch), Switzerland 🇨🇭*
