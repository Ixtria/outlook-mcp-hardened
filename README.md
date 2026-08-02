# `@ixtria/outlook-mcp-hardened`

[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A522-green.svg)](https://nodejs.org/)
[![mcp](https://img.shields.io/badge/protocol-MCP-purple.svg)](https://modelcontextprotocol.io/)
[![tests](https://img.shields.io/badge/tests-536%20passing-brightgreen.svg)](#testing)
[![lint](https://img.shields.io/badge/lint-0%20warnings%20enforced-brightgreen.svg)](./docs/adr/0004-discipline-de-maintenance.md)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Ixtria/outlook-mcp-hardened/badge)](https://scorecard.dev/viewer/?uri=github.com/Ixtria/outlook-mcp-hardened)
[![Security audit](https://img.shields.io/badge/security-see%20SECURITY.md-informational.svg)](./SECURITY.md)

A **security-hardened**, **client-agnostic** Model Context Protocol (MCP) server for **Microsoft Outlook** (Mail + Calendar). Designed for self-hosting by independent professionals, small teams, and anyone who needs Outlook through MCP **without trusting a third-party SaaS bridge**.

> ✅ **v0.4.0 released 2026-08-02** — cycle de remédiation post-audit stratégique complet : **37/37 tickets fermés**, 536 tests comportementaux (+145), `--max-warnings 0` enforced, CI + Security + Scorecard + ZAP verts. Détails complets dans le [CHANGELOG](./CHANGELOG.md#040--2026-08-02--remédiation-post-audit-stratégique). Posture **OSS solo-mainteneur security-serious** défendable ; posture nFADP **self-attestée** documentée sans engagement légal ([`docs/COMPLIANCE-nFADP.md`](./docs/COMPLIANCE-nFADP.md)).

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
| Audit trail | none | **JSON line on stderr** per outbound Graph call ET per OAuth event (`/authorize`, `/token`, `/register`, verify) avec HMAC-SHA256-hashed account + `request_id` corrélation (v0.4.0). Source de vérité : [`docs/AUDIT_EVENTS.md`](./docs/AUDIT_EVENTS.md). |
| Email body returned to LLM | raw | wrapped in `<untrusted_content>` with Unicode-obfuscation strip + tag neutralisation (defense against [Plane-14 steganography attacks](https://en.wikipedia.org/wiki/Tags_(Unicode_block))) |
| OAuth ingress (HTTP mode) | passthrough | **hardened proxy** : exact-match `redirect_uri`, PKCE S256 mandatory, scope intersection, trust-proxy IP allowlist, [ADR-0003](docs/adr/0003-pivot-niveau-b-oauth-proxy-hardened.md) |
| Logs PII | raw emails / bodies | **redacted** : emails → `[email:HASH]` (correlatable to audit-log entries), Bearer tokens → `[redacted]`, JWTs → `[JWT redacted]` |
| Telemetry | none | **contractually zero** — no analytics, no phone-home in first-party code. License-checker CI job enforces permissive licenses. Automated phone-home detection on new deps reste roadmap (Planned v0.5). |
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

- **Tier 0 — CI/CD automated** : CodeQL, Semgrep (OWASP + JWT + Node + Secrets), OSV-Scanner, TruffleHog, Dependabot (auto-merge PATCH only), ESLint-plugin-security (`--max-warnings 0` enforced), license-checker, OpenSSF Scorecard, StepSecurity harden-runner (audit mode), OWASP ZAP baseline. Toutes les GitHub Actions **pinnées par SHA 40-char** (supply chain). Weekly cron + per-PR + per-push.
- **Tier 1 — Multi-school LLM cross-reviews** : 4 rounds initiaux + **3 passes contradictoires cross-vendor GPT-5.5** (Codex) sur les décisions structurantes. N0 Claude `pr-review-toolkit:code-reviewer`, N3 [`mcp-vault`](https://github.com/Ixtria/mcp-vault) peer review via [`agent-hub`](https://github.com/Ixtria/agent-hub), N4 expert-OAuth-adversarial. **8 BLOCKERS + 16 IMPORTANT + 37 tickets v0.4.0 fixés**, fixes [tracés ligne-à-ligne](docs/plans/).
- **Tier 2 — Adversarial active** : property-based testing avec `fast-check` (200 random inputs × 24 propriétés, 0 invariant cassé), OWASP ZAP baseline scan en CI, chaos audit-salt étendu (TOCTOU, symlink swap, NUL byte, PATH_MAX, FS read-only).
- **Tier 3 — Audit humain expert** : non effectué. Le retour N4 + contradictoire GPT-5.5 simulent au mieux ce niveau mais ne le remplacent pas pour un déploiement à des tiers.

Threat model actuel (Niveau B OAuth proxy) : [`docs/threat-model/2026-08-02-oauth-proxy-niveau-b.md`](./docs/threat-model/2026-08-02-oauth-proxy-niveau-b.md).
Discipline de maintenance : [`docs/adr/0004-discipline-de-maintenance.md`](./docs/adr/0004-discipline-de-maintenance.md).

## What this fork does **not** protect against

- **A malicious MCP client running locally** — if the agent on the operator's machine is compromised, that agent can invoke any registered tool. The fork shrinks the blast radius via read-only defaults and explicit write opt-ins, but it does not police the agent itself.
- **Microsoft Graph throttling** — there is no local rate limiter for outbound calls. Graph enforces its own throttling and we surface the error.
- **Multi-tenant SaaS isolation** — one running instance serves one operator. Concurrent users per instance are not designed for.
- **Content policy / DLP** — what an operator (or an agent on their behalf) sends in a reply is between them and their compliance team.
- **A novel vulnerability in `@azure/msal-node`, `@modelcontextprotocol/sdk`, `express`, or `winston`** — `npm audit` is wired into CI but a 0-day in upstream is out of our control.

For a full STRIDE breakdown (Niveau B OAuth proxy, actuel) : [`docs/threat-model/2026-08-02-oauth-proxy-niveau-b.md`](./docs/threat-model/2026-08-02-oauth-proxy-niveau-b.md). Incident response runbook : [`docs/INCIDENT-RESPONSE.md`](./docs/INCIDENT-RESPONSE.md).

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
| [`docs/adr/`](./docs/adr/) | Reviewers — architectural decision records (incl. ADR-0004 discipline maintenance) |
| [`docs/AUDIT_EVENTS.md`](./docs/AUDIT_EVENTS.md) | Ops + auditors — source de vérité des events audités (Graph + OAuth) + politique d'alerting |
| [`docs/INCIDENT-RESPONSE.md`](./docs/INCIDENT-RESPONSE.md) | Ops — runbook par type d'incident (leak token, dep compromise, egress violation, CVE) |
| [`docs/COMPLIANCE-nFADP.md`](./docs/COMPLIANCE-nFADP.md) | DPO PME — posture nFADP déclarative self-attested (RoPA + DPIA + DFD, non-audited) |
| [`docs/RELEASING.md`](./docs/RELEASING.md) | Maintainers — release process + deprecation policy + support matrix |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Contributors — review workflow, quality gates, commit conventions |
| [`CHANGELOG.md`](./CHANGELOG.md) | Everyone — release-by-release security + breaking changes |

## Testing

```bash
npm test                       # 536 tests across 49 files
npm run test:coverage          # with v8 coverage report
npm run lint                   # --max-warnings 0 enforced
```

Coverage is enforced ≥ 80% on security-critical modules :

| Module | Lines | Branches |
|---|---|---|
| `src/oauth/**` | 100 % | ≥ 92 % |
| `src/security/**` | ≥ 92 % | ≥ 86 % |
| `src/lib/trust-proxy.ts` | 100 % | ≥ 94 % |
| `src/request-context.ts` | 100 % | 100 % |

Test categories :

- **Behavioral** (v0.4.0 MAINT-TEST-BEHAV) — HTTP fixture réutilisable (`test/helpers/oauth-server-fixture.ts`), interdit `SOURCE.toContain(...)` (ADR-0004 Règle 3)
- **E2E full-stack** — 8 routes OAuth réelles (`test/e2e/oauth-routes.test.ts`)
- **Contract MCP + RFC conformance** — `test/mcp-contract.test.ts` + `test/rfc-conformance/*` labellés RFC 7591 / 6749 / 9700 / 8707 pour traçabilité audit
- **Property-based** ([`src/oauth/__tests__/property-based.test.ts`](./src/oauth/__tests__/property-based.test.ts)) — 200 random inputs × 24 propriétés via `fast-check` : `validateRedirectUri`, `intersectScopes`, `resolveClientIp`
- **PKCE flood** — 10 001 requêtes concurrentes, LRU eviction validation
- **Chaos audit-salt** — TOCTOU, symlink swap, NUL byte, PATH_MAX, FS read-only
- **Health k8s** — `/live` (liveness) ≠ `/ready` (readiness), `/health` alias rétro-compat

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

**Supply-chain hardening (v0.4.0)** :
- All GitHub Actions **pinned by 40-char SHA** (SEC-05) — `trufflesecurity/trufflehog@main` mutable branch éliminée
- **SBOM CycloneDX** workflow dormant préparé (`.github/workflows/publish.yml`) — attend OIDC trusted publishing côté npm pour activer `npm publish --provenance`
- **Dependabot auto-merge PATCH only** — minor + major restent en review manuel (OAuth/sécu)
- **License compliance enforced in CI** : MIT, Apache-2.0, BSD-2/3-Clause, ISC, CC0-1.0, Unlicense, 0BSD, BlueOak-1.0.0, Python-2.0 only. GPL/AGPL refused
- `publish.yml` (dormant) hardening : `contents:read` least-priv, `persist-credentials:false`, `--ignore-scripts`, `harden-runner` audit

## Roadmap

### v0.4.0 (current — 2026-08-02)

Remédiation post-audit stratégique. **37/37 tickets fermés**. Highlights :

- ✅ SEC-01 P0 refresh token M365 leak fix + prévention comportementale
- ✅ RUNTIME-SEC-01 posture runtime (validation boot permissions, TOCTOU, symlink refuse)
- ✅ SEC-05 GitHub Actions pinnées par SHA 40-char
- ✅ AUTO-01/02/03/04 Dependabot automerge PATCH + Scorecard + harden-runner + Node 22/24
- ✅ OBS-02/03/04/05/07 audit events OAuth + PII redactor deep + request_id + winston JSON
- ✅ OBS-06/08 health `/live` ≠ `/ready` k8s + politique alerting
- ✅ GOV-01/02/03/04/05 nFADP self-attested + threat model Niveau B + IR runbook + OSS baseline + RELEASING
- ✅ SUP-01 SBOM CycloneDX workflow dormant + hardening
- ✅ TEST-01/02/03/04/06 E2E full-stack + PKCE flood + MCP contract + chaos + RFC conformance
- ✅ MAINT-LINT-0 : 150 → 0 warnings, `--max-warnings 0` enforced
- ✅ HTTP-public deployment kit intégré (systemd + nginx + Caddy + Docker)

Détails : [CHANGELOG v0.4.0](./CHANGELOG.md#040--2026-08-02--remédiation-post-audit-stratégique).

### Planned v0.5

- Architectural refactor : drop `mcpAuthRouter` mount, all OAuth endpoints hand-rolled (eliminates SDK-imported attack surface)
- HMAC verifier cache (60s TTL) to reduce Graph `/me` round-trips
- `/token` endpoint RFC 6749 §5.2 compliance (currently 500 instead of 400 invalid_grant)
- `pkceSweepHandle` graceful shutdown
- AAD error body sanitization (trace_id, correlation_id stripped before log)
- SUP-01-PROV : `npm publish --provenance` activation post OIDC npm setup
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
