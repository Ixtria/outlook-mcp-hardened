# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `@ixtria/outlook-mcp-hardened`, please report it responsibly.

**Preferred channel — GitHub Private Vulnerability Reporting (PVR)**:
Go to the [Security Advisories page](../../security/advisories/new) and submit a new advisory.

**Alternative channel — Email**:
Send details to **security@ixtria.ch**. PGP key available on request.

Please **do not** open public issues for security vulnerabilities.

## Scope

This project is a security-hardened fork of [`ms-365-mcp-server`](https://github.com/softeria/ms-365-mcp-server) focused on Microsoft Outlook (Mail + Calendar) via MCP. The hardening layers we own and triage:

- **Egress allowlist** — network boundary enforcement
- **Audit trail** — request logging integrity
- **Anti-prompt-injection** — wrapping of untrusted mail content
- **Token storage** — local keychain / encrypted fallback
- **Scope minimisation** — read-first flags (`--enable-send`, `--enable-write`)

Vulnerabilities in upstream code that we inherited unchanged will be forwarded to Softeria when applicable, alongside our own patch.

## Response Time

We aim to acknowledge reports within **3 business days** and provide a remediation timeline within **10 business days**. Critical issues affecting data confidentiality or allowing token exfiltration will be prioritised.

## Threat Model

Voir [`docs/threat-model/2026-05-10-oauth-as-threat-model.md`](docs/threat-model/2026-05-10-oauth-as-threat-model.md) pour le détail STRIDE par surface (DCR, /authorize, /token, JWKS, /mcp, token-exchange, SQLite, egress) et les politiques de recovery (post-restore, post-reuse-detection, post-rotation-failure).

## Architecture sécurité

- ADR-0001 — [Grille cross-LLM review N0+N1+N2+N3](docs/adr/0001-cross-llm-review-grid.md)
- ADR-0002 — [OAuth Trust Policy & AS Architecture](docs/adr/0002-oauth-trust-policy-and-as-architecture.md) (DCR registered-only par défaut, AS intégré côté ingress, MSAL device code conservé côté egress)
- Matrice modes — [`docs/MODES.md`](docs/MODES.md) (stdio / http-loopback / http-public, préconditions bloquantes)
- SPECS OAuth — [`SPECS-OAUTH-MCP.md`](SPECS-OAUTH-MCP.md) v2 (13 findings cross-review codex intégrés)

## Méthode de review sécurité

Toute évolution touchant la surface auth, l'egress guard, ou la couche réseau passe par une cross-review multi-LLM avant merge (ADR-0001) :

- **N0** Claude sub-agent `pr-review-toolkit:code-reviewer`
- **N1** `codex review` (gpt-5.4) — bloque sur BLOCKER cross-school
- **N2** ixtriasrv local (qwen36-27b + devstral-small-2) — warn-only
- **N3** mcp-vault peer review via bus agent-hub (optionnel, patterns partagés)

Chaque finding BLOCKER/IMPORTANT doit fournir un `repro_runtime` exécutable (schema V3 anti-hallucination).

## Out of Scope v0.2

- Malicious MCP clients (trust model: operator runs the agent)
- Rate limiting Microsoft Graph (délégué à Graph côté egress)
- Multi-tenant SaaS isolation (mono-instance v0.2 ; multi-account M365 OK)
- WAF / filtrage applicatif avancé (délégué au reverse proxy / Cloudflare)
- Revocation endpoint RFC 7009 (CLI admin `revoke-token` à la place, reporté v0.3)
- Introspection endpoint RFC 7662 (non requis car JWT self-contained)
- mTLS client OAuth (out of scope v1)
- Chiffrement at-rest fichier SQLite (reporté v0.3)
