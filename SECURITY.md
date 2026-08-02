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

**Actuel (v0.4.0, Niveau B OAuth proxy)** : [`docs/threat-model/2026-08-02-oauth-proxy-niveau-b.md`](docs/threat-model/2026-08-02-oauth-proxy-niveau-b.md) — STRIDE par surface actuelle (OAuth proxy validation, token verify Bearer, Graph egress).

Historique (superseded) : [`docs/threat-model/2026-05-10-oauth-as-threat-model.md`](docs/threat-model/2026-05-10-oauth-as-threat-model.md) — cible AS intégré, abandonné par ADR-0003.

## Incident Response

Runbook opérationnel par type d'incident (leak token M365, dep compromise, egress violation, refresh token reuse, CVE critique dep prod) : [`docs/INCIDENT-RESPONSE.md`](docs/INCIDENT-RESPONSE.md).

## Architecture sécurité

- ADR-0001 — [Grille cross-LLM review N0+N1+N2+N3](docs/adr/0001-cross-llm-review-grid.md)
- ADR-0002 — [OAuth Trust Policy & AS Architecture](docs/adr/0002-oauth-trust-policy-and-as-architecture.md) (superseded par ADR-0003)
- ADR-0003 — [Pivot Niveau B — OAuth proxy hardened](docs/adr/0003-pivot-niveau-b-oauth-proxy-hardened.md) (architecture actuelle)
- ADR-0004 — [Discipline de maintenance](docs/adr/0004-discipline-de-maintenance.md) (3 gates non-négociables + 1 SLA Dependabot)
- Matrice modes — [`docs/MODES.md`](docs/MODES.md)
- Source de vérité audit events — [`docs/AUDIT_EVENTS.md`](docs/AUDIT_EVENTS.md)

## Compliance posture

**nFADP (Suisse)** — [`docs/COMPLIANCE-nFADP.md`](docs/COMPLIANCE-nFADP.md) : posture déclarative **self-attested, non-auditée, sans engagement légal**. RoPA + DPIA simplifiée + DFD. Un déploiement soumis à la nFADP doit être validé par un DPO ou juriste.

## Méthode de review sécurité

Toute évolution touchant la surface auth, l'egress guard, ou la couche réseau passe par une cross-review multi-LLM avant merge (ADR-0001) :

- **N0** Claude sub-agent `pr-review-toolkit:code-reviewer`
- **N1** `codex review` (GPT-5.5) — bloque sur BLOCKER cross-school
- **N3** mcp-vault peer review via bus agent-hub (optionnel, patterns partagés)
- **N4** expert-OAuth-adversarial sub-agent (fenêtres de review pré-release)
- **Contradictoire cross-vendor** (v0.4.0) : `reviewer-contradictoire` skill lance Codex GPT-5.5 sur les décisions structurantes (plan de remédiation, ADR, choix d'architecture) — casse les biais partagés entre 2 modèles du même labo.

Chaque finding BLOCKER/IMPORTANT doit fournir un `repro_runtime` exécutable (schema V3 anti-hallucination).

## Out of Scope

- Malicious MCP clients (trust model: operator runs the agent)
- Rate limiting Microsoft Graph (délégué à Graph côté egress)
- Multi-tenant SaaS isolation (mono-instance ; multi-account M365 OK)
- WAF / filtrage applicatif avancé (délégué au reverse proxy / Cloudflare)
- Revocation endpoint RFC 7009 (Planned v0.5)
- Introspection endpoint RFC 7662 (non requis car JWT self-contained)
- mTLS client OAuth (out of scope)
- Chiffrement at-rest fichier cache MSAL (délégué à OS keychain via keytar quand disponible)
