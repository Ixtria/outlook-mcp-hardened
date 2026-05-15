# Plan d'intégration `mcp-vault` → `outlook-mcp-hardened` — v2

> **Statut** : v2 — intègre retour mcp-vault peer 2026-05-10 (APPROVED + 2 réserves) + cross-review codex 13 findings + ADR-0002.
> **Date** : 2026-05-10
> **Périmètre** : transposer les patterns sécurité/qualité/méthode validés par mcp-vault v0.3.4 (2678 LOC, 1043 LOC OAuth) vers outlook-mcp-hardened (TypeScript, mode http-public).

---

## 1. Mise à plat — qui fait quoi

| Axe | mcp-vault | outlook-mcp-hardened |
|---|---|---|
| Langage | Python 3.11+ | TypeScript strict |
| Sens du trafic | **Entrant** (sert des fichiers) | **Sortant** (consomme Graph) + entrant (mode http-public) |
| Transport | Streamable HTTP only | stdio (défaut) + http-loopback + http-public (cf. [`docs/MODES.md`](docs/MODES.md)) |
| Auth in | Bearer multi-tokens OU OAuth 2.1 intégré (DCR) | OAuth AS intégré (ADR-0002 — DCR registered-only par défaut) |
| Auth out | N/A | MSAL device code, conservé tel quel (D3 ADR-0002) |
| Storage | SQLite (tokens, audit, OAuth clients, JWKS) | SQLite (idem, schéma adapté — voir SPECS v2 §10) |
| Maturité | v0.3.4 | v0.1.0 → cible v0.2.0 post-cross-review |

---

## 2. Inventaire patterns mcp-vault — verdict actualisé

| # | Pattern | Verdict v2 | Notes |
|---|---|---|---|
| P1 | ADR-0001 cross-LLM review grid (N0+N1+N2+N3) | ✅ Adopté | `docs/adr/0001-cross-llm-review-grid.md` créé |
| P2 | CHANGELOG.md keepachangelog | ✅ Adopté | `CHANGELOG.md` créé, pas de backfill |
| P3 | Quality gate 3 niveaux (lint+types+tests cov ≥80%) | ✅ À implémenter | Ticket T11 (Lot A) |
| P4 | Spec design obligatoire avant code | ✅ Adopté | `docs/specs/` + `docs/plans/TEMPLATE.md` |
| P5 | SECURITY.md structuré | ✅ Adopté | `SECURITY.md` enrichi |
| P6 | TDD obligatoire modules sensibles | ✅ Adopté | SPECS v2 §15 |
| P7 | OAuth intégré DCR + /authorize + /token + JWKS + consent | ✅ Cf. SPECS v2 | **Réserve mcp-vault** : lire `oauth/` package complet (1043 LOC), pas juste server.py |
| P8 | Scope intersection stricte | ✅ Codé normatif | SPECS v2 §6 step 6 |
| P9 | Trusted-redirect exception (mcp-vault v0.3.4 Option B) | ❌ **Rejeté** | Codex I9 + ADR-0002 D5. On enregistre les scopes par client en `oauth-clients.json` plutôt qu'une exception transversale |
| P10 | DCR redirect_uri `fullmatch` strict | ✅ Adopté + durci | SPECS v2 §5 (rejet `\n`, `%2F`, etc.) |
| P11 | Rate-limit in-memory + persistant SQLite, **clé IP** | ✅ Adopté | SPECS v2 §11 |
| P12 | XFF rightmost | ⚠️ **Reformulé** | Codex I8 a contesté. Notre choix : trust-proxy model explicite (cf. [`docs/MODES.md`](docs/MODES.md) + SPECS v2 §12). On scanne les hops droite-à-gauche en sautant les proxies trusted, on s'arrête au premier non-trusted. |
| P13 | Audit log double SQLite + journald | ⚠️ Adapté | v0.2 = JSON stderr seul (déjà en place via `audit-logger.ts`). SQLite audit `audit_log` reporté v0.3 |
| P14 | CLI admin tokens | ⚠️ Adapté | v0.2 = `outlook-mcp admin issue-iat`, `revoke-refresh`, `rotate-jwt-key`, `post-restore-cleanup` |
| P15 | Path traversal guard | ⚠️ Marginal | Outlook n'écrit pas sur disque sauf tokens MSAL (déjà via keytar). Skip v0.2 |
| P16 | Durcissement systemd | ✅ Adopté | Lot C, `deploy/outlook-mcp.service` |
| P17 | Secrets en .env, jamais commit | ✅ Déjà en place | Aucun secret en clair |
| P18 | Cross-review trace `docs/plans/YYYY-MM-DD-*.md` | ✅ Adopté | Template créé |
| P19 | Repros runtime dans findings (V3 schema) | ✅ Adopté | ADR-0001 §"Schema Finding V3" |
| P20 | Reverse proxy delegated TLS, bind 127.0.0.1 | ✅ Adopté | Mode http-public refus boot si 0.0.0.0 |

**Score** : 14 ✅ direct, 4 ⚠️ adapté, 1 ❌ rejeté (P9). Méthodologie + OAuth + déploiement HTTP : tous couverts.

---

## 3. Phasage v2

### Lot A — Méthode & qualité (`~1j`)

- **A1** ✅ `docs/adr/0001-cross-llm-review-grid.md`
- **A2** ✅ `docs/adr/0002-oauth-trust-policy-and-as-architecture.md`
- **A3** ✅ `CHANGELOG.md`
- **A4** ✅ `SECURITY.md` enrichi (threat-model + ADR links + cross-review section)
- **A5** ✅ `docs/threat-model/2026-05-10-oauth-as-threat-model.md`
- **A6** ✅ `docs/MODES.md`
- **A7** ✅ `SPECS-OAUTH-MCP.md` v2
- **A8** ✅ Templates `docs/adr/TEMPLATE.md` + `docs/plans/TEMPLATE.md`
- **A9** ⏳ Quality gate : husky pre-commit + lint-staged + coverage seuil 80% (ticket T11)

### Lot B — OAuth AS intégré (`~5-7j` recalibré post-ADR-0002)

Architecture changée vs v1 (token-exchange interne), donc plus long.

- **B0** Setup `src/oauth/` package squelette + `better-sqlite3` + `jose` + `eta`
- **B1** `src/oauth/storage.ts` — schéma + migrations + helpers atomiques (`BEGIN IMMEDIATE`)
- **B2** `src/oauth/key-manager.ts` — Ed25519 gen + AES-256-GCM chiffrement + rotation grace 7j
- **B3** `src/oauth/dcr.ts` — DCR registered-only / trusted-dcr / open-dcr + IAT + exact-match
- **B4** `src/oauth/authorize.ts` — flow + erreurs locales avant validation + auth_requests
- **B5** `src/oauth/consent.ts` — template eta + CSRF + session cookie + CSP frame-ancestors
- **B6** `src/oauth/token.ts` — code grant atomic + refresh family + reuse detection
- **B7** `src/oauth/verifier.ts` — alg figé, kid strict, aud RFC 8707
- **B8** `src/oauth/discovery.ts` — well-known + jwks.json
- **B9** `src/oauth/token-exchange.ts` — outlook_jwt → MSAL account mapping
- **B10** `src/oauth/admin-cli.ts` — issue-iat, revoke-refresh, rotate-jwt-key, post-restore-cleanup
- **B11** Suppression `src/oauth-provider.ts` legacy + wiring nouveau dans `src/server.ts`
- **B12** Tests TDD complets par module (cf. SPECS §15)

### Lot C — Mode http-public durci (`~2-3j`)

- **C1** `src/rate-limit.ts` — token-bucket per-IP, persistance SQLite, clés multi-bucket
- **C2** `src/request-context.ts` étendu — `clientIp` resolved via trust-proxy model (cf. SPECS §12)
- **C3** Boot guards — refus 0.0.0.0, refus open-dcr en http-public, vérif TRUSTED_PROXIES (cf. MODES.md)
- **C4** `deploy/outlook-mcp.service` systemd durci
- **C5** `docs/HANDOFF_INFRA.md` — handoff peer `infra` (reverse proxy, certs, DNS, backups, monitoring)
- **C6** Headers sécurité (`HSTS`, `X-Frame-Options`, CSP global)

### Lot D — Audit / observabilité (`~1-2j`)

- **D1** `src/security/audit-logger.ts` étendu — events OAuth complets (cf. SPECS §14)
- **D2** Tests anti-fuite `__tests__/no-secret-in-logs.test.ts`
- **D3** `docs/AUDIT_EVENTS.md` — référentiel complet

### Lot E — Cross-review N0+N1 (+ N3 mcp-vault) finale (`~2-4j`)

- **E1** `/pf-cross-review HEAD~N..HEAD` après Lots B/C/D mergés
- **E2** N3 peer mcp-vault via bus agent-hub
- **E3** Plan `docs/plans/2026-XX-XX-cross-review-outlook-v0.2.0.md`, fix findings BLOCKER/IMPORTANT, ré-review fingerprint cache
- **E4** Tag `v0.2.0`

---

## 4. Estimation v2 (recalibrée)

| Lot | Effort v1 | Effort v2 | Différence |
|---|---|---|---|
| A — Méthode | ~1j | ~1j (90% fait) | inchangé |
| B — OAuth | ~3-5j | **~5-7j** | +2j pour AS intégré + token-exchange interne (ADR-0002) |
| C — HTTP durci | ~2-3j | ~2-3j | inchangé |
| D — Audit | ~1-2j | ~1-2j | inchangé |
| E — Cross-review | ~2-4j | ~2-4j | inchangé |
| **Total** | 9-15j | **11-17j** | +2j architecture-driven |

---

## 5. Référencement croisé

- ADR-0001 (cross-review grid) — méthode
- ADR-0002 (trust policy & AS arch) — décision pivot
- SPECS-OAUTH-MCP.md v2 — réf normative OAuth
- THREAT-MODEL — STRIDE + recovery
- MODES.md — matrice modes + trust-proxy
- TICKETS.md — checklist atomique (ticket T10)
- CHANGELOG.md — Unreleased v0.2.0
- SECURITY.md — entry point sécu (vulnerability reporting)

---

## 6. Points d'alignement mcp-vault (Q1-Q5 réponses incorporées)

| Q | Statut | Action |
|---|---|---|
| Q1 — N2 peer cross-review | ✅ ACCEPTÉ par mcp-vault | À déclencher en Lot E via `peer-ask.sh` |
| Q2 — Lib TS partagée | ❌ NON | Copie ad-hoc des patterns (confirmé par les deux) |
| Q3 — Format V3 anti-hallucination | ✅ Adopté | Référencé dans ADR-0001 §"Schema Finding V3" |
| Q4 — Consent template Jinja | ❌ Non partageable | Réimplem en eta TS (~35 lignes, cf. SPECS §6) |
| Q5 — Timeline v0.2 mcp-vault | ❌ Pas d'alignement | Lots orthogonaux, confirmé ADR-0002 §Conséquences |

---

*Fin plan v2. Implementation lots B/C/D commence post-merge de la doc + quality gate (T11).*
