# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versionning : [SemVer](https://semver.org/lang/fr/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase C HTTP-public deployment kit (2026-06-02)

- `deploy/outlook-mcp.service` — hardened systemd unit (NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, PrivateDevices, ProtectKernel*, MemoryDenyWriteExecute, RestrictNamespaces, RestrictAddressFamilies AF_UNIX/INET/INET6, CapabilityBoundingSet=, SystemCallFilter=@system-service, resource limits)
- `deploy/outlook-mcp.env.example` — env file template (Azure App Reg + PUBLIC_URL + TRUSTED_PROXIES + optional CORS/write policy/rate-limit)
- `deploy/nginx-outlook-mcp.conf` — nginx reverse proxy (Let's Encrypt + HSTS + CSP + XFF append + rate_limit zones + body size cap + slowloris defenses + SSE buffering off for /mcp)
- `deploy/Caddyfile` — Caddy alternative (TLS automatic, simpler config)
- `deploy/Dockerfile` — multi-stage container build (node:22-bookworm-slim, non-root, dumb-init, libsecret for keytar)
- `deploy/docker-compose.yml` — outlook-mcp + Caddy stack (read_only, cap_drop ALL, no-new-privileges)
- `docs/HANDOFF_INFRA.md` (416 lines) — end-to-end deployment handoff : DNS → TLS → reverse proxy → systemd → first auth → monitoring → logrotate → rollback → security posture verification checklist

### Planned v0.4

- Architectural refactor : drop `mcpAuthRouter` mount, all OAuth endpoints hand-rolled (eliminates SDK-imported attack surface — N4 META recommendation)
- HMAC verifier cache (60s TTL) to reduce Graph `/me` round-trips
- `/token` endpoint RFC 6749 §5.2 compliance (currently 500 instead of 400 invalid_grant)
- `pkceSweepHandle` graceful shutdown
- AAD error body sanitization (trace_id, correlation_id stripped before log)

## [0.3.0] — 2026-06-02 — pre-publication security audit complete

First public release after multi-school cross-LLM security audit. **8 BLOCKERS + 16 IMPORTANT fixed**, 380 tests passing, 0 npm-audit vulnerabilities, full Tier 0+1+2 audit history documented.

### Breaking changes (Phase A + Phase B post-audit pré-publication)

- **Audit log `account` field prefix changes** : `sha256:<unsalted, 64 hex chars>` (v0.2.0) → `hmac-sha256:<salted, 32 hex chars>` (v0.3.0). The salt is per-installation, persisted at `$XDG_STATE_HOME/outlook-mcp/audit-salt` (mode 0600). Operators using grep/jq pipelines on the audit log MUST update field-extraction rules. Historical entries cannot be correlated with new ones because the hash domain changed — this is intentional pseudonymity hardening (N0-O1 + N0-I3 fix).
- **`prepare` npm script removed** (N4-I4 fix). The pre-commit hook installation is now opt-in via `npm run setup-hooks` for contributors. Consumers installing outlook-mcp-hardened as a dependency are no longer silently modified.
- **Vitest 4.x + @azure/msal-node 5.2.2** semver-major bumps to clear all known CVEs (npm audit 17 → 0).

### Security — Phase A (cross-review N0 OBSERVATIONS resolved)

- **N0-O1** hashAccount HMAC+salt — see Breaking changes above
- **N0-O2** injection-wrapper Unicode confusables — strip BiDi controls + variation selectors + zero-width chars + **Plane-14 language tag chars U+E0000-U+E007F (2024 steganography CVE class)** + Mongolian Vowel Separator + invisible math operators. WRAPPER_TAG_RE extended with `\p{Default_Ignorable_Code_Point}` tolerance.
- **N0-O3** logs path XDG-compliant (`$XDG_STATE_HOME/outlook-mcp/logs/` with fallback ~/.local/state). Compatible `npm install -g`.

### Security — Phase B (cross-review N0 + N4 expert OAuth)

- **N0-B1 BLOCKER (conf 95)** — `winston` file log stream was emitting recipient emails, mail bodies, and Graph URL path params in CLEAR TEXT to `mcp-server.log` (same XDG dir as audit-salt). Defeated the audit-logger HMAC pseudonymity. **Fix** : new `src/security/log-redactor.ts` winston format runs every log message through pattern-based redaction (emails → `[email:8hex]` via hashAccount, Bearer tokens → `Bearer [redacted]`, JWTs → `[JWT redacted]`, percent-encoded Graph emails → same correlation handle as plaintext).
- **N4-B1 BLOCKER (conf 95)** — `/authorize` accepted requests without `code_challenge`, silent PKCE downgrade violating RFC 9700 §2.1.1. **Fix** : refuse with 400 invalid_request if `code_challenge` absent (PKCE mandatory for public clients).
- **N4-B2 BLOCKER (conf 92)** — POST `/authorize` was caught by SDK `mcpAuthRouter` (mounted in fallthrough) which accepted arbitrary `client_id` + `scope` from the body. Combined with `getClient()` returning the registered redirect_uris allowlist for ANY client_id, an attacker could redirect to AAD with `scope=Files.ReadWrite.All` + `client_id=ATTACKER_CLIENT`. **Fix** : explicit `app.post('/authorize')` → 405 Method Not Allowed (Allow: GET). RFC 6749 §3.1 allows GET-only authorization endpoints.
- **N4-B3 BLOCKER (conf 90)** — `verifyMicrosoftAccessToken` was calling `authManager.setOAuthToken(token)` which mutated global state, causing cross-user token leakage in multi-user HTTP scenarios. Not exploitable single-user. **Fix** : removed the mutation. `requestContext` AsyncLocalStorage is the sole token source per request.
- **N0-I1** Unicode obfuscation strip set extended to U+180E, U+2060-U+2064, U+E0000-U+E007F. Tag regex now uses `\p{Default_Ignorable_Code_Point}` for defense-in-depth.
- **N0-I2** Symlink attack defense on audit-salt + logs : `openSync` with `O_NOFOLLOW | O_EXCL` on writes, `O_NOFOLLOW` on reads. Pre-planted symlinks now fail with ELOOP error.
- **N0-I3** `OUTLOOK_MCP_AUDIT_SALT_HEX` refused at runtime if `NODE_ENV === 'production'`.
- **N4-I1** Discovery endpoints (`/.well-known/oauth-*`) now use a fixed issuer URL computed at boot from `host:port` or `OUTLOOK_MCP_PUBLIC_URL`, never reflected from the Host header. Closes DNS-rebinding vector on loopback bind.
- **N4-I2** Global Express error handler returns sanitized JSON (`{error, error_description}`) instead of the default HTML stack trace leak.
- **N4-I3** Protected Resource Metadata served at BOTH `/.well-known/oauth-protected-resource` AND `/.well-known/oauth-protected-resource/mcp` (RFC 9728 §3.1 + MCP Authorization 2025-11 draft).
- **N4-I4** `prepare` npm script removed (see Breaking changes).

### Documentation

Phase D OSS-grade refonte client-agnostic :

- `README.md` refondu — badges enrichis, positioning explicite "client-agnostic", tableau comparatif vs upstream complet, security posture matrice, audit history Tier 0+1+2
- `INSTALL.md` (NEW, 257 lines) — Azure App Registration step-by-step, 3 modes d'exécution, env vars exhaustifs, Key Vault alternative, multi-account
- `CLIENT_CONFIG.md` (NEW, 264 lines) — 100% client-agnostique : exemples pour Claude Desktop/Code/Cline/Continue/mcp-inspector/custom Node/Python SDK/openclaw/Hermès. MCP est un standard, on documente le contrat
- `USAGE.md` (NEW, 302 lines) — 16 workflows couvrant mail/calendar/folders/rules/settings/attachments/shared-mailbox + patterns recommandés
- `API_REFERENCE.md` (NEW, 183 lines) — catalogue 55 tools split par write policy + scope-to-tool quick reference
- `TROUBLESHOOTING.md` (NEW, 243 lines) — auth/network/HTTP guards/OAuth proxy/multi-account/logs/build avec symptôme → cause → fix

## [0.2.0] — 2026-05-16

Première release majeure post-hardening fork. Couvre :

1. **Cadrage v0.2** — 2 ADRs (cross-LLM review grid + OAuth trust policy), threat model STRIDE, matrice MODES (stdio/http-loopback/http-public), SPECS OAuth v2 + v3 pivot, MIGRATION-PLAN, TICKETS, CONTRIBUTING.
2. **Pivot architectural Niveau B** (ADR-0003 supersede ADR-0002) — OAuth proxy hardened vers Microsoft AAD, ~150 LOC ajoutés au lieu de ~1200 LOC AS intégré. Aucune nouvelle dépendance lourde (pas de SQLite, JOSE, eta, bcrypt).
3. **3 modules pures réutilisables** : `redirect-uri.ts`, `scope.ts`, `trust-proxy.ts` — 100% test coverage, fonctions sans I/O.
4. **CI sécurité Tier 0** : CodeQL + Semgrep + OSV-Scanner + Gitleaks + Dependabot + ESLint-plugin-security + License-checker.
5. **Audit cross-LLM 4-school complet** — N0 (Claude pr-review-toolkit) + N3 (mcp-vault peer via bus agent-hub) avec 4 BLOCKERS + 9 IMPORTANT fixés (3 OBS reportées v0.3). N1 (codex) sandbox bypass à compléter post-publication.

### Security — findings fixés (chronologique cross-reviews)

**Tour 1 — modules pures (commits b60a690 + edb294d)**
- B1 (codex conf 96) — `redirect_uri` wildcard allowlist → exact-match strict, refus subdomain/scheme/control-chars
- B2 (codex conf 93) — DCR ouvert → `OAUTH_TRUST_MODE=registered-only` par défaut
- I1 (codex conf 95) — scope intersection non normative → `requested ∩ registered ∩ KNOWN` + RFC 6749 §3.3 fallback
- I2 (codex conf 92) — open redirect sur erreur /authorize → erreur LOCALE avant validation
- I4 (codex conf 94) — TOCTOU codes/refresh → `BEGIN IMMEDIATE` (abandonné pivot Niveau B, no SQLite)
- I7 (codex conf 79) — confusion alg/kid → alg=EdDSA figé (abandonné pivot Niveau B, no JWT local)
- I8 (codex conf 90) — XFF rightmost faux → trusted-proxy model explicite
- I9 (codex conf 87) — trusted-redirect exception → rejetée (ADR-0002 D5)
- N0-B1 (conf 95) — userinfo bypass `https://attacker@claude.ai/...` → reject userinfo URL component
- N0-I1 (conf 80) — DANGEROUS_PERCENT incomplet → +%0A/%0D/%2E
- N0-I2 (conf 82) — IPv4-mapped IPv6 silent attribution → `normalizeIp` strip `::ffff:`

**Tour 2 — pivot Niveau B + wiring (commits 446220b + 5d25d29 + 922c008)**
- N0-B1 (conf 95) — `offline_access` silently dropped → META_SCOPES bypass post-intersection (refresh tokens préservés)
- N0-B2 (conf 92) — `req.secure` cassé `trust proxy=false` → IP allowlist via `app.set('trust proxy', [...trustedProxies])`
- N0-I1 (conf 90) — `Mail.ReadWrite` dropped (write tools cassés) → ajouté CLAUDE_AI_ALLOWED_SCOPES
- N0-I2 (conf 88) — `User.Read` dropped → via META_SCOPES
- N0-I3 (conf 82) — `allRegisteredRedirectUris()` rebuilt per request → hoist au boot
- N0-O1 — boot guard 0.0.0.0 sans TRUSTED_PROXIES → refus boot avec message explicite
- Refactor : extraction `src/oauth/http-routes.ts` pour rendre le wiring server.ts testable (25 tests intégration)

**Tour 3 — N3 mcp-vault peer review (commit 2aafdd3)**
- **N3-C1 CRITICAL (conf 90)** — `getClient()` hardcodé `http://localhost:3000/callback` → bypass exact-match via SDK `mcpAuthRouter`. Fix : retourne `[...allRegisteredRedirectUris()]`. **Faille que ni N0 Claude ni N1 codex n'avaient vue.**
- N3-M1 — deux chemins OAuth parallèles non documentés → annotation
- N3-M2 — `verifyAccessToken` pas annoté "aud non validé par design" → annotation ADR-0003 D2

**Tour 4 — audit pré-publication final (commits 2250ccb + fd1270c + 98dd0db)**
- **N0-B1 BLOCKER (conf 88)** — PKCE downgrade to `plain` accepté → refus si method !== 'S256', S256 forcé sur AAD
- **N0-B2 BLOCKER (conf 92)** — `pkceStore` OOM via state-flood → MAX_PKCE_STORE_SIZE=10000 LRU + MAX_STATE_LENGTH=256 + setInterval sweep 60s
- **N0-B3 BLOCKER (conf 82)** — body parser limits manquantes + qs nested → `express.json({limit:'10kb'})` + `urlencoded({extended:false, limit, parameterLimit:20})`
- **N0-I1 (conf 90)** — UPN logué en clair → hashAccount avant emit
- **N0-I2 (conf 86)** — /mcp Bearer non validé → `createBearerAuthMiddleware(verifier)` factory + verifier Graph /me roundtrip + 13 tests régression
- **N0-I3 (conf 82)** — discovery reflect Host header → `OUTLOOK_MCP_PUBLIC_URL` strict + `Cache-Control: no-store` + boot guard https://
- **N0-I4 (conf 80)** — trust-proxy IP canonicalization → `normalizeIp` étendu IPv4 leading-zero + IPv6 lowercase + entries invalides skip warn
- **N0-I5 (conf 81)** — CORS port-agnostic → default-deny + exact-match strict
- **N0-I6 (conf 80)** — CORS=* footgun → refus boot sans `OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true` opt-in

### Reporté v0.3 (OBSERVATIONS non-bloquantes)

- N0-O1 — `hashAccount` SHA256 unsalted (reversible mainteneur connu) → HMAC-SHA256 avec salt OS keychain
- N0-O2 — `injection-wrapper` regex naïf vs Unicode confusables → strip `<`/`>` → fullwidth OU base64
- N0-O3 — `logs/` path fragile npm install -g → `envPaths('outlook-mcp').log`
- Perf cache verifier (Graph /me roundtrip par requête) → in-memory TTL 60s si latency observée

### Methodology

Méthode review documentée dans `docs/adr/0001-cross-llm-review-grid.md` (transpose ADR mcp-vault v3.3). Schema Finding V3 anti-hallucination : tout BLOCKER/IMPORTANT exige un `repro_runtime` exécutable. 297 tests PASS, coverage `src/oauth/**` 100%, `src/security/**` 92%, `src/lib/trust-proxy.ts` 100%, `src/request-context.ts` 100%.

Plans cross-review versionnés dans `docs/plans/`. Threat model STRIDE par surface dans `docs/threat-model/2026-05-10-oauth-as-threat-model.md`. Matrice modes dans `docs/MODES.md`.

### Tooling

- CI workflow `.github/workflows/security.yml` (CodeQL + Semgrep + OSV + Gitleaks + license-check, weekly cron Monday 06:00 Europe/Zurich)
- `.github/dependabot.yml` (npm + github-actions, security updates priorisés)
- `.github/CODEOWNERS` (zones sensibles @Ixtria review obligatoire)
- `.githooks/pre-commit` (lint + typecheck + coverage si touche security/oauth)
- `vitest.config.js` coverage thresholds ≥80% sur `src/oauth/**`, `src/security/**`, `src/request-context.ts`

### Architecture (2026-05-10 mid-Lot B pivot)

- **ADR-0003 supersede ADR-0002** — pivot vers OAuth proxy hardened vers Microsoft AAD, abandonnant l'AS intégré complet (DCR, JWKS local, consent UI, SQLite, ~1200 LOC, 4 nouvelles dépendances).
- Justification : respect du principe minimalisme du projet (CLAUDE.md §1 "Mail + Calendar uniquement"). Arbitrage utilisateur explicite contre l'usine à gaz.
- Conséquences : ~100 LOC ajoutés au lieu de ~1200 ; zéro nouvelle dépendance (pas de `jose`, `better-sqlite3`, `eta`, `@node-rs/bcrypt`) ; time-to-v0.2.0 réduit de 9-14j à ~1j.
- Les 3 modules pures déjà commités (`redirect-uri`, `scope`, `trust-proxy`) **restent valorisés** : ils sont wirés dans `oauth-provider.ts` et `request-context.ts` au lieu d'alimenter un AS standalone.

### Added (rétrospective, intégré dans [0.2.0])

- ADR-0001 — Grille cross-LLM review N0+N1+N2+N3 (mcp-vault peer)
- ADR-0002 — OAuth Trust Policy & AS Architecture (superseded par ADR-0003)
- ADR-0003 — Pivot vers OAuth proxy hardened (Niveau B)
- THREAT-MODEL OAuth AS (STRIDE) + politiques de recovery
- MODES.md — matrice stdio / http-loopback / http-public avec préconditions bloquantes
- SPECS-OAUTH-MCP.md v2 — 13 findings codex intégrés (sections AS intégré superseded par ADR-0003)
- MIGRATION-PLAN-FROM-MCP-VAULT.md v2 — retour mcp-vault peer review + correctifs codex
- TICKETS.md — lots A-E en checklist atomique
- `docs/plans/TEMPLATE.md` — template plan cross-review (format V3)
- `docs/adr/TEMPLATE.md` — template ADR

### Security (planned v0.2.0 — réponses cross-review codex 2026-05-10)

- **B1 BLOCKER fix** — `redirect_uri` exact-match hardcodé, refus wildcard (`https://claude.ai/*` etc.). DCR allowlist par client_name connu.
- **B2 BLOCKER fix** — DCR registered-only par défaut. Mode `registered-trusted-dcr` exige Initial Access Token. Mode `open-dcr` interdit en prod.
- **I1 fix** — `effective_scope = requested ∩ registered ∩ KNOWN` rendu normatif dans SPECS et codé en TS. Pas d'exception trusted-client (rejet finding mcp-vault Option B v0.3.4).
- **I2 fix** — `/authorize` ne redirige avec `error=` que si `client_id` + `redirect_uri` sont validés exactement contre registered. Sinon erreur locale non redirigée (anti open-redirect).
- **I3 fix** — Consent UX : cookie session `HttpOnly; Secure; SameSite=Strict`, CSRF token lié à la session, `frame-ancestors 'none'`, liaison login-consent obligatoire.
- **I4 fix** — Consommation atomique `auth_codes` et `refresh_tokens` : `BEGIN IMMEDIATE; UPDATE … SET used=1 WHERE code=? AND used=0 AND expires_at>?` + check `rowcount==1`.
- **I5 fix** — Refresh token rotation avec `family_id` + `parent_token_hash` + détection de reuse → révocation de toute la famille (RFC 9700).
- **I6 fix** — Politique backup SQLite normative : mode WAL, checkpoint, restore post-procédure `DELETE FROM auth_codes; DELETE FROM refresh_tokens` (invalide tout token antérieur au snapshot).
- **I7 fix** — JWT `alg=EdDSA` figé, refus de tout token avec `alg` différent, unicité forte `kid`, lookup `kid → key` documenté.
- **I8 fix** — Modèle de confiance proxy explicite (`OUTLOOK_MCP_TRUSTED_PROXIES`). XFF lu uniquement si peer IP ∈ trusted. Sinon socket IP. Pas d'heuristique rightmost/leftmost magique.
- **I9 fix** — "Trusted-redirect exception" (mcp-vault v0.3.4 Option B) **non importée**. Pour chaque client, scope/redirect dans `oauth-clients.json` registered-only.

### Changed (planned v0.2.0)

- `src/oauth-provider.ts` legacy (ProxyOAuthServerProvider AAD) remplacé par `src/oauth/` package complet : `as-server.ts`, `dcr.ts`, `authorize.ts`, `token.ts`, `jwks.ts`, `consent.ts`, `verifier.ts`, `storage.ts` (SQLite).
- `src/request-context.ts` étendu : `clientIp` (trusted-proxy resolved), `userJwt`, `clientId`.
- Pre-commit hook `husky` + `lint-staged` + coverage threshold vitest ≥80% sur `src/security/*` et `src/oauth/*`.

### Documentation

- `SECURITY.md` durci (versions, contact, threat model link, hors scope explicite)
- `CONTRIBUTING.md` ajoute section "Cross-review obligatoire avant merge sécu"
- `docs/plans/2026-05-10-cross-review-oauth-first-wave.md` — cross-review N0+N1 sur commit b60a690

### Security (cross-review N0 fixes, 2026-05-10)

Première vague Lot B reviewée par Claude sub-agent N0 (pr-review-toolkit:code-reviewer) + codex N1. Convergence : 1 BLOCKER + 2 IMPORTANT trouvés par N0 dans mes 3 nouveaux modules, tous fixés.

- **N0-B1 BLOCKER (conf 95)** — `normalizeRedirectUri` drop le userinfo URL (`user:pass@host`). `https://attacker@claude.ai/api/mcp/auth_callback` validait à TRUE contre l'URI enregistrée. **Fix** : `if (parsed.username !== '' || parsed.password !== '') return null;` + 3 tests régression (suite "userinfo bypass").
- **N0-I1 IMPORTANT (conf 80)** — `DANGEROUS_PERCENT` ne bloquait que `%2F/%5C/%00`. **Fix** : extension à `%0A/%0D/%2E` (CRLF + dot anti-`..`-smuggling) + 5 tests régression.
- **N0-I2 IMPORTANT (conf 82)** — IPv4-mapped IPv6 (`::ffff:10.0.0.1`) ne matchait pas une entrée `10.0.0.1` dans `TRUSTED_PROXIES`. Silent attribution bug. **Fix** : helper `normalizeIp()` strip `::ffff:` prefix après validation dotted-quad + 4 tests régression.

N1 (codex) a reviewé le repo entier (sandbox bwrap n'accède pas au range non-pushé local) et a confirmé **les bugs legacy v0.1 que le Lot B doit remplacer** : `trust proxy=true` global, `/register` echo sans persistance, scope forwardé sans intersection, fallback scope avec `Files.Read`. Tous tracés vers les tickets TKT-B3/B4/B6/B8/B11/C2/C3 du Lot B planifié.

N1 a aussi flaggé une **divergence README ↔ code** sur le cache MSAL : doc dit "encrypted file" mais `auth.ts:320-337` écrit en plaintext (perms 0o600). À arbitrer hors plan OAuth (patch README v0.1.1 OR chiffrement at-rest v0.3).

### Security (cross-review N0 finale Niveau B, 2026-05-10)

Cross-review finale post-pivot (commit `446220b`). N0 (Claude sub-agent) a flaggé 2 BLOCKERS + 3 IMPORTANT + 3 OBSERVATIONS. 4 fixés en cycle, 1 observation fixé, 2 reportées (UX + dette test integration).

- **N0-B1 BLOCKER (conf 95)** — `offline_access` silently dropped : `buildScopesFromEndpoints()` dérive du `endpoints.json` qui ne liste pas les scopes OIDC/refresh, donc l'intersection les éliminait → AAD ne mintait pas de refresh token → session Claude.ai meurt après 1h. **Fix** : nouvelle constante `META_SCOPES` (`offline_access`, `openid`, `profile`, `User.Read`) que `/authorize` ajoute en bypassant la KNOWN check (sont des scopes protocole, pas des Graph permissions).
- **N0-B2 BLOCKER (conf 92)** — `req.secure` cassé derrière reverse proxy TLS : `trust proxy=false` désactivait `X-Forwarded-Proto`, donc discovery `/.well-known/oauth-*` retournait `issuer: "http://..."` → violation RFC 8414 §2 + 9728 §3.1, Claude.ai aurait refusé le document. **Fix** : `trust proxy` configuré avec IP allowlist (`[...trustedProxies]`) quand `OUTLOOK_MCP_TRUSTED_PROXIES` non vide.
- **N0-I1 IMPORTANT (conf 90)** — `Mail.ReadWrite` absent de `CLAUDE_AI_ALLOWED_SCOPES` cassait les write tools `--enable-send`. **Fix** : ajouté à l'allowlist.
- **N0-I2 IMPORTANT (conf 88)** — `User.Read` même root cause que B1 (pas dans endpoints.json). **Fix** via META_SCOPES.
- **N0-I3 IMPORTANT (conf 82)** — `allRegisteredRedirectUris()` rebuilt per request. **Fix** : hoist `allowedRedirectUris` + `registeredScopesString` au scope HTTP server une fois.
- **N0-O1 OBSERVATION** — boot guard 0.0.0.0 sans `OUTLOOK_MCP_TRUSTED_PROXIES` manquant (ADR-0003 D6). **Fix** : throw Error au boot si bind non-loopback sans trusted-proxies.

N1 codex tentative finale a échoué (sandbox bwrap `RTM_NEWADDR`, ADR-0001 §règle méta 5 connue). N0 sub-agent a couvert exhaustivement.

Détails : `docs/plans/2026-05-10-cross-review-niveau-b-final.md`.

## [0.1.0] — 2026-04-XX

Version initiale du hardening fork. Voir `git log v0.1.0` pour le détail.

### Added

- Fork chirurgical de `@softeria/ms-365-mcp-server@0b1a2fe` (MIT) → `@ixtria/outlook-mcp-hardened` (Apache-2.0)
- `src/security/egress-guard.ts` — allowlist `login.microsoftonline.com` + `graph.microsoft.com`, monkey-patch `globalThis.fetch`
- `src/security/audit-logger.ts` — JSON stderr, account hashé SHA-256
- `src/security/injection-wrapper.ts` — `<untrusted_content>` wrapper sur mail bodies
- `src/security/write-policy.ts` — gating `--enable-send` / `--enable-write`
- Filtrage `endpoints.json` upstream : 202 → ~58 endpoints Mail+Calendar uniquement
- Markers `// HARDENED:` sur chaque ligne modifiée d'un fichier upstream
- npm tarball whitelist (exclusion tests + dev logs)

### Security

- Lockfile npm audit `--audit-level=moderate` clean en CI
- Aucune dépendance avec `fetch` hors allowlist
