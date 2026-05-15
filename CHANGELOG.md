# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versionning : [SemVer](https://semver.org/lang/fr/spec/v2.0.0.html).

## [Unreleased] — Lot B OAuth proxy hardened (Niveau B, pivot 2026-05-10)

### Architecture (2026-05-10 mid-Lot B pivot)

- **ADR-0003 supersede ADR-0002** — pivot vers OAuth proxy hardened vers Microsoft AAD, abandonnant l'AS intégré complet (DCR, JWKS local, consent UI, SQLite, ~1200 LOC, 4 nouvelles dépendances).
- Justification : respect du principe minimalisme du projet (CLAUDE.md §1 "Mail + Calendar uniquement"). Arbitrage utilisateur explicite contre l'usine à gaz.
- Conséquences : ~100 LOC ajoutés au lieu de ~1200 ; zéro nouvelle dépendance (pas de `jose`, `better-sqlite3`, `eta`, `@node-rs/bcrypt`) ; time-to-v0.2.0 réduit de 9-14j à ~1j.
- Les 3 modules pures déjà commités (`redirect-uri`, `scope`, `trust-proxy`) **restent valorisés** : ils sont wirés dans `oauth-provider.ts` et `request-context.ts` au lieu d'alimenter un AS standalone.

### Added (planned v0.2.0)

- ADR-0001 — Grille cross-LLM review N0+N1+N2+N3 (mcp-vault peer)
- ADR-0002 — OAuth Trust Policy & AS Architecture : DCR registered-only par défaut, AS intégré (RFC 8693 token-exchange) côté ingress, MSAL device code conservé côté egress
- THREAT-MODEL OAuth AS (STRIDE) + politiques de recovery
- MODES.md — matrice stdio / http-loopback / http-public avec préconditions bloquantes
- SPECS-OAUTH-MCP.md v2 — 13 findings codex intégrés
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
