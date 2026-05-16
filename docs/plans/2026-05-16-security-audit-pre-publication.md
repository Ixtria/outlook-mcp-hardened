# Security Audit — pre-publication OSS + usage perso mainteneur (2026-05-16)

**Range** : `b60a690..2250ccb` (toute la branche OAuth)
**Reviewers invoqués** : N0 (Claude pr-review-toolkit) + N1 (codex, **échec sandbox**) + N2 (ixtriasrv, **unreachable**) + N3 (mcp-vault peer via bus agent-hub)
**Contexte** : Jimmy va publier outlook-mcp-hardened en OSS + l'utiliser pour son mail Outlook personnel — exigence sécurité maximale.

## Résumé exécutif

| Source | BLOCKER | IMPORTANT | OBSERVATION |
|---|---|---|---|
| N0 Claude | 3 | 6 | 3 |
| N3 mcp-vault peer | 1 (CRITICAL) | 2 | 0 |
| **Total** | **4** | **8** | **3** |

| Statut fix | Count |
|---|---|
| ✅ Fixé dans cette session | 4 BLOCKER + 2 IMPORTANT (I1 PII-leak, N3-M1/M2) |
| ⏳ Reporté v0.2.1 (P0/P1) | 5 IMPORTANT (I2-I6) |
| ⏳ Reporté v0.3 (P2) | 3 OBSERVATIONS |

## Findings fixés ✅

### N3-C1 CRITICAL — getClient() bypass exact-match
**Source** : mcp-vault peer N3
**Commit fix** : `2aafdd3`
`MicrosoftOAuthProvider.getClient()` retournait `http://localhost:3000/callback` hardcodé → le SDK MCP `mcpAuthRouter` consultait ce hardcode au lieu de notre allowlist `registered-clients`. **Bypass total** de la validation exact-match pour tous les chemins enregistrés par le SDK.

Fix : `getClient()` retourne maintenant `[...allRegisteredRedirectUris()]` (single source of truth). 5 tests régression.

### N0-B1 BLOCKER (conf 88) — PKCE downgrade to `plain`
**Source** : N0 Claude
**Commit fix** : `2250ccb`
`/authorize` acceptait silencieusement `code_challenge_method=plain` sur le no-state code path (branche Claude Code stdio) malgré la discovery advertise `S256` only.

Fix : refus HTTP 400 `invalid_request` dès l'entrée si method !== 'S256'. Forçage S256 dans la branche no-state. Tests invariants.

### N0-B2 BLOCKER (conf 92) — pkceStore OOM DoS
**Source** : N0 Claude
**Commit fix** : `2250ccb`
`pkceStore: Map<string, {...}>` sans cap. Clé `state` attacker-controlled de longueur illimitée. Cleanup uniquement eviction-on-insert → flood + arrêt = entrées lingèrent.

Fix : 3 mesures combinées :
- `MAX_PKCE_STORE_SIZE = 10_000` avec LRU eviction via `Map.keys().next().value`
- `MAX_STATE_LENGTH = 256` chars, refus 400 sinon
- `setInterval(sweepExpired, 60_000)` indépendant du traffic, `unref()` pour pas keeper l'event loop

### N0-B3 BLOCKER (conf 82) — body parser limits manquantes + qs nested
**Source** : N0 Claude
**Commit fix** : `2250ccb`
`express.json/urlencoded` sans `limit:` (default 100kb). `extended: true` activait `qs` parser → prototype pollution surface historique.

Fix : `express.json({ limit: '10kb' })` + `express.urlencoded({ extended: false, limit: '10kb', parameterLimit: 20 })`. `extended: false` désactive qs (utilise `querystring` natif).

### N0-I1 IMPORTANT (conf 90) — UPN (email) logué en clair
**Source** : N0 Claude
**Commit fix** : `2aafdd3`
`logger.info("OAuth token verified for user: ${userPrincipalName}")` écrivait l'email Microsoft à chaque vérif token → PII dans `logs/mcp-server.log` sur disque, en violation du contrat `audit-logger.ts` qui hash systématiquement.

Fix : `createHash('sha256').update(upn).digest('hex').slice(0, 16)` puis `logger.info("OAuth token verified (user_id_hash=sha256:${upnHash})")`.

### N3-M2 MEDIUM — `verifyAccessToken` pas annoté "aud non validé par design"
**Source** : mcp-vault peer N3
**Commit fix** : `2aafdd3`
Risque : un futur mainteneur pourrait ajouter validation stricte aud=mcp et casser le flow.

Fix : commentaire inline explicite pointant ADR-0003 D2.

### N3-M1 MEDIUM — Deux chemins OAuth parallèles non documentés
**Source** : mcp-vault peer N3
**Commit fix** : `2aafdd3`
Handlers manuels `/authorize` etc. coexistent avec SDK `mcpAuthRouter`. Express match-first-win cache le problème mais fragile à un refactor.

Fix : commentaire avant `app.use(mcpAuthRouter(...))` expliquant que getClient corrigé (C1) est le filet de sécurité.

## Findings reportés v0.2.1

### N0-I2 IMPORTANT (conf 86) — `/mcp` Bearer middleware ne valide PAS le token

`microsoftBearerTokenAuthMiddleware` (src/lib/microsoft-auth.ts) extrait le Bearer du header et le forward à Graph SANS validation locale. Conséquences :
- Token forgé arbitraire accepté par les routes MCP utilitaires (`tools/list`, `resources/list`) qui ne touchent pas Graph
- Token Graph leaké d'une autre intégration peut être replayed ici (pas de check aud/iss)
- Enum surface MCP possible sans auth réelle

**Fix planifié v0.2.1** : remplacer le custom middleware par `requireBearerAuth({ verifier: oauthProvider, requiredScopes: ['User.Read'] })` du SDK MCP officiel (`@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js`). Refactor invasif → commit séparé avec tests E2E.

**Priorité** : **P0 avant déploiement public**. Tolérable pour usage stdio local (transport process-bound = pas de Bearer concerné).

### N0-I3 IMPORTANT (conf 82) — Discovery reflect Host header → `http://` issuer

Lignes 332/360 server.ts : `${protocol}://${req.get('host')}` où protocol vient de `req.secure` qui dépend de XFP. Si reverse proxy mal config (pas de X-Forwarded-Proto), issuer = `http://...` → spec-non-compliant RFC 8414 §2.

**Fix planifié v0.2.1** :
1. Préférer `OUTLOOK_MCP_PUBLIC_URL` env > Host header
2. Boot guard : exiger PUBLIC_URL si bind non-loopback
3. `res.set('Cache-Control', 'no-store')` sur les 2 discovery
4. Validation XFP=https sur premier /authorize si trustedProxies non vide

### N0-I4 IMPORTANT (conf 80) — Trust-proxy IP canonicalization manquante

`parseTrustedProxiesEnv` ne normalise pas (`192.168.001.001` typo opérateur silently break trust). `normalizeIp` ne couvre que la forme `::ffff:` socket.

**Fix planifié v0.2.1** : canonicalisation via `net.isIP()` + IP-Address package (refuser entries failant `net.isIP()`). Extend `normalizeIp` à IPv6 compaction.

### N0-I5 IMPORTANT (conf 81) — CORS port-agnostic localhost matching

`localhostAllowlist` matche `http://localhost` sans port → `http://localhost:1337` (malicious local Electron/extension) accepté + `Authorization` header allowed.

**Fix planifié v0.2.1** : soit (a) port-exact whitelist, soit (b) default `Access-Control-Allow-Origin: null` (MCP clients ne sont pas browsers, bypass CORS).

### N0-I6 IMPORTANT (conf 80) — `OUTLOOK_MCP_CORS_ORIGIN=*` footgun

Quand env var = `*`, le serveur reflect `*` + `Allow-Headers: Authorization`. Quelques non-browser clients honorent ça.

**Fix planifié v0.2.1** : refus boot si `*` sans `OUTLOOK_MCP_CORS_ALLOW_WILDCARD=true` explicite + strip Authorization de Allow-Headers en mode wildcard.

## Findings reportés v0.3 (OBSERVATIONS)

### N0-O1 — `hashAccount` unsalted SHA256

Reversible pour mainteneur connu, peu utile single-tenant. **Fix v0.3** : HMAC-SHA256 avec salt aléatoire 16 bytes en OS keychain.

### N0-O2 — `injection-wrapper` regex naive vs Unicode confusables

`/<\/?untrusted_content>/gi` ne couvre pas `<untrusted_content‍>` ni `&lt;/untrusted_content&gt;`. **Fix v0.3** : strip `<`/`>` → fullwidth, OU base64 mail body.

### N0-O3 — `logs/` dans module path → fragile npm install -g

`path.join(__dirname, '..', 'logs')` → fail sous `/usr/lib/node_modules/...`. **Fix v0.3** : `envPaths('outlook-mcp').log` ou `os.homedir() + /.outlook-mcp/logs/`.

## ESLint-plugin-security warnings (106) — triage

### Faux positifs par construction (safe — pas de fix)
- `egress-guard.ts:70,89` — `Symbol.for()` literal access
- `trust-proxy.ts:34` — regex anchored bounded (pas de ReDoS)
- `cloud-config.ts:60,70` — typed union exhaustif compile-time
- `auth.ts` paths — `path.join(homedir(), ...)` controlled, pas user input
- `registered-clients.ts:65` — static Map keys typés

### À tightener (real signal, **reporté v0.2.1**)
- `graph-tools.ts:521` — `new RegExp(non-literal)` : audit call site pour ReDoS
- `graph-tools.ts:235,262,…` — many object-injection sinks → 1 review pass + suppression comments per occurrence
- `auth.ts:157` — non-literal RegExp : idem

## Ce qui n'a PAS pu être fait dans cette session

1. **N1 codex round 3** — `codex exec` sandbox bwrap a planté (RTM_NEWADDR, bug connu ADR-0001 §règle méta 5). Workaround = push origin avant N1, à faire avant publication.
2. **N2 ixtriasrv** — `100.74.67.76:11500` unreachable (curl timeout 5s). À relancer une fois infra up.
3. **Tier 2 adversarial** (property-based fast-check, fuzzing, OWASP ZAP scan) — reporté.
4. **Tier 3 humain expert** (consultant sécu OAuth) — reporté avant publication massive.

## Pattern d'attaques mcp-vault prod testées en analogie

- **Trailing `\n` redirect_uri** : COVERED via `[\s\x00-\x1F\x7F]` pre-match filter
- **ChatGPT DCR dynamic** : N/A — on n'a pas de DCR (ADR-0003 D1)
- **Scope deadlock offline_access** : COVERED via META_SCOPES post-intersection bypass

## Positive durable patterns confirmés par N0

- `redirect-uri.ts` exact-match + percent-encoded CR/LF/dot/null = solide layered defense
- `scope.ts` + `META_SCOPES` split = clean OIDC vs Graph
- `egress-guard.ts` hostname-exact + port allowlist + Symbol-tagged patch = solid
- `trust-proxy.ts` operator-managed trust set + RTL walk = correct model (idem Cloudflare)
- `server.ts` boot guard non-loopback sans TRUSTED_PROXIES = fail-closed default
- `http-routes.ts` extraction = unit-testable wiring
- `.githooks/pre-commit` test:coverage sur src/security/oauth/ = gate régressions

## Décision de publication OSS

| Use case | Statut |
|---|---|
| **Publier en OSS Apache-2.0** | ✅ Possible APRÈS fix v0.2.1 des I2-I6 |
| **Usage perso stdio (Claude Code local)** | ✅ Acceptable maintenant (Bearer pas exposé) |
| **Usage perso HTTP local (`--http 127.0.0.1`)** | ⚠️ Tolérable mais I2 reste limite |
| **Déploiement public derrière reverse proxy** | ❌ Bloqué jusqu'à I2-I6 fixés v0.2.1 + Tier 2 adversarial + Tier 3 humain expert |

## Prochains pas concrets

1. **Commit série v0.2.1** : I2 (requireBearerAuth) + I3 (discovery PUBLIC_URL strict) + I4 (IP canonicalization) + I5 (CORS port-aware ou disable) + I6 (refus CORS=* sans opt-in)
2. **Push branche origin** + relancer N1 codex hors sandbox + N2 ixtriasrv quand up
3. **Tag v0.2.0** après v0.2.1 fixes intégrés
4. **Tier 2 adversarial** sur branche dédiée : `npm install fast-check` + property tests, OWASP ZAP baseline scan en CI
5. **Tier 3 expert humain** (1 j pro consultant sécu OAuth) avant publication tier majeur

## Commits de cette session

```
2250ccb fix(oauth): N0 cross-review BLOCKERS B1+B2+B3 — PKCE downgrade, OOM, body limits
2aafdd3 fix(oauth): N3 mcp-vault peer review — CRITICAL C1 + M1/M2 annotations
e47c052 ci(security): Tier 0 — CodeQL + Semgrep + OSV + Gitleaks + Dependabot + ESLint-security
922c008 test(oauth): integration tests on HTTP wiring — dette N0-O3 fixée
5d25d29 fix(oauth): cross-review N0 Niveau B — META_SCOPES, trust-proxy IP, boot guard
446220b feat(oauth): pivot Niveau B — wire 3 modules pures dans server.ts
edb294d fix(oauth+lib): cross-review N0 findings — userinfo bypass, CRLF/dot percent, IPv6 mapped
b60a690 feat(oauth): redirect-uri exact-match + scope intersection + trusted-proxy
3de68f1 docs(lot-a): cadrage v0.2 OAuth AS — ADRs, threat model, specs v2, tickets
```

269 tests PASS. Coverage src/oauth/** 100%, src/security/** 92%, request-context.ts 100%, trust-proxy.ts 100%.
