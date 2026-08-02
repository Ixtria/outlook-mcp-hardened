# Threat Model — OAuth proxy hardened Niveau B (post ADR-0003)

**Date** : 2026-08-02
**Auteur** : Jimmy Blanquet
**Reviewers** : audit stratégique 2026-08-02 (`docs/plans/2026-08-02-audit-maintenance-strategique.md`), contradictoire GPT-5.5 (via `codex exec`)
**Statut** : Accepté — remplace `2026-05-10-oauth-as-threat-model.md` (superseded)
**Couvre** : architecture Niveau B réelle telle qu'implémentée dans `main` au 2026-08-02 (post pivot ADR-0003, post release v0.3.0)
**Ticket** : GOV-02 (audit maintenance stratégique)

## Pourquoi ce document existe

Le TM précédent (`2026-05-10-oauth-as-threat-model.md`) modélisait un **Authorization Server intégré** (DCR étendu, `/authorize` complet avec consent HTML local, `/token` avec émission JWT signé, JWKS publiées, SQLite pour clients/codes/refresh/mapping, token-exchange RFC 8693). Cette architecture a été **abandonnée** par ADR-0003 (2026-05-10) au profit d'un **OAuth proxy** vers Microsoft AAD.

Le pivot supprime des surfaces entières — mais **le TM n'a pas été rejoué** dans les 12 semaines qui ont suivi. L'audit stratégique 2026-08-02 (STRAT-03 §"Trous structurels") a identifié ce trou comme finding GOV-02 et le contradictoire GPT-5.5 a confirmé qu'un TM figé sur une archi qui n'existe plus est **pire qu'un TM absent** : il induit en erreur qui le lit.

Ce document redéfinit le périmètre réel et rejoue STRIDE sur les surfaces Niveau B effectives.

## Hook ADR ↔ TM (règle process installée par ce ticket)

Pour éviter que ce trou se reproduise, `docs/adr/TEMPLATE.md` inclut désormais une section obligatoire **"Threat Model Impact"** avec clause `TM: unchanged | to-update | superseded` et un lien vers le TM courant. Toute PR qui ajoute un ADR sans cette section est refusée en review (règle intégrée à ADR-0004 anti-patterns explicites : *"Un ADR qui modifie l'architecture sans clause `TM: unchanged/to-update/superseded`"*).

## Surfaces supprimées par le pivot (à considérer NON APPLICABLES)

| Surface TM 2026-05-10 | État Niveau B |
|---|---|
| **F1 — DCR étendu** avec Initial Access Token, rate-limit dédié, mode `registered-trusted-dcr` | **Supprimée**. Un endpoint `/register` existe (SDK) mais il est **conditionnel** (`--enable-dynamic-registration`, désactivé par défaut) et délégué à `createRegisterHandler` (`src/oauth/http-routes.ts`) qui **refuse tout `redirect_uri` hors allowlist statique** `allRegisteredRedirectUris()`. Pas d'IAT bearer, pas de rate-limit propre, pas de stockage de client secret : rien à voler côté serveur. |
| **F2 — /authorize + consent HTML local + POST /authorize/consent** | **Supprimée**. Pas de page consent locale. `GET /authorize` (`src/server.ts:499`) valide `redirect_uri` (exact-match), refuse PKCE `plain`, borne `state`, intersecte les scopes, puis **redirige 302 vers `login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`**. C'est AAD qui affiche la page de consentement. `POST /authorize` renvoie **405 Method Not Allowed** (`src/server.ts:484`) — impossible de contourner la validation via le POST fallback du SDK. |
| **F3 — /token émettant JWT signé par notre AS** | **Supprimée**. Aucun JWT n'est signé côté outlook-mcp. `POST /token` (`src/server.ts:699`) est un simple **proxy vers l'endpoint token AAD** ; le token retourné à Claude.ai est le token AAD tel quel (`aud=https://graph.microsoft.com` — limitation RFC 8707 stricte assumée par ADR-0003 §D2). Pas de rotation refresh maison, pas de family_id, pas de détection reuse locale (AAD gère). |
| **F4 — JWKS locales + rotation + grace period** | **Supprimée**. Pas de clé privée à protéger. Pas de `/jwks.json` local. Pas de rotation `alg=EdDSA` maison. |
| **F6 — Token-exchange interne outlook_jwt → MSAL account** | **Supprimée**. Il n'y a plus d'`outlook_jwt`. Le token Bearer reçu sur `/mcp` **est** le token AAD ; il est validé par `verifyMicrosoftAccessToken` (`src/oauth-provider.ts:38`) qui l'utilise directement contre Graph `/me`. Pas de mapping `sub → MSAL account` HMAC-signé côté serveur. |
| **F7 — SQLite (clients, codes, refresh, jwks, mapping)** | **Supprimée**. `package.json` ne contient **ni `better-sqlite3` ni `jose` ni `bcrypt` ni `eta`** (vérification : `grep -E 'sqlite\|jose\|bcrypt\|eta' package.json` → vide). Le seul état persistant du serveur est le MSAL token cache (`keytar`/AES-256, hors OAuth proxy). Pas de restore playbook OAuth car pas de DB OAuth. |

**Conséquence globale** : 6 surfaces sur 8 du TM précédent sont retirées. Le blast radius côté outlook-mcp est réduit à **~200 LOC** de code auth réellement exposé (vs ~1200 LOC prévus par ADR-0002).

## Périmètre réel Niveau B

```
   ┌─────────────┐        HTTPS         ┌────────────────────────────┐
   │  Claude.ai  │◀────────────────────▶│  outlook-mcp-hardened      │
   │  (public    │                       │  (Express + MCP SDK)       │
   │   OAuth     │                       │                            │
   │   client,   │                       │  F-META ── /.well-known/*  │
   │   exact-    │                       │            (discovery)     │
   │   match     │                       │  F-AUTHZ ─ GET /authorize  │
   │   allowlist)│                       │            (proxy → AAD)   │
   └─────────────┘                       │  F-TOKEN ─ POST /token     │
                                          │            (proxy → AAD)   │
   ┌─────────────┐   MCP JSON-RPC        │  F-MCP ─── POST /mcp       │
   │  MCP client │◀────Bearer AAD ──────▶│            (Bearer-guarded)│
   │  (stdio ou  │                       │  F-VERIFY  verifyAccessTok │
   │   HTTP)     │                       │            (Graph /me)     │
   └─────────────┘                       │  F-EGRESS  fetch guard     │
                                          │            (allowlist HC)  │
                                          └─────────┬──────────────────┘
                                                    │
                              ┌─────────────────────┼────────────────────────┐
                              ▼                                              ▼
              ┌───────────────────────────────┐          ┌──────────────────────────────────┐
              │  login.microsoftonline.com    │          │  graph.microsoft.com             │
              │  (AAD — AS de confiance)      │          │  (RS Graph — data plane)         │
              └───────────────────────────────┘          └──────────────────────────────────┘
```

## Acteurs et hypothèses de confiance (mises à jour)

| Acteur | Confiance | Différence vs TM 2026-05-10 |
|---|---|---|
| Claude.ai (client OAuth public) | Allowlist exact-match `redirect_uris` | inchangé |
| Utilisateur final | Voit la page de consentement **Microsoft**, pas une page locale | consent délégué AAD (ADR-0003 §D1) |
| Reverse proxy (Caddy/nginx) | Trusted via `OUTLOOK_MCP_TRUSTED_PROXIES` allowlist IP | inchangé, mais boot guard renforcé (`src/server.ts:227`) refuse démarrage non-loopback sans TRUSTED_PROXIES |
| Microsoft AAD | Tiers de confiance — c'est **notre AS** | promu de "IdP utilisé pour token-exchange" à "AS unique" |
| Microsoft Graph | Tiers de confiance — c'est **notre RS delegate** | inchangé (allowlist egress `graph.microsoft.com`) |
| Filesystem local (MSAL cache via keytar, log files) | Trusted (mêmes droits process) | plus de SQLite ni JWKS à protéger, mais **MSAL cache** reste sensible + logs (voir SEC-01) |
| Bus agent-hub | Trusted limité (file-based, pas d'auth crypto) | inchangé |

**Nouveau : hypothèse forte sur AAD.** Le projet accepte pleinement la dépendance AAD (ADR-0003 §"Conséquences Négatives"). Si `login.microsoftonline.com` est down, l'auth est down — SLA Microsoft 99.99% jugé acceptable.

## Surfaces effectives et flux sensibles

| Code | Surface | Point d'entrée code | Type |
|---|---|---|---|
| **F-META** | Discovery `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource` | `src/server.ts:413,445` | Read metadata publique |
| **F-REG** (opt-in) | DCR strict allowlist `POST /register` (uniquement si `--enable-dynamic-registration`) | `src/oauth/http-routes.ts` `createRegisterHandler` | Refuse tout URI hors allowlist statique |
| **F-AUTHZ** | `GET /authorize` — validation + redirect 302 vers AAD | `src/server.ts:499` | Proxy OAuth authorize |
| **F-AUTHZ-405** | `POST /authorize` — refus 405 explicite | `src/server.ts:484` | Anti-bypass SDK route |
| **F-TOKEN** | `POST /token` — proxy vers AAD `/token` | `src/server.ts:699` | Pass-through code→token |
| **F-VERIFY** | `verifyMicrosoftAccessToken` : Bearer → GET Graph `/me` | `src/oauth-provider.ts:38` | Validation token AAD |
| **F-MCP** | `POST /mcp` (Bearer-protégé) | `src/server.ts:827+` (SDK mcpAuthRouter) | Route applicative MCP |
| **F-EGRESS** | Monkey-patch `globalThis.fetch` avec allowlist hardcoded | `src/security/egress-guard.ts` | Empêche exfil via fetch tiers |
| **F-CTX** | `resolveClientIp` (`src/lib/trust-proxy.ts`) + `AsyncLocalStorage` request scope | `src/request-context.ts` | IP attribution + isolation multi-req |

## STRIDE par surface

### F-META — Discovery `/.well-known/oauth-*`

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **T** | `issuer` reflète Host header attaqué (RFC 8414 §2 violation) | Moyenne | Élevé | ✅ Boot guard refuse démarrage non-loopback sans `OUTLOOK_MCP_PUBLIC_URL` (`src/server.ts:238`) + exige `https://` (`:248`). |
| **I** | Divulgue les `redirect_uris` allowlist | Faible | Faible | ✅ Assumé : l'allowlist Claude.ai est publique (URL `claude.ai/callback` documentée par Anthropic). |

### F-REG — DCR (opt-in, désactivé par défaut)

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **S** | Attaquant enregistre client "usurpateur" | Basse (endpoint absent par défaut) | Critique | ✅ Désactivé sauf `--enable-dynamic-registration`. Même activé, le handler `createRegisterHandler` refuse tout `redirect_uri` hors allowlist statique. Aucun stockage de client secret. |
| **T** | `redirect_uri` avec CRLF injection (response-splitting) | Basse | Élevé | ✅ Comparaison exact-string post-parsing URL (`allRegisteredRedirectUris()`) ; pas de wildcard, pas de préfix-match. |
| **E** | DCR crée un client avec scopes non autorisés | N/A | N/A | Enregistrement n'attribue pas de scopes propres (proxy) ; scopes intersectés au moment de `/authorize`. |

### F-AUTHZ — `GET /authorize`

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **T** | Scope elevation par requête sur-large (`Files.ReadWrite` alors qu'on n'expose que Mail/Calendar) | Haute | Critique | ✅ `intersectScopes(requested ∩ registered ∩ KNOWN)` (`src/oauth/scope.ts:29`). Fallback `Files.Read` supprimé (ADR-0003 §D2 pt.3 / codex N1-I2). Test unitaire dédié. |
| **T** | Code intercepté via `redirect_uri` non allowlist (open-redirect vers `evil.com/callback`) | Haute si non validé | Critique | ✅ `validateAuthorizeRedirectUri` exact-match contre `allRegisteredRedirectUris()` **AVANT** toute redirection ; erreur = 400 locale **sans `Location`** (anti-open-redirect, codex I2). |
| **T** | Downgrade PKCE `plain` alors qu'on advertise `S256` only | Moyenne | Critique | ✅ Refus `code_challenge_method !== 'S256'` (`src/server.ts:542`, N0 B1 conf 88). |
| **E** | POST bypass — le SDK `mcpAuthRouter` accepte `POST /authorize` sans notre validation | Haute si non intercepté | Critique | ✅ **Interceptor 405 explicite** (`src/server.ts:484`, N4 B2 conf 96 2026-06-02) monté AVANT le router SDK. |
| **D** | Flood `state`/PKCE → OOM `pkceStore` | Moyenne | Moyen | ⚠️ **PARTIEL**. Borne `state` (MAX_STATE_LENGTH) + sweep intervalle 60s (`src/server.ts:271`). **Test de flood réel manquant** (TEST-02 pending). Régression possible non détectée aujourd'hui. |
| **R** | Rejects `/authorize` (redirect_uri hors allowlist, PKCE non-S256, etc.) non audités structurellement | Actuelle | Moyen | ⚠️ **PARTIEL**. `logger.warn` émis mais **pas** `auditLog()` structuré (OBS-02 pending). |

### F-TOKEN — `POST /token`

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **T** | Replay d'un `code` déjà consommé | Faible côté nous | Critique | ✅ Délégué à AAD (AAD refuse le replay côté sa DB). Pas de code table locale. |
| **T** | `code_verifier` mismatch | Faible | Critique | ✅ Délégué à AAD. |
| **I** | Access token / refresh token loggé en clair (**SEC-01-P0**) | Historique confirmé | Critique | ✅ **FIXÉ 2026-08-02** — voir §"Findings réels" ci-dessous. |
| **R** | Émission token proxy non auditée | Actuelle | Moyen | ⚠️ **PARTIEL** — OBS-02 pending. |
| **E** | Refresh reuse → token éternel | N/A côté nous | Critique | Délégué à AAD (rotation + revocation côté AAD). Assumé (ADR-0003 §R3). |

### F-VERIFY — `verifyMicrosoftAccessToken`

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **S** | Token forgé sans clé privée AAD | Nulle | Critique | ✅ Vérification via appel réel Graph `/me` avec le token — impossible à forger sans compromettre AAD. |
| **T** | Token cross-resource (aud d'un autre MCP) | Impossible côté RFC | N/A | ⚠️ **Limitation assumée ADR-0003 §D2** : token AAD a `aud=Graph`, pas `aud=notre-host`. Pattern proxy → RFC 8707 stricte non satisfaite. **Mitigation** : documenté, scope Graph limité à Mail/Calendar, expiration courte AAD. |
| **R** | Verify d'un token invalide non audité | Faible | Moyen | ⚠️ **PARTIEL** — `logger.error` émis (`src/oauth-provider.ts:103`) mais pas `auditLog()` (OBS-02). |
| **I** | UPN (email utilisateur) loggé en clair | Fixée | Critique | ✅ `sha256:16` hash de UPN avant tout log (N0-I1 fix, `src/oauth-provider.ts:57`). Test regression `no-secret-in-logs.test.ts`. |
| **D** | Amplification via appel Graph systématique | Moyenne | Moyen | ⚠️ Assumé (ADR-0003 §R2). Cache TTL 60s prévu si perf devient un problème v0.3+. |
| **E** | Cross-user data leak par mutation globale AuthManager | Historique fixé | Critique | ✅ **N4 B3 BLOCKER fix 2026-06-02** : `authManager.setOAuthToken(token)` supprimé (`src/oauth-provider.ts:63-74`). Propagation via AsyncLocalStorage per-req. |

### F-MCP — `POST /mcp` (Bearer-protégé)

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **S** | Middleware Bearer pass-through (I2 N0 conf 86) | Historique fixé | Critique | ✅ **N0-I2 fix** : `verifyMicrosoftAccessToken` obligatoirement appelé (SDK provider ET middleware). |
| **T** | Prompt-injection via body mail retourné par tool | Actuelle | Élevé | ✅ Wrapper `<untrusted_content>` sur les bodies (`src/security/injection-wrapper.ts`) + warning dans description tool (principe #6 CLAUDE.md). |
| **I** | Scope insuffisant non détecté (Mail.Send exécuté sans scope) | Faible | Élevé | ✅ Mapping explicite tool→scope + flag `--enable-send` / `--enable-write` (write-policy `src/security/write-policy.ts`). |
| **D** | Flood /mcp | Moyenne | Moyen | ⚠️ Pas de rate-limit dédié. Reverse-proxy (Caddy/nginx) supposé le faire. Documenté `docs/MODES.md`. |
| **E** | Scope confusion (Mail.Read vs Mail.Send) | Faible | Élevé | ✅ Explicit gating via `--enable-send`. |

### F-EGRESS — allowlist `login.microsoftonline.com` + `graph.microsoft.com`

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **T** | Exfiltration via fetch vers autre host (nouveau dep phone-home, prompt-injection ordonne fetch tiers) | Faible avec guard | Critique | ✅ `egress-guard.ts` monkey-patch `globalThis.fetch` ; test `egress-guard.test.ts` vérifie crash sur host non-allowlist. Principe #3 non-négociable CLAUDE.md. |
| **T** | Nouveau cloud AAD (US Gov, China) demande nouveau hostname | Prévu | Moyen | ✅ `cloud-config.ts` maintient les hostnames par cloud (ADR-0003 §R1). |
| **I** | DNS rebinding sur hostnames allowed | Faible | Élevé | ✅ TLS + Node cert validation. Allowlist par hostname (pas IP). |
| **D** | AAD/Graph down | Moyenne | Élevé | Assumé (ADR-0003 §"Conséquences Négatives"). Pas de fallback local. |

### F-CTX — Trust proxy / IP attribution

| Cat. | Menace | Prob. | Impact | Contre-mesure (état) |
|---|---|---|---|---|
| **T** | Spoof `X-Forwarded-For` depuis client direct → contourne rate-limit / audit IP | Haute si `trust proxy: true` | Élevé | ✅ ADR-0003 §D6 : middleware custom `resolveClientIp` (`src/lib/trust-proxy.ts`) au lieu d'`app.set('trust proxy', true)`. Boot refuse démarrage non-loopback sans `OUTLOOK_MCP_TRUSTED_PROXIES` (`src/server.ts:227`, N0 I3 conf 92). |
| **I** | IP loggée en clair (PII faible mais tracé) | Actuelle | Faible | ⚠️ Pas hashée systématiquement dans les warn logs (OBS-03 pending). |

## Findings CodeQL réels — état

Les 3 findings CodeQL ERROR réels + 2 faux positifs identifiés par l'audit stratégique 2026-08-02 :

| Finding | Fichier | État 2026-08-02 | Preuve |
|---|---|---|---|
| **SEC-01-P0** `js/clear-text-logging` refresh token Azure (`M.C_...`, `1.A...`) | `src/graph-client.ts:183` | ✅ **FIXÉ** — destructuring `safeOpts` (jamais log l'objet options complet contenant le token) | `grep -n "SEC-01-P0" src/graph-client.ts` |
| **SEC-01-P0** `js/clear-text-logging` `homeAccountId` MSAL | `src/auth.ts:317` | ✅ **FIXÉ** — `hashAccount(this.selectedAccountId)` avant log | `src/auth.ts:317-323` |
| **SEC-01-P0** `js/clear-text-logging` `homeAccountId` fallback | `src/auth.ts:440` | ✅ **FIXÉ** — `hashAccount(...)` | `src/auth.ts:438-440` |
| **SEC-02** `js/regex-injection` (faux positif — pattern vient d'un flag CLI local) | `src/auth.ts:158` | ✅ **SUPPRIMÉ** avec `codeql[js/regex-injection]` + justif explicite audit 2026-08-02 | `src/auth.ts:158-160` |
| **SEC-02** `js/regex-injection` (faux positif idem) | `src/graph-tools.ts:521` | ✅ **SUPPRIMÉ** avec justif audit 2026-08-02 | `src/graph-tools.ts:521-526` |

**Régression prévention** : SEC-01-P0 doit être couvert par un test comportemental (fixture refresh token → assertion absence dans le fichier de log réellement écrit, pas grep sur source). Ticket **MAINT-TEST-BEHAV** (ADR-0004 Règle 3). Sans ce test, la fix peut régresser silencieusement au prochain refactor du logger.

## Politiques de recovery Niveau B

### R1 — Rotation MSAL cache post-incident

Si un token AAD fuite (log verbeux découvert après coup) :

1. Stopper le service.
2. Purger le keychain OS : `keytar deletePassword('outlook-mcp-hardened', '<account>')` (ou reset MSAL cache file).
3. Rotation du `AUDIT_SALT` env (pour invalider les hashes account historiques dans les logs).
4. Redémarrer — l'utilisateur doit ré-auth via device code / auth-code flow.

**Différence vs TM 2026-05-10** : plus de `DELETE FROM auth_codes/refresh_tokens` SQL à jouer. Le seul état persistant est le keytar cache MSAL.

### R2 — Refresh token compromis côté AAD

1. Révocation côté portal AAD (`https://portal.azure.com` → app registration → "Revoke all refresh tokens for this user").
2. AAD invalide le refresh sous 24h max ; l'access token expire naturellement (1h par défaut).
3. Pas d'action côté outlook-mcp (pas de DB refresh à purger — c'est le point du pivot).

### R3 — Changement de redirect_uri Claude.ai (Anthropic modifie son callback)

Inchangé vs TM 2026-05-10 :

1. Vérification du changement dans documentation Anthropic publique (pas de rumeur).
2. PR sur `config/oauth-clients.json` (source de `allRegisteredRedirectUris()`) avec le nouveau callback string littéral.
3. Cross-review N0+N1 obligatoire (touche surface auth — voir ADR-0001 grid).
4. Deploy après merge.

### R4 — Régression `verifyAccessToken` pass-through (N0-I2 revient)

Prévention primaire : test d'intégration HTTP réel (spawn serveur, POST /mcp avec Bearer forgé, attendre 401). **Manquant aujourd'hui** — ticket TEST-01 ouvert. Détection secondaire : audit event obligatoire à chaque échec de verify (OBS-02 pending).

## Croisement avec l'audit stratégique 2026-08-02

L'audit stratégique a identifié **4 patterns systémiques** (STRAT-04) + **1 pattern supplémentaire GPT-5.5** (secrets/runtime blind spot). Impact sur ce TM :

| Pattern | Impact sur TM Niveau B |
|---|---|
| **A — "Silence = succès"** (cron sec rouge, Dependabot ignoré) | Le TM ne peut pas être considéré valide si le CI qui garde ses invariants (egress guard test, no-secret-in-logs test, PKCE flood test) est rouge. Gate : Règle 1 ADR-0004. |
| **B — "CI green-washing"** | Tests `--max-warnings 0` obligatoire (Règle 2 ADR-0004). Applicable ici : chaque `eslint-disable` sur du code auth/security doit porter `// justif:`. |
| **C — "Test miroir de l'impl"** | Les BLOCKERS N4 (PKCE flood, POST /authorize 405, redactor) sont testés par grep source aujourd'hui. Ce TM identifie explicitement les endroits où la régression peut passer silencieuse : F-AUTHZ (POST 405), F-AUTHZ (PKCE flood), SEC-01 (redactor). Tickets TEST-01, TEST-02, MAINT-TEST-BEHAV. |
| **D — "Doc = intention, code = réalité"** | Ce TM lui-même est l'application du fix : au lieu de laisser croire à des surfaces AS intégré qui n'existent plus, on décrit les surfaces réelles. Le hook ADR ↔ TM (TEMPLATE.md) empêche de re-drifter. |
| **5e — Secrets/runtime blind spot** (GPT-5.5) | SEC-01-P0 fixé ne suffit pas : besoin de tests startup hostile, redaction runtime dans errors/métriques/stack traces, validation fs perms au boot. Ticket **RUNTIME-SEC-01 P1**. Ce TM référence ce ticket comme "gap connu Niveau B non résolu". |

## Risques résiduels assumés (Niveau B)

- **`aud=Graph` intrinsèque au proxy** (ADR-0003 §D2) — RFC 8707 stricte non satisfaite. Documenté ici comme risque accepté, pas comme bug à corriger.
- **Dépendance AAD disponibilité** — pas de fallback local.
- **Compromis local du process** (RCE applicative) ⇒ compromis MSAL cache → tokens exfiltrables. Pas de mitigation HSM/TEE v0.3.
- **Reverse proxy mal configuré** (TRUSTED_PROXIES faux ou trop permissif) ⇒ trust-proxy défaillant. Documentation `docs/MODES.md` + boot guard.
- **Rate-limit /mcp** délégué au reverse proxy — si l'op oublie de le configurer, DoS possible. Documenté handoff infra.
- **Runtime secret posture** (RUNTIME-SEC-01) non couvert : pas de validation au boot que les fichiers de log ont bien `0600`, pas de test que la redaction survit à un splat winston, pas de scénario "keychain absent → fail-closed vs silent-degrade".

## Champs de mesure (pour la révision suivante)

À revoir dans 8 semaines (aligné ADR-0004) :

- Tests comportementaux couvrant SEC-01, F-AUTHZ POST 405, F-AUTHZ PKCE flood : cible **présents et green**
- `auditLog()` sur les 6 sites F-* identifiés (OBS-02) : cible **≥ 6/6**
- Runtime posture (RUNTIME-SEC-01) : cible **livré ou requalifié P0**
- Nouveau pivot ADR ajouté depuis ? → clause `TM: ...` vérifiée à chaque merge d'ADR

## Références

- **ADR-0003** — pivot Niveau B (superseding decision) `docs/adr/0003-pivot-niveau-b-oauth-proxy-hardened.md`
- **ADR-0004** — discipline de maintenance (gates qui protègent ce TM) `docs/adr/0004-discipline-de-maintenance.md`
- **Audit stratégique 2026-08-02** — `docs/plans/2026-08-02-audit-maintenance-strategique.md`
- **TM précédent (superseded)** — `docs/threat-model/2026-05-10-oauth-as-threat-model.md`
- **CLAUDE.md** — principes non-négociables (minimalisme, zéro télémétrie, egress allowlist, audit trail, anti-injection, tokens locaux)
- **RFC 6749** (OAuth 2.0), **RFC 7636** (PKCE), **RFC 8414** (AS metadata), **RFC 8707** (Resource Indicators — non satisfaite strictement, assumé), **RFC 9700** (Security Topics — refresh rotation déléguée AAD), **RFC 9728** (Protected Resource Metadata)
