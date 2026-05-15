# Threat Model — OAuth AS intégré + intégration M365

**Date** : 2026-05-10
**Auteur** : Jimmy Blanquet
**Reviewers** : codex/gpt-5.4 (META-CRITIQUE 2026-05-10), mcp-vault peer
**Couvre** : Lot B (OAuth AS) + couches connexes (egress, audit, trust-proxy)

## Périmètre

```
   ┌───────────────┐                          ┌────────────────────────────┐
   │  Claude.ai    │  HTTPS (TLS reverse-    │  outlook-mcp-hardened       │
   │  (public      │  proxy + outlook AS)    │                            │
   │   OAuth       │ ◀──────────────────────▶│  ┌──────────────────────┐  │
   │   client)     │                          │  │ AS intégré ingress  │  │
   └───────────────┘                          │  │ (DCR/auth/token/JWT)│  │
                                              │  └──────────────────────┘  │
                                              │  ┌──────────────────────┐  │
                                              │  │ Token-exchange       │  │
                                              │  │ outlook_jwt → MSAL   │  │
                                              │  └──────────────────────┘  │
                                              │  ┌──────────────────────┐  │
                                              │  │ MSAL device flow     │──────▶ login.microsoftonline.com
                                              │  └──────────────────────┘  │
                                              │  ┌──────────────────────┐  │
                                              │  │ Graph client + egress│──────▶ graph.microsoft.com
                                              │  │ guard + audit log    │  │
                                              │  └──────────────────────┘  │
                                              │  ┌──────────────────────┐  │
                                              │  │ SQLite (clients,     │  │
                                              │  │ codes, refresh,      │  │
                                              │  │ jwks_keys, mapping)  │  │
                                              │  └──────────────────────┘  │
                                              └────────────────────────────┘
```

## Acteurs et hypothèses de confiance

| Acteur | Confiance | Hypothèse |
|---|---|---|
| Claude.ai (client OAuth public) | Connu, pré-enregistré, callback fixe | Microsoft public client, peut être compromis par phishing utilisateur |
| Utilisateur final (humain) | Lecteur du consent, choisit d'autoriser | Peut être ingénierie-socialisé pour valider un consent malveillant |
| Reverse proxy (Caddy/nginx) | Trusted via `TRUSTED_PROXIES` allowlist IP | Considéré L7-fidèle après config |
| Microsoft AAD (`login.microsoftonline.com`) | Tiers de confiance Microsoft | Disponible, conforme RFC, mais sa roadmap nous échappe |
| Microsoft Graph (`graph.microsoft.com`) | Tiers de confiance | Idem |
| Filesystem local (SQLite, jwks, MSAL cache) | Trusted (mêmes droits que le process) | Compromis local ⇒ compromis total assumé |
| ixtriasrv (LLM local pour N2) | Best-effort | Hors path applicatif, juste outillage review |
| Bus agent-hub (N3 peer mcp-vault) | Trusted limité | Pas d'auth crypto, file-based — utilisé pour signalisation, pas pour décisions sécurité |

## Surfaces et flux sensibles

1. **F1 — DCR** : `POST /register` (mode `registered-trusted-dcr` uniquement, sinon désactivé)
2. **F2 — Authorize** : `GET /authorize?...` + page consent + `POST /authorize/consent`
3. **F3 — Token** : `POST /token` (grant authorization_code + refresh_token)
4. **F4 — JWKS** : `GET /jwks.json`, `GET /.well-known/oauth-*`
5. **F5 — MCP** : `POST /mcp` Bearer-protégé, route applicatif réelle
6. **F6 — Token-exchange interne** : à chaque appel /mcp, mapping `outlook_jwt.sub → MSAL account` puis Graph
7. **F7 — Persistence** : lectures/écritures SQLite (clients, codes, refresh, jwks, mapping)
8. **F8 — Egress** : fetch vers `login.microsoftonline.com` ou `graph.microsoft.com`

## STRIDE par surface

### F1 — DCR `/register`

| Catégorie | Menace | Probabilité | Impact | Contre-mesure |
|---|---|---|---|---|
| **S**poofing | Attaquant s'enregistre comme "Claude" usurpateur (codex B2) | Haute si DCR ouvert | Critique | DCR registered-only par défaut. Mode DCR exige Initial Access Token (IAT) bearer + allowlist `client_name → URIs exactes`. |
| **T**ampering | `redirect_uri` avec trailing `\n` exploite response-splitting (codex v0.3.4 mcp-vault) | Moyenne | Élevé | `fullmatch` strict avec rejet de `\r\n\t ` et `%2F` / `%5C` / `%00` post-décodage. |
| **R**epudiation | Enregistrement sans audit | Faible | Moyen | Audit event `oauth.register` avec `iat_label`, `client_name`, `redirect_uris_hash`. |
| **I**nfo disclosure | Énumération de `client_id` valides via erreurs différentielles | Faible | Faible | Erreurs uniformes `invalid_client_metadata` sans détail discriminant. |
| **D**oS | Flood de DCR | Haute | Moyen | Rate-limit IP 10/h hardcodé en mode `registered-trusted-dcr`. Mode `registered-only` = endpoint absent (404). |
| **E**lev. priv. | DCR crée un client avec scopes non autorisés | Haute si non filtré | Critique | `scope` à DCR intersecté avec `KNOWN_SCOPES` ; refus si vide. |

### F2 — Authorize `/authorize` + consent

| Cat. | Menace | Prob. | Impact | Contre-mesure |
|---|---|---|---|---|
| **S** | CSRF du POST consent | Moyenne | Critique | CSRF token lié à la session, vérifié côté serveur (codex I3). |
| **S** | Clickjacking de la page consent | Moyenne | Critique | `Content-Security-Policy: frame-ancestors 'none'` + `X-Frame-Options: DENY`. |
| **T** | Open redirect via erreur de validation (codex I2) | Moyenne | Élevé | Erreurs avant validation `client_id`+`redirect_uri` → page locale, jamais 302 vers une URL externe. |
| **T** | Scope elevation par form tampering (mcp-vault B1) | Haute | Critique | `effective_scope = requested ∩ registered ∩ KNOWN` calculé **après** consent, persisté immutable en `auth_codes.scope`. |
| **R** | Consent sans liaison session/transaction | Moyenne | Élevé | Session cookie `HttpOnly; Secure; SameSite=Strict` ; consent POST exige `session.user_id == auth_code.user_id`. |
| **I** | Fuite de `state` opaque dans logs | Faible | Faible | `state` non loggé en JSON, seulement hash SHA-256[:8]. |
| **D** | Flood consent | Moyenne | Moyen | Rate-limit IP 100 req/min mode `http-public`. |
| **E** | Code authorization volé via redirect mal validé (codex B1) | Haute si wildcard | Critique | `redirect_uri` `===` exact-match contre registered. Aucun wildcard. PKCE `S256` obligatoire (pas de `plain`). |

### F3 — Token `/token`

| Cat. | Menace | Prob. | Impact | Contre-mesure |
|---|---|---|---|---|
| **S** | Replay d'un `code` déjà consommé (codex I4) | Haute sous concurrence | Critique | `BEGIN IMMEDIATE; UPDATE auth_codes SET used=1 WHERE code=? AND used=0 AND expires_at>?`. Refus si `rowcount != 1`. |
| **T** | `code_verifier` mismatch | Faible | Critique | Vérif `S256(verifier) == challenge_stored`, comparaison constant-time. |
| **T** | `resource` mismatch entre /authorize et /token | Moyenne | Élevé | Stocké en `auth_codes`, comparé strict-equal à /token. RFC 8707. |
| **R** | Émission de token sans audit | Faible | Moyen | `oauth.token.issued` audit event avec `jti`, `aud`, `scope`. Pas de payload. |
| **I** | Token leak via logs verbeux | Moyenne | Critique | Logs structurés interdisent `token`/`access_token`/`refresh_token` en clair. Tests anti-fuite obligatoires. |
| **D** | Brute-force refresh tokens | Moyenne | Moyen | Refresh hashé SHA-256 en DB ; lookup constant-time ; rate-limit IP. |
| **E** | Refresh stolen → token éternel (codex I5) | Moyenne | Critique | Rotation obligatoire + `family_id` + détection reuse → révocation famille (RFC 9700). |

### F4 — JWKS / discovery

| Cat. | Menace | Prob. | Impact | Contre-mesure |
|---|---|---|---|---|
| **T** | Confusion `alg` (RS256 vs HS256 vs none) | Moyenne | Critique | `alg=EdDSA` figé. Verifier refuse tout token avec `alg` différent (codex I7). |
| **T** | `kid` spoofing pendant rotation | Faible | Critique | `kid` UUIDv4 unique, lookup strict `kid → key` ; pas de fallback "essaie toutes les clés". |
| **I** | Fuite clé privée JWKS | Faible si AES-GCM | Critique | Privées stockées AES-256-GCM (passphrase `JWT_PRIVATE_KEY_PASSPHRASE` env), publiques seules en JWKS. |
| **D** | Rotation ratée → tous tokens invalides | Moyenne | Élevé | Grace period 7j (clé old reste dans JWKS pour validation, retire de signature). Test régression `test_jwks_grace_period`. |

### F5 — MCP `/mcp` (Bearer-protégé)

| Cat. | Menace | Prob. | Impact | Contre-mesure |
|---|---|---|---|---|
| **S** | Token forgé sans clé privée | Faible | Critique | Verifier strict (`alg`+`kid`+`iss`+`aud`+`exp`+`nbf`). |
| **T** | Token cross-resource (aud d'un autre MCP) | Moyenne | Critique | `aud == "https://<our-host>/mcp"` strict-equal. RFC 8707. |
| **R** | Appel tool sans audit | Faible | Moyen | Audit `tool.invoke` avec `jti`, `tool`, `account_hash`, `status`. |
| **I** | Scope insuffisant non détecté | Moyenne | Élevé | Chaque tool déclare son scope requis. Middleware refuse si `effective_scope` ne contient pas. |
| **D** | Flood /mcp | Moyenne | Moyen | Rate-limit IP token-bucket. |
| **E** | Scope confusion (Mail.Read vs Mail.Send) | Moyenne | Élevé | Mapping explicite `tool → scope` + flag `--enable-send`. |

### F6 — Token-exchange interne

| Cat. | Menace | Prob. | Impact | Contre-mesure |
|---|---|---|---|---|
| **S** | Mapping `outlook_sub → MSAL account` falsifié | Faible | Critique | Mapping écrit uniquement par flow consent + MSAL device, signé HMAC sur secret serveur. |
| **T** | MSAL token cache poisoning | Faible | Élevé | MSAL cache via `keytar` (OS keychain) ; intégrité du keychain hors scope applicatif. |
| **I** | MSAL token loggé en clair | Moyenne | Critique | Logs filtrés ; test `test_no_msal_token_in_logs`. |
| **E** | Utilisation MSAL token d'un autre user | Faible | Critique | Mapping vérifié à chaque appel ; check `jwt.sub == mapping.outlook_sub`. |

### F7 — SQLite persistence

| Cat. | Menace | Prob. | Impact | Contre-mesure |
|---|---|---|---|---|
| **T** | Restore d'un snapshot ancien ressuscite tokens révoqués (codex I6) | Moyenne | Élevé | Procédure restore documentée : `DELETE FROM auth_codes; DELETE FROM refresh_tokens` avant remise en service. |
| **T** | Race write sans transaction | Moyenne sous charge | Élevé | Mode WAL + `BEGIN IMMEDIATE` sur toutes les écritures sensibles. |
| **I** | Lecture DB par un autre process | Faible | Critique | Fichier `0600` owner-only ; durcissement systemd `ProtectSystem=strict`. |
| **D** | Disque plein | Moyenne | Moyen | Monitoring déféré à `infra` (peer) ; refus écrits non critiques si <50MB libres. |

### F8 — Egress

| Cat. | Menace | Prob. | Impact | Contre-mesure |
|---|---|---|---|---|
| **T** | Exfiltration via fetch vers autre host | Faible | Critique | `egress-guard.ts` monkey-patch `globalThis.fetch` ; allowlist hardcodée `login.microsoftonline.com` + `graph.microsoft.com`. Test `test_egress_violation_crashes`. |
| **I** | DNS rebinding sur les hostnames allowed | Faible | Élevé | TLS + cert pinning délégué au runtime Node ; allowlist exact hostname (pas IP). |

## Politiques de recovery

Codex META-CRITIQUE : "politique de dégradation/recovery manquante".

### R1 — Post-restore SQLite

1. Stopper le service (`systemctl stop outlook-mcp`).
2. Remplacer le fichier `.sqlite` par le snapshot.
3. Exécuter `outlook-mcp admin post-restore-cleanup` qui :
   - `DELETE FROM auth_codes;`
   - `DELETE FROM refresh_tokens;`
   - Vérifie que `jwks_keys` contient au moins une clé active non `retired`.
4. Redémarrer.

**Effet** : tous les utilisateurs doivent ré-authentifier. Acceptable car restore est un événement rare.

### R2 — Détection de refresh reuse

1. Audit event `oauth.refresh.reuse_detected` émis (severity=ALERT).
2. Révocation de toute la famille : `UPDATE refresh_tokens SET revoked=1 WHERE family_id=?`.
3. Si `family_id` apparaît dans plus de N=3 alertes/heure, blocage du `user_id` (table `users.suspended_at`) ; ré-auth requise.

### R3 — Rotation clé JWT ratée

1. Si génération nouvelle clé échoue, ancienne clé reste active.
2. Si publication JWKS échoue mais ancienne clé déjà retirée → rollback : remettre `retired_at = NULL` sur la dernière clé valide.
3. Audit event `oauth.jwks.rotation_failed` avec stack trace dans `details`.

### R4 — Changement de redirect_uri Claude.ai

Si Anthropic ajoute/change un callback :

1. Vérifier le changement dans documentation publique Anthropic (pas de rumeur).
2. PR sur `config/oauth-clients.json` avec nouveau callback string littéral.
3. Cross-review N0+N1 obligatoire (touche surface auth).
4. Deploy après merge.

## Mesures transversales

- **Logs structurés JSON sur stderr** uniquement (jamais stdout — corrompt MCP stdio protocol)
- **Pas de PII en clair** : `user_id` hashé SHA-256, IP hashée SHA-256, `state` hashé SHA-256[:8]
- **Tests anti-fuite** : suite `__tests__/no-secret-in-logs.test.ts` vérifie que pour chaque event, aucune string ne contient `eyJ` (JWT prefix), `Bearer `, `client_secret`, etc.
- **Egress guard** vérifié dans `__tests__/egress-guard.test.ts` avec `EgressViolationError` lancé sur fetch hors allowlist
- **Quality gate CI** : coverage ≥80% sur `src/security/`, `src/oauth/`, `src/request-context.ts`

## Risques résiduels assumés

- **Compromis local du process** (RCE applicative) ⇒ compromis total — pas de mitigation crypto matérielle prévue v0.2.
- **Reverse proxy mal configuré** (TRUSTED_PROXIES list erronée) ⇒ trust-proxy défaillant — documentation `MODES.md` + checklist `infra` handoff.
- **Anthropic change un comportement Claude.ai non documenté** ⇒ casse silencieuse — détectée par tests d'intégration `MCPJam/inspector` en CI.
- **Utilisateur ingénierie-socialisé** valide un consent malveillant ⇒ hors périmètre technique (mitigation = page consent informative + `client_name` visible).

## Référence cross-projet

- `mcp-vault` couvre les mêmes surfaces F1-F4 + F7 sur SQLite/storage. Réviser de pair quand un fix sécurité touche un pattern partagé.
- `infra` peer gère reverse-proxy, TLS, backups, monitoring — handoff documenté `docs/HANDOFF_INFRA.md` (à créer en lot C).
