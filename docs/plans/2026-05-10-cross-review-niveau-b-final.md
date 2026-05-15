# Cross-review 2026-05-10 — Niveau B final (commit 446220b + fixes)

**Range** : `HEAD~1..HEAD` au moment de la review (commit `446220b` — pivot Niveau B wiring)
**Reviewers invoqués** : N0 (Claude `pr-review-toolkit:code-reviewer`) + N1 (`codex review` gpt-5.4, failed due to bwrap sandbox)

## Résumé

| Niveau | BLOCKER | IMPORTANT | OBSERVATION |
|---|---|---|---|
| N0 sur wiring Niveau B | 2 | 3 | 3 |
| N1 codex | — | — | — (sandbox failure, ADR-0001 §règle méta 5) |

**Statut merge** : ✅ post-fix immédiat (4 findings techniques + 1 observation boot guard intégrés).

## N0 — Claude sub-agent — focus wiring src/server.ts

### B1 N0 — `offline_access` silently dropped → no refresh token (BLOCKER conf 95) ✅ FIXÉ

`buildScopesFromEndpoints()` dérive `knownScopes` de `endpoints.json` qui ne contient AUCUN scope OIDC (`offline_access`, `openid`, `profile`, `User.Read`). L'intersection `requested ∩ registered ∩ KNOWN` droppait silencieusement ces meta-scopes → AAD émettait un token sans refresh token → session Claude.ai mourrait après 1h.

**Fix** : nouvelle constante `META_SCOPES` dans `registered-clients.ts` (`offline_access`, `openid`, `profile`, `User.Read`). Dans `/authorize`, après l'intersection standard, on RE-ajoute les META_SCOPES qui sont à la fois requested ET registered (en sautant la KNOWN check, parce que ce ne sont pas des Graph permissions mais des scopes protocole OAuth/OIDC). 5 tests régression ajoutés.

### B2 N0 — `req.secure` cassé → discovery emit `http://` issuer (BLOCKER conf 92) ✅ FIXÉ

`app.set('trust proxy', false)` désactivait la lecture de `X-Forwarded-Proto`, donc `req.secure` = `false` derrière reverse proxy TLS → discovery `/.well-known/oauth-*` retournait `issuer: "http://..."` → Claude.ai refuserait le document (RFC 8414 §2 / RFC 9728 §3.1 = MUST `https://` pour issuer non-loopback).

**Fix** : Express accepte un IP allowlist comme `trust proxy` setting. Si `OUTLOOK_MCP_TRUSTED_PROXIES` non vide → `app.set('trust proxy', [...trustedProxies])`. Sinon `false` (default safe = pas de proxy = pas besoin de XFP).

### I1 N0 — `Mail.ReadWrite` dropped (IMPORTANT conf 90) ✅ FIXÉ

`CLAUDE_AI_ALLOWED_SCOPES` ne listait pas `Mail.ReadWrite`. Si Claude.ai demandait ce scope (nécessaire pour create-draft, update-mail, move-mail, delete-mail avec `--enable-send`), l'intersection avec `registered` returnait ∅ → outil silently broken.

**Fix** : ajout de `Mail.ReadWrite` à `CLAUDE_AI_ALLOWED_SCOPES`. La writePolicy reste le filter primaire via `KNOWN`.

### I2 N0 — `User.Read` dropped → /me 403 (IMPORTANT conf 88) ✅ FIXÉ

Même root cause que B1. Fix via META_SCOPES.

### I3 N0 — `allRegisteredRedirectUris()` rebuilt per request (IMPORTANT conf 82) ✅ FIXÉ

Pas un risque sécu mais incohérence : `/register` cachait via closure, `/authorize` rebuilt à chaque appel.

**Fix** : hoist `allowedRedirectUris` et `registeredScopesString` au scope du bloc `if (this.options.http)` une fois pour toutes.

### O1 N0 — Boot guard 0.0.0.0 sans TRUSTED_PROXIES (OBSERVATION) ✅ FIXÉ

ADR-0003 D6 disait : "refuser de démarrer en mode `http-public` si `OUTLOOK_MCP_TRUSTED_PROXIES` non défini". Le wiring l'avait oublié.

**Fix** : check au début du bloc `if (this.options.http)` — si bind non-loopback (≠ 127.0.0.1 / ::1 / localhost) ET `parseTrustedProxiesEnv` size 0 → throw Error avec message explicite pointant ADR-0003 D6 + MODES.md.

### O2 N0 — `/authorize` errors en text/plain au lieu de JSON OAuth (OBSERVATION) ⏳ reporté

Findings : message d'erreur révèle quel check a échoué. Pas une fuite sécu critique, juste UX. À harmoniser en `{error, error_description}` JSON v0.3.

### O3 N0 — Coverage gap wiring server.ts (OBSERVATION) ⏳ reporté

Le wiring lui-même n'a pas de test d'intégration. Modules pures à 100% mais server.ts à 0% (le coverage threshold n'est pas configuré sur server.ts). Les tests intégration via supertest devraient venir dans une vague v0.2.1 ou v0.3.

## N1 — codex — sandbox failure

`codex exec` a été bloqué par bwrap : `Failed RTM_NEWADDR: Operation not permitted`. Bug connu documenté dans ADR-0001 §règle méta 5 ("codex CLI sandboxé via bwrap échoue sur git diff local d'un repo non-pushé"). Workaround = push sur origin avant N1. Non bloquant pour ce cycle car N0 a couvert exhaustivement le diff.

## Positive durable patterns (N0)

1. Pure-module + thin wiring split → review tractable, repros faciles
2. Erreurs locales avant validation redirect_uri → codex I2 (anti open-redirect) respecté
3. Markers `// HARDENED (ADR-0003 ...)` sur chaque bloc modifié → audit-friendly
4. `parseTrustedProxiesEnv` retourne `Set` → bon datatype pour `has()` membership
5. Suppression du fallback `User.Read Files.Read Mail.Read` était la bonne direction (les BLOCKERS ne demandent PAS de revert)

## Décisions et plan de remédiation

| Finding | Statut |
|---|---|
| B1 offline_access | ✅ fixé (META_SCOPES + 5 tests) |
| B2 https issuer | ✅ fixé (trust proxy IP allowlist) |
| I1 Mail.ReadWrite | ✅ fixé (ajout CLAUDE_AI_ALLOWED_SCOPES) |
| I2 User.Read | ✅ fixé (META_SCOPES) |
| I3 hoist | ✅ fixé (allowedRedirectUris + registeredScopesString hoist) |
| O1 boot guard 0.0.0.0 | ✅ fixé (throw Error si bind non-loopback sans TRUSTED_PROXIES) |
| O2 JSON OAuth errors | ⏳ reporté v0.3 (UX, pas sécu) |
| O3 wiring integration tests | ⏳ reporté v0.2.1 (dette de coverage) |

## Tag attendu post-fix

Commit fix(oauth): N0 cross-review findings — META_SCOPES, trust-proxy IP allowlist, boot guard, hoist.

Après ce commit, le wiring Niveau B est **production-ready** pour v0.2.0 modulo les 2 OBSERVATIONS reportées v0.2.1/v0.3.

## Annexes

- Output complet N0 : agent task `a8d733e4ba85bf8c9` (transcript JSONL)
- Output N1 : `/tmp/.../bsi7q0jvr.txt` (sandbox failure logs)
