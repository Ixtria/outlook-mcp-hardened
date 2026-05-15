# ADR-0003 — Pivot vers OAuth proxy hardened (Niveau B), supersede ADR-0002

**Date** : 2026-05-10
**Statut** : Accepté
**Décideur** : Jimmy Blanquet
**Supersede** : [ADR-0002](0002-oauth-trust-policy-and-as-architecture.md)

## Contexte

ADR-0002 décidait d'implémenter un **AS intégré complet** (token-exchange RFC 8693, DCR, /authorize, /token, JWKS local, consent UI, SQLite, ~1200 LOC, 4 nouvelles dépendances). Justification : conformité RFC 8707 stricte + indépendance roadmap Microsoft AAD.

À mi-Lot B, après livraison des fondations (3 fonctions pures `redirect-uri` / `scope` / `trust-proxy`) et avant d'attaquer la stack SQLite/JOSE/eta/bcrypt, **arbitrage utilisateur** :

> "On rajoute du SQLite, jose, bcrypt, eta… c'est pour la sécurité ou on empile pour empiler ? Le but ce n'est pas une usine à gaz, c'est un truc un peu sécurisé pour Outlook."

L'observation est juste. Le projet déclare en `CLAUDE.md` §"Principes non-négociables" :

> "**Minimalisme** : Mail + Calendar uniquement. Rien d'autre."

L'AS intégré viole ce principe pour un gain qui ne correspond pas au scope déclaré (pas de plateforme SaaS multi-tenant, pas de souveraineté vs Microsoft AAD revendiquée explicitement, PME suisse nFADP qui peut accepter AAD comme IdP).

## Décision

**Pivoter vers Niveau B — OAuth proxy hardened.**

### D1 — Architecture AS : externe (Microsoft AAD), pas intégré

| Couche | Choix | Différence vs ADR-0002 |
|---|---|---|
| **AS** (Authorization Server) | Microsoft AAD (`login.microsoftonline.com`) | ADR-0002 prévoyait outlook-mcp AS intégré → **abandonné** |
| **RS** (Resource Server) | outlook-mcp (validation token AAD côté ingress) | inchangé |
| **OAuth proxy MCP** | `ProxyOAuthServerProvider` du SDK MCP (code actuel) **+ 3 hardenings ciblés** | ADR-0002 le supprimait → **conservé** |

Le serveur outlook-mcp **ne crée pas ses propres clients**, **ne stocke aucun token**, **n'a pas de page consent locale**, **n'émet pas de JWT**. AAD reste le tiers de confiance OAuth.

### D2 — 3 hardenings chirurgicaux sur `oauth-provider.ts`

Les findings codex B1/I1/I8 + N0 B1/I1/I2 doivent être adressés. Solution Niveau B :

1. **Wire `validateRedirectUri()`** dans `getClient` : retourner les `redirect_uris` autorisés (Claude.ai exact-match) au lieu du `http://localhost:3000/callback` actuel hardcodé. Le SDK MCP fera la comparaison exacte.

2. **Wire `verifyAccessToken`** : appeler Graph `/me` reste OK pour valider le token, mais **ajouter** une vérification que le token a été émis pour notre ressource (proxy logic : on vérifie que le `scp`/`scope` du token AAD inclut ceux qu'on s'attend à voir, et on stocke les scopes valides). Pas de validation `aud` côté outlook (le token AAD a `aud=Graph`, c'est attendu pour un proxy).

3. **Wire `intersectScopes()`** : avant de forwarder vers AAD à `/authorize`, intersecter `requested ∩ allowed_for_writepolicy ∩ KNOWN`. Drop le fallback `Files.Read` du `server.ts:377` (N1-I2 codex).

4. **Wire `resolveClientIp()`** dans `request-context.ts` : remplacer `app.set('trust proxy', true)` global par middleware lisant `OUTLOOK_MCP_TRUSTED_PROXIES` env. Pas-confiance par défaut, opt-in explicite.

### D3 — Dépendances : **aucune nouvelle**

| Dep prévue ADR-0002 | Statut Niveau B |
|---|---|
| `jose` | ❌ Non requis (pas de JWT à signer) |
| `better-sqlite3` | ❌ Non requis (pas d'état persistant nouveau) |
| `eta` | ❌ Non requis (pas de consent UI) |
| `@node-rs/bcrypt` | ❌ Non requis (pas d'IAT DCR) |

`package.json` reste tel quel. Aucun `npm install` nécessaire.

### D4 — Modules `src/oauth/redirect-uri.ts`, `src/oauth/scope.ts`, `src/lib/trust-proxy.ts` : **conservés**

Ces 3 fonctions pures et leurs 73 tests (commits b60a690 + edb294d) sont **réutilisables tels quels** dans le Niveau B. Pas de gaspi. Ils encapsulent la logique sécurité, le wiring les utilise.

### D5 — `src/oauth-provider.ts` legacy : **mis à jour**, pas supprimé

Le `MicrosoftOAuthProvider` actuel est étendu (pas remplacé) avec les 3 hardenings D2. ~50-80 LOC ajoutés. Suppression du legacy prévue ADR-0002 D7 est annulée.

### D6 — Trust-proxy : middleware Express ciblé

Dans `src/server.ts`, remplacer `app.set('trust proxy', true)` par :
- Si `OUTLOOK_MCP_TRUSTED_PROXIES` non défini ou vide → `app.set('trust proxy', false)` (refus XFF).
- Si défini → middleware custom qui injecte `req.clientIp = resolveClientIp(socket, xff, parsed_trusted_set)`. **Pas** d'usage de `req.ip` natif Express (qui suit ses propres heuristiques).
- Boot guard : refuser de démarrer en mode `http-public` si `OUTLOOK_MCP_TRUSTED_PROXIES` non défini.

### D7 — Pas de mode `http-public` au sens AS intégré

ADR-0002 distinguait `stdio` / `http-loopback` / `http-public` selon la disponibilité de l'AS intégré. Niveau B ne change rien à ce découpage de surface — `http-public` reste l'expo derrière reverse proxy — mais c'est **toujours un proxy vers AAD**, jamais un AS standalone. Les préconditions boot (`TRUSTED_PROXIES`, bind `127.0.0.1`, refus `0.0.0.0`) restent valides et nécessaires.

## Conséquences

### Positives

- **Respect du principe minimalisme** (CLAUDE.md §1) : zéro nouvelle dépendance, zéro nouveau paradigme (pas de SQLite, pas de crypto JWT, pas de templating).
- **~100 LOC ajoutés au lieu de ~1200** : surface d'audit réduite d'un ordre de grandeur.
- **Time-to-v0.2.0** : ~1 jour au lieu de 9-14j (cf. MIGRATION-PLAN v2 §4).
- **3 modules pures déjà commités sont valorisés**, pas jetés.
- **Aucun risque crypto maison** : on n'écrit pas un AS, on délègue à Microsoft qui le fait correctement depuis 15 ans.
- **Indépendance utilisateur** : un opérateur peut auditer en lisant `oauth-provider.ts` + `request-context.ts` (200 LOC total) au lieu de naviguer dans `src/oauth/` package complet.

### Négatives

- **Dépendance disponibilité AAD** : si `login.microsoftonline.com` est down, l'auth est down. Acceptable (Microsoft uptime SLA 99.99% sur AAD).
- **Token reçu par Claude a `aud=Graph`**, pas `aud=outlook-mcp`. Techniquement viole RFC 8707 stricte. **Mitigation acceptée** : c'est intrinsèque au pattern proxy, documenté dans threat model. Le risque pratique reste limité car le token est de toute façon scoped Graph et expire rapidement.
- **Pas de consent UX souverain** : c'est AAD qui montre la page de consentement. L'utilisateur voit "Microsoft" et pas "Ixtria/outlook-mcp". Cohérent avec le scope réel (le serveur consomme Graph, l'utilisateur autorise Graph).
- **Pas d'enregistrement client dynamique côté outlook-mcp** : seul Claude.ai (allowlist exact-match) peut se connecter. Tout autre client MCP doit être ajouté manuellement à la config. Acceptable car le scope déclaré est Claude.ai exclusif.

### Risques résiduels

- **R1** — Si Microsoft change les hostnames AAD (`graph.microsoft.us`, `login.microsoftonline.de`, etc.), il faut maintenir `cloud-config.ts`. Déjà géré v0.1.
- **R2** — Le `verifyAccessToken` actuel appelle Graph `/me` à chaque requête MCP. Latence + dépendance Graph permanent. Mitigation : cache mémoire 60s du résultat (à ajouter si besoin perfomance v0.3).
- **R3** — Pas de détection de token reuse côté outlook-mcp (le token AAD est self-contained, on ne le rotate pas). AAD gère sa propre lifecycle ; on ne réinvente pas.

## Alternatives reconsidérées

### Op-A — Stdio only (drop mode HTTP)

Plus minimal encore. Rejeté car le besoin d'usage Claude.ai web (transport HTTPS + OAuth) est réel et explicite.

### Op-B — Niveau B retenu (cette ADR)

Voir D1-D7.

### Op-C — AS intégré complet (ADR-0002)

Rejeté **après reconsidération** car :
- Viole le principe minimalisme du projet
- Effort disproportionné (1200 LOC + 4 deps) pour un MCP Outlook
- Surface d'audit étendue pour un gain pratique faible (RFC 8707 strict, indépendance AAD) non aligné avec le scope déclaré

ADR-0002 reste dans le repo comme **trace de réflexion** et référence si jamais le scope évolue (ex : product standalone vendu à des tiers refusant AAD).

## Plan d'application

1. Marquer ADR-0002 statut `Superseded by ADR-0003` (en-tête).
2. Réviser :
   - `SPECS-OAUTH-MCP.md` v3 — drop sections §5 DCR, §6 authorize complet, §7 token endpoint, §9 JWKS, §10 SQLite, §11 rate-limit AS, §13 discovery. Garder §8 validation token (avec aud=Graph documenté), §12 trust-proxy.
   - `MIGRATION-PLAN-FROM-MCP-VAULT.md` v3 — Lot B réduit à 2 tickets (wiring code), Lot C simplifié.
   - `TICKETS.md` v2 — Lot B/C réduits à T19+T20.
   - `docs/MODES.md` — clarifier que http-public reste proxy AAD, pas AS standalone.
   - `THREAT-MODEL` — marquer sections AS intégré (DCR, /authorize, /token, JWKS) comme "non applicables Niveau B".
   - `CHANGELOG.md` Unreleased — ajouter section "Architecture pivot 2026-05-10".
3. Implémenter T19 (oauth-provider wiring) + T20 (request-context trust-proxy).
4. Cross-review N0+N1 finale T21.
5. Tag `v0.2.0`.

## Références

- ADR-0002 (superseded) — `0002-oauth-trust-policy-and-as-architecture.md`
- Cross-review codex 2026-05-10 (findings B1/B2/I1-I9/META-CRITIQUE)
- Cross-review intermédiaire 2026-05-10 N0+N1 (commit b60a690, plan `docs/plans/2026-05-10-cross-review-oauth-first-wave.md`)
- Arbitrage utilisateur 2026-05-10 : "Niveau B me convient" (challenge minimalisme vs usine à gaz)
- CLAUDE.md §"Principes non-négociables" : minimalisme Mail+Calendar
- RFC 6749, 7591 (DCR), 8707 (Resource Indicators) — non strictement respectées par le pattern proxy, documentés
- SDK MCP `@modelcontextprotocol/sdk` ≥1.29 `ProxyOAuthServerProvider`
