# ADR-0002 — OAuth Trust Policy & AS Architecture

**Date** : 2026-05-10
**Statut** : ⚠️ **Superseded by [ADR-0003](0003-pivot-niveau-b-oauth-proxy-hardened.md)** (2026-05-10, le même jour)
**Décideur** : Jimmy Blanquet
**Reviewers** : mcp-vault (peer N2 via bus agent-hub), codex/gpt-5.4 (cross-school N1, 13 findings, 2 BLOCKER)

> **Note historique** : Cette ADR proposait un AS intégré complet (token-exchange RFC 8693, DCR, /authorize, /token, JWKS local, consent UI, SQLite). Après livraison des fondations (3 fonctions pures) et **arbitrage minimalisme vs usine à gaz**, le projet a pivoté vers ADR-0003 (OAuth proxy hardened, ~100 LOC au lieu de ~1200). Cette ADR reste dans le repo comme trace de réflexion et référence si le scope évolue vers un produit standalone.

## Contexte

Deux questions structurantes restaient ouvertes après cross-review N1 (codex) :

### Q1 — Politique de confiance sur le client OAuth (META-CRITIQUE codex)

> *"Quelle est la politique de confiance exacte sur le client OAuth, et pourquoi DCR ouvert est-il encore nécessaire si le client visé est déjà connu et à callback fixe ?"*

Les SPECS v1 autorisaient `redirect_uri` par allowlist wildcard (`https://claude.ai/*`, `https://claude.com/*`, `https://app.*.anthropic.com/*`) — codex finding **B1 conf 96**. En parallèle, `/register` était public sans Initial Access Token — finding **B2 conf 93**. Ces deux choix combinés ouvrent une exfiltration de code et un enregistrement d'apps usurpatrices.

### Q2 — Architecture AS : proxy vers AAD vs AS intégré

Le code actuel (`src/oauth-provider.ts`) utilise `ProxyOAuthServerProvider` du SDK MCP qui **proxifie vers Microsoft AAD**. Conséquences :

- Le token reçu par Claude est un token Microsoft Graph (`aud = https://graph.microsoft.com`), **pas un token outlook-mcp**.
- Cela viole RFC 8707 (Resource Indicators) : le token n'est pas confined à la resource MCP.
- Le `getClient` est hardcodé `redirect_uris: ['http://localhost:3000/callback']` — incompatible avec Claude.ai.
- Pas de DCR, pas de JWKS local, pas de consent local.

Les SPECS écrites en parallèle décrivaient un AS intégré (`authlib`-style en TS). **Les deux architectures sont mutuellement exclusives.**

## Décision

### D1 — Architecture AS : **hybride RFC 8693 token-exchange** (Option C)

| Couche | Choix | Justification |
|---|---|---|
| **Ingress** (Claude.ai → outlook-mcp) | **AS intégré** : DCR optionnel + `/authorize` + `/token` + JWKS + consent local | Conformité RFC 8707 stricte ; JWT scopé `aud=https://<notre-domaine>/mcp` ; indépendance vis-à-vis de la roadmap AAD (Microsoft pourrait changer ses flows demain) |
| **Egress** (outlook-mcp → Graph) | **MSAL device code flow conservé** (code actuel `src/auth.ts`, `src/lib/microsoft-auth.ts`) | Déjà éprouvé ; pas de besoin de migrer côté Graph ; multi-account déjà géré |
| **Pont entre les deux** | **Mapping interne `{outlook_user_id → MSAL account}`** dans SQLite | À chaque appel tool autorisé par un JWT outlook, le serveur résout le MSAL account correspondant et l'utilise pour signer les requêtes Graph |

**Conséquence code** : `src/oauth-provider.ts` actuel est remplacé. Il sert d'inspiration pour le `verifyAccessToken` pattern, mais devient un AS local + verifier JWT local.

### D2 — Trust policy par client : **registered-clients-only par défaut**

Trois modes de confiance, choisis au boot par variable env `OAUTH_TRUST_MODE` :

| Mode | Description | Cas d'usage |
|---|---|---|
| `registered-only` **(défaut, recommandé)** | DCR **désactivé**. Liste statique de clients pré-enregistrés dans `config/oauth-clients.json` (Claude.ai uniquement par défaut). | Production, déploiement souverain, posture stricte |
| `registered-trusted-dcr` | DCR **activé** mais avec : (a) `redirect_uri` exact-match contre allowlist hardcodée par client name ; (b) Initial Access Token requis (`OAUTH_DCR_INITIAL_TOKEN` env var, distribué hors-bande) | Multi-client connu (Claude + ChatGPT + futurs MCP clients), enrôlement contrôlé |
| `open-dcr` | DCR ouvert (legacy / dev local). Rate-limit IP strict, jamais en prod. | Dev/CI uniquement, refus boot si `NODE_ENV=production` |

**Fixe le finding B1 (conf 96)** : plus aucun pattern wildcard. Chaque `redirect_uri` est une string littérale comparée par `===`.

**Fixe le finding B2 (conf 93)** : DCR n'est plus ouvert par défaut. Et même quand il l'est, il exige un IAT.

### D3 — Liste exacte des `redirect_uris` Claude.ai (registered-only)

Source : tests d'intégration Claude.ai + bug Anthropic claude-ai-mcp#82 + SPECS-OAUTH-MCP.md v1 §5.

```json
{
  "name": "claude",
  "client_id": "claude-anthropic-builtin",
  "redirect_uris": [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback"
  ],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "mcp:read"
}
```

**Pas de wildcard `*.anthropic.com`**. Si Anthropic ajoute un domaine, on ajoute la string littérale après vérification documentaire publique.

### D4 — DCR mode (registered-trusted-dcr) — règles obligatoires

Si `OAUTH_TRUST_MODE=registered-trusted-dcr` :

1. **IAT obligatoire** : header `Authorization: Bearer <IAT>` à `/register`, sinon `403`. IAT est une chaîne aléatoire 32 bytes générée par l'admin via `outlook-mcp admin issue-iat --label <name>`.
2. **`client_name` ↔ allowlist** : table `OAUTH_DCR_TRUSTED_CLIENTS` mappant `client_name` → URIs exactes acceptées. Tout DCR doit déclarer un `client_name` connu ; tout `redirect_uri` doit être dans l'allowlist exacte pour ce nom.
3. **`fullmatch` strict** : pas de `match`, pas de regex permissive. Comparaison `===` après normalisation (lowercase scheme+host, path tel quel).
4. **Refus trailing `\n`, `\r`, espaces, percent-encoded slashes** dans `redirect_uri` (anti response-splitting).
5. **`token_endpoint_auth_method=none` autorisé uniquement pour les clients publics dont les redirect_uris sont en `https://`** (pas de localhost/HTTP en prod).

### D5 — Refus de la "trusted-redirect exception" (P9 mcp-vault Option B)

Codex finding **I9 conf 87** : importer le pattern "trusted-redirect grants full registered scope" de mcp-vault v0.3.4 entre en collision avec l'exact-match strict. **On ne l'importe pas**. La politique reste : `effective_scope = requested ∩ registered ∩ KNOWN`, pas d'exception par client trusted (codex finding **I1 conf 95**).

Rationnel : mcp-vault avait ce besoin pour ChatGPT qui demandait toujours `scope=mcp:read` explicitement — un cas de friction OAuth-strict. Notre choix : si un client a besoin de ça, on l'enregistre avec le scope exact qu'il demande, plutôt que d'introduire une exception transversale. Si plus tard outlook-mcp doit supporter ChatGPT, on ajoute une entrée registered-only dédiée.

### D6 — Threat model et politiques de recovery : DOIVENT exister

Codex META-CRITIQUE : "manque threat model explicite, politique recovery post-restore, post-reuse, post-rotation".

Ces documents sont **prérequis obligatoires** au merge du Lot B (OAuth). Ils sont créés en parallèle de cette ADR :

- `docs/threat-model/2026-05-10-oauth-as-threat-model.md`
- `docs/MODES.md` (matrice stdio / http-loopback / http-public, finding O2)
- `SECURITY.md` (mise à jour avec liens)

## Conséquences

### Positives

- **Surface d'attaque OAuth réduite massivement** : pas de DCR ouvert, pas de wildcard, IAT requis si DCR.
- **Conformité RFC 8707 stricte** : JWT outlook scopé `aud=<our-mcp-resource>`, plus de fuite de tokens AAD.
- **Indépendance roadmap Microsoft** : si AAD change ses endpoints/flows, on ne casse pas Claude.
- **Audit clair** : chaque event OAuth a un `client_id` connu et stable, pas un DCR éphémère anonyme.
- **Aligné mcp-vault** : même grille de patterns (intersection scope, exact-match), aucune dérive cross-projet.

### Négatives

- **~1200 LOC TS à écrire** : AS intégré complet (DCR si activé, /authorize, /token, JWKS, consent, verifier) + SQLite + token-exchange interne MSAL.
- **`src/oauth-provider.ts` actuel devient legacy** : à supprimer (pas à muter — éviter la confusion de deux providers cohabitant).
- **Nouvelle dépendance crypto** : besoin d'une lib JOSE TS (`jose` package, MIT, maintenu par panva). Acceptable, dépendance directe sans transitives.
- **Multi-account UX plus complexe** : il faut un mapping `outlook_jwt.sub → MSAL account`. Cas premier login = consent UI + déclenchement device code flow côté serveur.

### Risques résiduels

- **R1** — JWKS rotation downgrade attack si l'algo n'est pas figé. Mitigation : `alg=EdDSA` (Ed25519) figé, refus de tout token avec un `alg` différent (codex finding I7 conf 79).
- **R2** — Token replay si auth_codes consommation pas atomique. Mitigation : `BEGIN IMMEDIATE; UPDATE … WHERE used=0` avec check `rowcount==1` (codex finding I4 conf 94).
- **R3** — Refresh token reuse non détecté. Mitigation : `token_family` + `parent_token_hash` + révocation famille (codex finding I5 conf 91).
- **R4** — Backup SQLite incohérent ressuscite tokens révoqués. Mitigation : politique restore = `DELETE FROM auth_codes; DELETE FROM refresh_tokens` post-restore (codex finding I6 conf 88, documentée dans MODES.md).

## Alternatives envisagées et rejetées

### Op-A — Garder OAuth proxy + ajouter `aud` claim sur token AAD

Idée : ne pas refondre, juste demander à Microsoft AAD un token avec `aud=outlook-mcp` via le param `resource` (legacy v1) ou `scope` v2.

**Rejetée** car :
- AAD v2 ne supporte pas la délivrance de tokens custom `aud` arbitraires côté ressources tierces.
- On reste dépendant de la disponibilité d'AAD (le serveur outlook ne peut pas auth Claude si AAD est down).
- Le pattern proxy MCP est notoirement problématique (advisory FastMCP v3 RFC 8707).
- Pas de consent UX souverain : c'est AAD qui montre la page de consentement, on perd la transparence.

### Op-B — AS intégré pur (pas de token-exchange interne)

Idée : Claude → outlook AS → JWT outlook. Pour parler à Graph, le serveur outlook utilise un service account M365 (client credentials).

**Rejetée** car :
- Multi-account utilisateur perdu (le service account = un seul tenant).
- Demande des permissions Graph "Application", très privilégiées, dangereuses si compromise.
- Pas le scope du fork (le fork part de MSAL device code = user-delegated).

### Op-C (retenue) — AS intégré ingress + MSAL conservé egress

Voir D1.

## Plan d'application

Cette ADR débloque le Lot B (OAuth) du plan migration. Séquence :

1. Spec v2 réécrite avec cette architecture (T08)
2. Threat model détaillé (T04)
3. Tickets atomiques (T10)
4. Implémentation TDD : skeleton AS → DCR → /authorize → /token → JWKS → consent → verifier → token-exchange MSAL
5. Cross-review N0+N1 sur le code (T16) avant tag v0.2.0

## Références

- Codex review 2026-05-10, findings B1/B2/I1/I4/I5/I7/I9/META-CRITIQUE
- mcp-vault peer review 2026-05-10 (Q1-Q5 reçues)
- RFC 6749, 7591, 7636, 8414, 8707, 9700, 9728
- RFC 8693 — OAuth Token Exchange
- MCP Authorization spec (2026-04) — https://modelcontextprotocol.io/specification/2026-04-XX/basic/authorization
- mcp-vault ADR-0001 — grille N0+N1+N2
- `~/Projets/outlook-mcp-hardened/SPECS-OAUTH-MCP.md` v1 (à réécrire v2 cf. T08)
- `~/Projets/outlook-mcp-hardened/MIGRATION-PLAN-FROM-MCP-VAULT.md` v1 (à réécrire v2 cf. T09)
