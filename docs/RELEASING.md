# RELEASING

Process de release, deprecation et support pour `@ixtria/outlook-mcp-hardened`.

## 1. Versionning — SemVer strict

| Bump | Déclencheur |
|------|-------------|
| **MAJOR** (`X.0.0`) | Breaking change sur l'API publique : tools MCP retirés/renommés, changement de contrat sur les paramètres, changement de comportement observable non-rétrocompatible (ex. format du champ `account` dans l'audit log v0.2→v0.3), bump de Node minimum. |
| **MINOR** (`x.Y.0`) | Nouvelle fonctionnalité rétrocompatible : nouveau tool, nouveau flag CLI, nouveau format d'audit ajouté sans casser les consommateurs. |
| **PATCH** (`x.y.Z`) | Fix rétrocompatible : bug, correctif sécurité, dépendance patchée. |

**Toute breaking change DOIT** apparaître dans la section `### Breaking changes` du CHANGELOG et être annoncée en deprecation au moins 2 minor avant (voir §3), sauf correctif sécurité P0.

## 2. Commit convention

Format Conventional Commits : `type(scope): description`.

Types acceptés : `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `ci`, `build`, `perf`, `revert`.
Scopes courants : `auth`, `graph`, `security`, `deploy`, `ci`, `deps`, `docs`.

Un footer `BREAKING CHANGE:` déclenche systématiquement un bump MAJOR.

## 3. Deprecation policy

1. Toute fonctionnalité destinée à être retirée est annoncée `Deprecated` dans le CHANGELOG d'un release **MINOR N.x**.
2. Le retrait effectif ne peut avoir lieu **au plus tôt au release N+2** (2 minors de préavis, ~= plusieurs mois).
3. Tant que la fonctionnalité est deprecated mais encore présente, le serveur DOIT émettre un warning sur `stderr` au démarrage si le consommateur active/utilise la surface concernée (ex. `--enable-send` deprecated → warning avant le premier appel).
4. Le retrait effectif est un **breaking change** et suit §1 (bump MAJOR).

Exception : un retrait pour cause sécurité (CVE non-mitigable en place) peut se faire à un minor sans préavis. Il DOIT alors être documenté comme `Security` dans le CHANGELOG avec justification.

## 4. Support matrix

| Composant | Version(s) supportée(s) | Note |
|-----------|-------------------------|------|
| **Node.js** | `>= 22` LTS (Jod), `24` Current | Node 20 EOL 2026-04, non supporté (voir ticket AUTO-04). |
| **MCP protocol** | version(s) déclarées dans `@modelcontextprotocol/sdk` de la release courante | Bump du SDK = MINOR sauf breaking. |
| **Linux** | Ubuntu 22.04+, Debian 12+ | **tested** (CI + prod déploiement Phase C). |
| **macOS** | 14+ (Sonoma) | **tested** manuellement, `keytar` via Keychain. |
| **Windows** | 11 / Server 2022 | **best-effort** — pas de CI, `keytar` via Credential Manager. Issues acceptées mais non prioritaires. |
| **Azure Cloud** | Global Azure AD / Entra ID uniquement | Sovereign clouds (US Gov, China) non supportés. |

## 5. LTS policy

| Ligne MAJOR | Statut | Durée |
|-------------|--------|-------|
| **Dernière MAJOR (`N`)** | Full support (fix, feature, security) | tant que c'est la dernière |
| **Précédente MAJOR (`N-1`)** | **Security-only** (backport patch CVE HIGH/CRITICAL) | 6 mois après la sortie de `N.0.0` |
| **`N-2` et antérieures** | **Pas de support** | — |

Les patches security-only sont taggés `N-1.x.y` sur une branche `release/N-1.x` maintenue le temps du support.

## 6. Release process

Pré-requis : working tree clean, sur `main` à jour, `npm run verify` vert.

```bash
# 1. Rédiger la section CHANGELOG (Added/Changed/Deprecated/Removed/Fixed/Security)
$EDITOR CHANGELOG.md              # basculer [Unreleased] -> [X.Y.Z] - YYYY-MM-DD

# 2. Bump version + tag annoté
npm version <major|minor|patch>   # met a jour package.json + package-lock + git tag vX.Y.Z

# 3. Push
git push origin main --follow-tags

# 4. GitHub Release (colle la section CHANGELOG comme body)
gh release create vX.Y.Z \
  --title "vX.Y.Z" \
  --notes-file <(awk '/^## \[X.Y.Z\]/,/^## \[/' CHANGELOG.md | sed '$d')

# 5. Publish npm (si le package est publié — pas encore le cas au v0.3)
npm publish --access public --provenance
```

### Checklist pré-tag

- [ ] `npm run verify` vert (generate + lint + typecheck + build + test:coverage)
- [ ] `npm audit --production --audit-level=moderate` vert
- [ ] CHANGELOG section `[Unreleased]` déplacée vers `[X.Y.Z] - YYYY-MM-DD`
- [ ] Breaking changes explicitement listés dans une sous-section dédiée
- [ ] Deprecations warnings testées (message stderr au démarrage)
- [ ] Support matrix à jour si bump Node minimum ou drop d'OS

### Checklist post-tag

- [ ] GitHub Release créée avec notes complètes
- [ ] Branche `release/N-1.x` créée si la ligne précédente entre en security-only
- [ ] Advisory GHSA publiée si la release contient un fix CVE (voir SECURITY.md)
- [ ] Bus agent-hub notifié via `send-message.sh` (peer `infra` pour déploiement, peer `orchestrator` pour info)

## 7. Hotfix / security release

Pour un fix P0 sur une ligne en support :

1. Brancher depuis le tag : `git checkout -b hotfix/vN.M.(Z+1) vN.M.Z`
2. Fix + test comportemental démontrant la régression corrigée (ADR-0004 règle 3)
3. `npm version patch` puis release process §6 depuis la branche hotfix
4. Merger la fix sur `main` (cherry-pick ou merge suivant l'écart de code)

## 8. Références

- ADR-0004 — Discipline de maintenance : `docs/adr/0004-discipline-de-maintenance.md`
- Politique sécurité + coordinated disclosure : `SECURITY.md`
- Historique versions : `CHANGELOG.md`
