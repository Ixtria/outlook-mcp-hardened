# ADR-0001 — Grille d'industrialisation des reviews multi-LLM

**Date** : 2026-05-10
**Statut** : Accepté
**Décideur** : Jimmy Blanquet
**Inspiré de** : [`mcp-vault/docs/adr/0001-cross-llm-review-grid.md`](https://github.com/Ixtria/mcp-vault/blob/main/docs/adr/0001-cross-llm-review-grid.md) v3.3

## Contexte

`outlook-mcp-hardened` entre en phase d'industrialisation post-v0.1 avec un Lot B (OAuth AS intégré) à fort risque sécurité (~1200 LOC TS, crypto JWT, surface DCR). Adopter une grille de review multi-LLM dès maintenant évite la régression typique "tout-Claude se valide soi-même" (cf. mcp-vault incident 2026-04-30 où N0 sub-agent a flaggé une élévation de scope que la review Claude monolithique avait validée).

Cette ADR transpose la grille mcp-vault en l'adaptant au contexte TypeScript / Node 20 / vitest.

## Décision

### Grille principale — quel LLM, à quelle étape, à quel coût

| Étape SDLC | LLMs invoqués | Coût tokens | Latence cible | Bloque ? | Justification |
|---|---|---|---|---|---|
| **Pre-commit** | N2 (qwen36-27b OU devstral-small-2 via ixtriasrv HTTP) sur `git diff --staged` | 0 € (GPU local) | 10–30 s | warn-only | Gratuit, contexte 16–32K tokens largement suffisant pour un commit unitaire |
| **Pre-push** | N0 (Claude sub-agent `pr-review-toolkit:code-reviewer`) sur `@{u}..HEAD` | $$ | 30–60 s | warn-only | Catch les intégrations cross-fichiers que N2 voit mal sur petit contexte |
| **PR opened** | N0 + N2 par-fichier en parallèle | $$$ | 2–5 min | warn-only | Duplication contrôlée, anti-blind-spot intra-school Anthropic |
| **Pre-merge gate** | N1 (`codex review` gpt-5.4) sur le diff de la PR | $$$$ | ~5 min | **bloque si BLOCKER détecté** | Cross-school = la vraie valeur ajoutée |
| **N3 peer (optionnel)** | mcp-vault via bus agent-hub `peer-ask` (peer review entre serveurs MCP Ixtria) | 0 € hors LLM peer | timeout 300s | warn-only | Catch les divergences cross-projet (ex : XFF rightmost dispute 2026-05-10) |
| **Post-merge / staging** | aucun LLM | — | — | — | Tests E2E + smoke suffisent |
| **Pre-prod / release** | aucun LLM sur le code | — | — | — | Release notes only, sauf hotfix |

**Lecture** : une feature traverse pre-commit → pre-push → PR → pre-merge (+ N3 si touche surface partagée avec mcp-vault). Hotfix `fix:` trivial peut être accéléré (cf. règle méta n°2).

### Règles méta (les 7 garde-fous, inchangés mcp-vault)

1. **No re-review on identical code.** Fingerprint = `git rev-parse <range>` + hash du diff. Cache local sous `.cache/cross-review/<fingerprint>.json`. Implémentation via `pf-cross-review-iterate` extension Project-Forge.

2. **Trivial-commit detection** :
   - `comment-only` : diff ne touche que `//` ou `/* */`
   - `rename-only` : `git diff --stat` ne montre que des renames (R100)
   - `bump-version` : seul `package.json` change, `version` field uniquement
   - `formatting-only` : `prettier --write` est la seule diff sémantique (skip N0/N1, N2 warn-only)

3. **Budget cap LLM** : plafond souple `$5/jour` cumulés sur N0+N1. N2 gratuit, hors cap.

4. **Diff trop gros pour N2 (> 32K tokens, ~100KB)** :
   - **a.** Découper par fichier (`git diff <range> -- <file>` boucle), N2 par-fichier
   - **b.** Basculer sur `mistral-medium-3-5` (128K ctx)
   - **c.** Marquer N2 `skipped: oversize`, laisser N0+N1 prendre le relais

5. **Sandbox-friendly N1 codex** : codex CLI sandboxé via bwrap échoue sur `git diff` local non-pushé. Workaround : pousser sur `origin` avant N1. Re-tester à chaque bump `codex --version`.

6. **PR-first absolu pour features non triviales**. Interdire commit direct sur `main` si :
   - 3+ commits dans la même unité de travail
   - Bump semver minor/major
   - Modification de `src/oauth-provider.ts`, `src/security/*`, `src/auth.ts`, `src/server.ts`
   - Migration schéma SQLite (futur)

7. **N3 peer (outlook-mcp-hardened spécifique)** : pour tout changement touchant un pattern partagé avec mcp-vault (OAuth, rate-limit, audit, trust-proxy), notifier mcp-vault via `peer-ask` avant merge. Réponses < 300s ou bascule en review async.

### Schema Finding V3 (anti-hallucination, inchangé mcp-vault)

Tout finding 🔴 BLOCKER ou 🟠 IMPORTANT DOIT contenir :

```finding
id: <B1, B2, I1, ...>
severity: BLOCKER | IMPORTANT | OBSERVATION
file: <path:line>
claim: <one-line bug description>
reasoning: |
  Step-by-step reasoning leading to the bug claim.
  MUST consider at least one alternative explanation that would mean it's NOT a bug,
  and explain why that explanation is rejected. (Anti-bias: forces consideration of counter-evidence)
evidence:
  tool: runtime | doc | rfc | threat-model
  repro_runtime: |
    # Exact shell commands to reproduce the bug, NO manual setup required.
    # MUST exit 0 if the bug is present, exit 1 if not. ≤30 lines.
    npm test -- --run path/to/test.ts -t "specific test name"
fix: <concrete actionable correction>
confidence: 0-100
```

**Sans `evidence.repro_runtime` exécutable**, le finding est auto-downgrade à `OBSERVATION`. C'est la garde anti-faux-positifs (51% FP reduction documenté par Cubic, 79-83% kill rate par Refute-or-Promote arXiv 2604.19049).

### Cas limite documenté

Un repro test peut être structurellement valide mais mesurer mal le bug — ex : comparer la syntaxe à d'autres parties du codebase plutôt que reproduire l'effet runtime. C'est un faux positif que la validation V3 attrape à tort. Phase N3 Executor (review humaine du repro) chasse ces cas.

## Outils et commandes

### Lancer une cross-review

```bash
# Skill PF cross-review (installé)
/pf-cross-review HEAD~3..HEAD

# Variantes
/pf-cross-review --n0-only HEAD~3..HEAD     # éco budget
/pf-cross-review --no-n2 HEAD~3..HEAD       # ixtriasrv indisponible
/pf-cross-review HEAD~3..HEAD --label oauth # tag le rapport
```

Sortie : `docs/plans/YYYY-MM-DD-cross-review-<label>.md` versionné.

### Peer review mcp-vault

```bash
~/Projets/agent-hub/scripts/peer-ask.sh \
  --from mcp-outlook \
  --to mcp-vault \
  --topic <slug> \
  --timeout 300 \
  --content-file <path>
```

Réponse format JSON structuré (cf. `peer-ask.sh --help`).

### Pre-commit hook (T11)

Configuré via `.husky/pre-commit` :
- `npm run lint --silent`
- `npm run typecheck --silent`
- N2 ixtriasrv warn-only via `tools/n2-pre-commit.sh` (créé en T11)

## Conséquences

### Positives
- Catch cross-school des angles morts Anthropic (cf. les 13 findings codex sur les SPECS v1)
- Discipline review documentée et reproductible
- Alignement méthodologique mcp-vault, facilite peer review croisée

### Négatives
- Budget LLM ~$5/jour à monitorer
- Friction PR mandatoire ralentit les patches triviaux (mitigé par règle méta 2)
- Dépendance ixtriasrv pour N2 (mitigation : graceful degradation déjà implémentée dans `/pf-cross-review`)

## Références

- mcp-vault ADR-0001 v3.3 — grille originale Python
- Cubic — 51% FP reduction par filtering agent + reasoning logs
- Refute-or-Promote (arXiv 2604.19049) — 79-83% kill rate empirical execution
- Beyond Consensus / NUS — LLM-judges convergent par politesse, mandat adversarial requis
- Skill `/pf-cross-review` v3.3 — `~/Projets/Project-Forge/extensions/pf-cross-review/commands/cross-review.md`
