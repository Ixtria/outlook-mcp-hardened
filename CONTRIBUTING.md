# Contributing to outlook-mcp-hardened

Merci de l'intérêt. Ce projet est un fork sécurité de [`ms-365-mcp-server`](https://github.com/softeria/ms-365-mcp-server) maintenu par Ixtria. Toute contribution doit respecter la posture sécurité documentée.

## Avant de contribuer

1. Lis [`CLAUDE.md`](CLAUDE.md) — principes non-négociables (égress allowlist, zéro télémétrie, audit, anti-injection, tokens locaux).
2. Lis [`SECURITY.md`](SECURITY.md) — surface couverte, threat model.
3. Lis [`docs/adr/0001-cross-llm-review-grid.md`](docs/adr/0001-cross-llm-review-grid.md) — méthode review obligatoire.
4. Si tu touches la surface OAuth/auth/sécu : lis [`docs/adr/0002-oauth-trust-policy-and-as-architecture.md`](docs/adr/0002-oauth-trust-policy-and-as-architecture.md) + [`SPECS-OAUTH-MCP.md`](SPECS-OAUTH-MCP.md).

## Quality gate

Toutes les contributions doivent passer :

```bash
npm run verify   # generate + lint + typecheck + build + test:coverage
```

Coverage cible ≥80% sur `src/security/**`, `src/oauth/**`, `src/request-context.ts`. Le seuil est strict, le build CI échoue sinon.

### Activer le pre-commit hook (recommandé)

```bash
git config core.hooksPath .githooks
```

Le hook lance lint + typecheck sur tout commit touchant du TS, et la suite de tests si tu touches `src/security/` ou `src/oauth/`. Désactivable ponctuellement avec `SKIP_PRECOMMIT=1 git commit`.

## Workflow

1. **Spec d'abord pour features non triviales** — pour toute nouveauté >3 commits ou touchant `src/oauth/`, `src/security/`, `src/auth.ts`, écris d'abord un document dans `docs/specs/` ou propose une ADR. Pas de code avant alignement sur la spec.

2. **TDD obligatoire sur modules sensibles** — test rouge AVANT le code, test vert APRÈS. Modules concernés : `src/security/**`, `src/oauth/**`, `src/request-context.ts`, `src/auth.ts`.

3. **Commits atomiques + conventional commits** — `type(scope): description [TKT-ID]`. Un commit = un concern. `feat`/`fix`/`docs`/`refactor`/`test`/`chore`/`security`.

4. **Cross-review pre-merge sur surface sensible** — ADR-0001 §grille. N0 (Claude sub-agent) minimum, N1 (codex) si BLOCKER potentiel cross-school. N3 (mcp-vault peer) si pattern partagé OAuth/rate-limit/audit/trust-proxy.

5. **PR-first absolu** pour features non triviales (cf. ADR-0001 §règle méta 6) — pas de commit direct sur `main`.

## Signaler une vulnérabilité

Voir [`SECURITY.md`](SECURITY.md). Channel privé recommandé : GitHub PVR ou `security@ixtria.ch`. Jamais d'issue publique pour vulnérabilité.

## Style

- TypeScript strict (`"strict": true`, `"noUncheckedIndexedAccess": true`).
- ESLint + `@typescript-eslint` rules — pas d'override sans justification commentée.
- Pas de commentaire qui répète le code. Commentaires uniquement pour le WHY non-évident.
- Pas d'emoji dans le code (sauf demande explicite user).

## Outils de review

```bash
# Cross-review N0+N1+N2 sur range
/pf-cross-review HEAD~3..HEAD

# Peer review mcp-vault (synchrone, timeout 300s)
~/Projets/agent-hub/scripts/peer-ask.sh \
  --from mcp-outlook --to mcp-vault \
  --topic <slug> --timeout 300 \
  --content-file <file>
```
