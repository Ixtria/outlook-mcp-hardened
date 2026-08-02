# Plan d'exécution — remédiation post-audit stratégique 2026-08-02

> **Statut** : draft — en attente contradictoire codex + validation Jimmy.
> **Contexte** : 30 tickets pending après commit `55f9e2d` (CI + Security verts). Audit source `docs/plans/2026-08-02-audit-maintenance-strategique.md`. Discipline `docs/adr/0004-discipline-de-maintenance.md`.

## Principe directeur (rappel ADR-0004)

Toute modification de code ou de doc **DOIT** respecter les 4 gates :

1. Scanner deps bloquant à seuil explicite (osv-scanner.toml, npm audit)
2. `--max-warnings 0` sur ESLint, chaque disable inline avec `// justif:`
3. Tests comportementaux, pas de grep sur source
4. SLA Dependabot 7 jours (auto-merge patch/minor si CI verte)

Chaque ticket termine avec :
- Un commit atomique
- Un test comportemental (Règle 3)
- Une mise à jour doc/CHANGELOG si applicable
- Push + CI verte avant de passer au ticket suivant du même lot

---

## Phase A — Fondations tests (SÉQUENTIEL, ~1-2 j)

Bloque tout le reste. Impossible de fiabiliser les fixes CI sans un vrai test comportemental (Pattern B "CI green-washing" du STRAT-04, prouvé en direct par mon fix bâclé `--experimental-fail-severity=high`).

| # | Ticket | Effort | Sortie | Bloque |
|---|---|---|---|---|
| A.1 | **MAINT-TEST-BEHAV** (issu de Lot 2 ADR-0004 Règle 3) — 1 vrai test d'intégration comportemental sur PKCE required + POST /authorize 405 + redactor. **Petit périmètre**, garantit qu'un fix ne casse pas le comportement | 4-6 h | `test/lot1-behavior.test.ts` avec supertest+http.createServer minimal | A.2 |
| A.2 | **TEST-01** E2E HTTP full-stack supertest sur les 8 routes OAuth. Refactor `blockers-N4.test.ts` (grep source → vrai HTTP). server.ts 0% → cible 80% | 2-3 j | `test/e2e/oauth-routes.test.ts` (supertest sur app.listen(0)) + refactor blockers-N4 | Phase B, C, D |

**Choix technique** : `supertest` déjà mainstream, léger, joue bien avec vitest. Alternative `undici mock` rejetée (moins ergonomique pour testing complet).

**Gate de sortie Phase A** : coverage `src/server.ts` ≥ 60% (cible 80% mais 60% acceptable en fondation).

---

## Phase B — Élargissement (PARALLÈLE post-A, ~2-3 j)

7 tickets parallélisables. Chaque sous-agent travaille sur un fichier disjoint. Les dépendances de fichier sont explicites ci-dessous.

| # | Ticket | Fichiers owned | Effort |
|---|---|---|---|
| B.1 | **OBS-02** auditLog OAuth events + `docs/AUDIT_EVENTS.md` source de vérité + test contract-first (grep AST sur call-sites `auditLog(...)`) | `src/security/audit-logger.ts`, `src/server.ts` (add sites), `docs/AUDIT_EVENTS.md` (NEW), `test/audit-events-contract.test.ts` (NEW) | 1-2 j |
| B.2 | **TEST-02** PKCE flood test réel (10 001 requêtes concurrentes) | `test/pkce-flood.test.ts` (NEW) | 1 j |
| B.3 | **TEST-03** contract MCP protocol (JSON Schema validation `list_tools()`) | `test/mcp-contract.test.ts` (NEW) | ½ j |
| B.4 | **TEST-06** contract tests labelled RFC (7591 / 6749 §5.2 / 9700 §2.1.1 / 8707) | `test/rfc-conformance/*.test.ts` (NEW dir) | 1 j |
| B.5 | **OBS-04** request_id cross-events via `crypto.randomUUID()` | `src/request-context.ts`, `src/security/audit-logger.ts` (add field) | 2 h |
| B.6 | **OBS-03 + OBS-07** redactor étendu récursivement sur `info` entier (incl. splat `err`) + test pipeline end-to-end | `src/logger.ts`, `test/logger-pii-pipeline.test.ts` (NEW) | 3 h |
| B.7 | **OBS-05** winston printf → JSON + timezone + statiques | `src/logger.ts` (merge avec B.6) | 1 h |

**Conflit fichier** : B.5 + B.1 touchent `audit-logger.ts` → séquentiel (B.5 d'abord puis B.1 rebase).
**Fusion** : B.6 + B.7 sur même fichier `logger.ts` → 1 agent unique.

**Gate de sortie Phase B** : coverage `src/security/**` maintenu ≥ 92%, coverage `src/oauth/**` maintenu 100%, aucune régression tests A.

---

## Phase C — Automation + governance (PARALLÈLE massif, ~1-2 j)

**Indépendant de A et B**. Peut lancer en parallèle dès le début. 11 tickets, tous sur fichiers disjoints (workflows / docs / configs).

### C.a — Automation CI (workflows uniquement)

| # | Ticket | Fichier owned | Effort |
|---|---|---|---|
| C.1 | **AUTO-01** auto-merge Dependabot patch/minor | `.github/workflows/dependabot-automerge.yml` (NEW) | 30 min |
| C.2 | **AUTO-02** OpenSSF Scorecard | `.github/workflows/scorecard.yml` (NEW) | 30 min |
| C.3 | **AUTO-03** StepSecurity harden-runner sur les 3 workflows | `.github/workflows/{ci,security,zap}.yml` (edit léger) | 30 min |
| C.4 | **AUTO-04** Node 22/24 bump + engines `>=22` | `package.json`, `.github/workflows/ci.yml` | 30 min |
| C.5 | **SEC-05** pin actions par SHA 40-char (via `pinact` ou manuel) | `.github/workflows/*.yml` | 45 min |

**Conflit fichier** : C.3 + C.5 + C.4 tous sur workflows → séquentiel (C.5 dernier pour pin les SHA des ajouts précédents).

### C.b — Governance docs (aucun conflit)

| # | Ticket | Fichier owned | Effort |
|---|---|---|---|
| C.6 | **GOV-02** hook ADR ↔ TM check (rejouer TM post ADR-0003) | `docs/adr/TEMPLATE.md` (edit) + `docs/threat-model/2026-08-02-oauth-proxy-niveau-b.md` (NEW) | ½ j |
| C.7 | **GOV-03** `docs/INCIDENT-RESPONSE.md` playbook par type | `docs/INCIDENT-RESPONSE.md` (NEW) | 1 j |
| C.8 | **GOV-04** trio baseline OSS : issue+PR templates + CODE_OF_CONDUCT + security.txt | `.github/ISSUE_TEMPLATE/*.yml`, `.github/PULL_REQUEST_TEMPLATE.md`, `CODE_OF_CONDUCT.md`, `deploy/nginx-outlook-mcp.conf` (add security.txt route) | 2 h |
| C.9 | **GOV-05** `docs/RELEASING.md` + deprecation policy + support matrix | `docs/RELEASING.md` (NEW) | 3 h |
| C.10 | **SUP-01** `.github/workflows/publish.yml` avec SBOM CycloneDX + npm provenance | `.github/workflows/publish.yml` (NEW) | 2 h |
| C.11 | **GOV-01** décision binaire : soit écrire `docs/COMPLIANCE-nFADP.md`, soit acter le retrait définitif dans README+CLAUDE.md (déjà retiré au commit `e4f68bd`, à confirmer) | `docs/COMPLIANCE-nFADP.md` (NEW) OU décision | 1 j OU 5 min |

### C.c — Lint discipline (impact large)

| # | Ticket | Fichier owned | Effort |
|---|---|---|---|
| C.12 | **MAINT-LINT-0** `npm run lint --max-warnings 0` gate + tagger inline les 121 warnings (ou fix) — ADR-0004 Règle 2 | Tout `src/**/*.ts`, mais règle est "inline justif OU fix" par occurrence | 3-4 h |

**Gate de sortie Phase C** : tous les workflows passent au run suivant, aucune régression.

---

## Phase D — Nice-to-have (PARALLÈLE, ~1-2 j)

Non bloquant pour publication. Peut être fait plus tard si contrainte temps.

| # | Ticket | Fichier | Effort |
|---|---|---|---|
| D.1 | **TEST-04** chaos audit-salt / secrets (fs hostile, TOCTOU, perms) | `test/chaos-audit-salt.test.ts` (NEW) | 1 j |
| D.2 | **OBS-06** health endpoint enrichi | `src/server.ts` (edit léger) | 2 h |
| D.3 | **OBS-08** health `/live` ≠ `/ready` différenciés | `src/server.ts` (edit léger) | 1 h |

---

## Stratégie de parallélisation

### Sans opt-in Workflow explicite (défaut)

**Agent tool en parallèle** (moteur `general-purpose` ou `coder-sonnet` selon nature) :

- Phase A : 1 agent séquentiel (A.1 → A.2)
- Phase B : 6 agents parallèles (B.1..B.7 avec fusion B.6+B.7)
- Phase C : 12 agents parallèles (limite : conflits fichier C.3+C.4+C.5 → séquentiel dans même agent)
- Phase D : 3 agents parallèles

Total : ~15-20 sous-agents sur la durée, jamais plus de 6-8 concurrents.

**Discipline sous-agent** :
- Owner unique par fichier (règle CLAUDE.md)
- Brief self-contained (base SHA, fichiers owned, test rouge attendu)
- Aucun spawn en cascade
- Read-only tools sauf le sous-agent qui écrit le fichier
- Retour attendu : commit SHA + test vert + éventuel finding secondaire à ticketiser

### Avec opt-in Workflow (Jimmy dit "ultracode" ou "utilise un workflow")

**Fanout Workflow structuré** :

- Workflow 1 "phase-a-fondations-tests" : pipeline séquentiel A.1 → A.2 avec vérification test vert avant next
- Workflow 2 "phase-b-elargissement" (post-A) : parallel sur 6 items avec judge panel sur les fichiers partagés
- Workflow 3 "phase-c-automation-gov" : parallel massif 12 items avec dépendances fichier explicites
- Workflow 4 "phase-d-nice" : parallel simple 3 items

Chaque workflow rend un rapport de synthèse structuré + tickets nouveaux si findings découverts.

**Avantages Workflow vs Agent tool** :
- Pipeline avec judge/verify entre stages
- Résilience aux échecs partiels (retry, budget)
- Cache de résultats (resume)
- Traçabilité complète JSONL

**Coût** : ~10-100k tokens output par workflow selon la profondeur. Compte tenu du budget non défini côté Jimmy, la version Agent tool est plus économique.

---

## Contradictoire attendu

Points à faire challenger par codex GPT-5.5 avant de lancer :

1. **La phase A est-elle vraiment un bloqueur strict pour tout le reste** ? Ou peut-on paralléliser certains items de Phase B et C sans TEST-01 ?
2. **Les fusions de fichiers proposées** (B.6+B.7, C.3+C.4+C.5) sont-elles bien optimales, ou existe-t-il un ordre différent qui permettrait plus de parallélisation ?
3. **GOV-01 nFADP** : la décision "écrire le doc OU acter le retrait" est-elle bien binaire ? Un consultant DPO externe serait-il indispensable pour valider un RoPA / DPIA / DFD auto-écrit ?
4. **MAINT-LINT-0** : 3-4 h pour tagger 121 warnings est-il réaliste, ou faut-il découper en batches par module (5 batches × 45 min) ?
5. **SUP-01 npm provenance** : nécessite OIDC trusted publishing configuré npm → GitHub. Est-ce que ce prérequis est bloquant pour ce ticket (auquel cas c'est un pré-requis Jimmy) ?
6. **Un cinquième pattern** systémique manqué qu'on aurait dû capturer dans l'ADR-0004 et qui rend ce plan bancal ? (le contradictoire précédent avait justement pointé "secrets/runtime blind spot" — est-il vraiment neutralisé par ce plan ?)
7. **Ordonnancement TEST-06 RFC conformance** avant OBS-02 auditLog OAuth ? Ça permettrait de vérifier que les events audités sont RFC-conformes.

---

## Validation Jimmy — 3 questions binaires

Avant lancement autonome :

**Q1 — Mode de parallélisation** :
- (a) **Agent tool parallèles** (léger, moins de tokens, moins de garanties structurelles)
- (b) **Workflow explicite** (plus lourd, pipeline avec judge/verify, cache resume) — nécessite "ultracode" ou "utilise un workflow"

**Q2 — GOV-01 nFADP** :
- (a) **Écrire `docs/COMPLIANCE-nFADP.md`** (RoPA + DPIA simplifiée + DFD auto-générés à ma main, ~1 j) et rétablir le claim
- (b) **Acter le retrait définitif** dans README+CLAUDE.md (déjà retiré au commit `e4f68bd`, à formaliser) et supprimer GOV-01
- (c) **Déférer** à quand tu auras du temps pour valider avec un DPO externe

**Q3 — SUP-01 npm provenance** :
- (a) Je committe le workflow `.github/workflows/publish.yml` **sans l'activer** (nécessite OIDC configuré npm côté Jimmy) — safe, reste dormant
- (b) Skip SUP-01 tant que l'OIDC npm n'est pas configuré (SBOM peut être livré séparément sans provenance)

## Prochaines étapes

1. Contradictoire codex sur ce plan (lancé en parallèle de sa livraison)
2. Attendre le retour + les 3 réponses de Jimmy
3. Lancer Phase A dès validation
4. Fanout Phase B + C dès sortie Phase A
5. Phase D en fin ou différée

---

## Annexe — Contradictoire GPT-5.5 (2026-08-02) → révisions v2

Contradictoire cross-vendor via `reviewer-contradictoire` (Codex GPT-5.5). Verdict : **GO avec conditions bloquantes** — pas GO en l'état. 4 démolitions structurelles + 6 points corrigés + 1 nouveau ticket exigé.

### Failles cassées et corrections adoptées

**F1. Contradiction A/C interne** — le plan v1 disait "A bloque tout" puis "C peut partir en parallèle dès le début". Contradiction assumée. **Correction v2** : A n'est PAS un bloqueur global. Seule Phase B (extensions de l'harness A) attend A. Phase C peut partir immédiatement en parallèle de A.

**F2. B.1 (OBS-02) "test contract-first grep AST" viole Règle 3 ADR-0004 déguisée** — un grep AST reste une assertion structurelle, pas un test comportemental. Le plan v1 violait littéralement la Règle qu'il prétendait appliquer partout. **Correction v2** : B.1 remplacé par un vrai test HTTP qui déclenche `/authorize` avec cas rejet + vérifie l'appel réel de `auditLog(...)` via spy sur le module + assertions sur les champs émis (type, outcome, request_id, redaction). Dépend de A pour le harness.

**F3. 5e pattern "secrets/runtime blind spot" pas neutralisé** — SEC-01 P0 fixé + OBS-02 planifié couvrent le leak logging, mais pas : validation runtime au boot des permissions fichiers, rotation/reload policy quand salt change, redaction dans errors/métriques/stack traces, tests startup hostile (fs missing, config, keychain, disk full). **Correction v2** : nouveau ticket **RUNTIME-SEC-01 P1** créé et placé en Phase B bloquant.

**F4. CI verte à chaque ticket (30x) ingérable en solo** — file d'attente, conflits rebase, discipline qui casse. **Correction v2** : batching par lot cohérent :
- Lot `test-foundation` (Phase A : MAINT-TEST-BEHAV)
- Lot `obs-runtime` (Phase B : OBS-02 + OBS-03/07 + OBS-04 + OBS-05 + RUNTIME-SEC-01)
- Lot `test-behavior` (Phase B : TEST-01 + TEST-02 + TEST-03 + TEST-06)
- Lot `ci-automation` (Phase C.a : AUTO-01 + AUTO-02 + AUTO-03 + AUTO-04 + SEC-05)
- Lot `governance` (Phase C.b : GOV-02 + GOV-03 + GOV-04 + GOV-05 + GOV-01 + SUP-01-SBOM)
- Lot `lint-cleanup` (Phase C.c : MAINT-LINT-0 batché par règle)
- Lot `nice` (Phase D)

CI complète en fin de lot, pas à chaque ticket.

### Corrections mineures adoptées

**F5. MAINT-LINT-0 3-4h "fantaisiste"** — 121 warnings peuvent cacher dette typage/async/sécu. **Correction v2** : batching par règle (5 batches × 45 min-1h30 selon règle : `no-explicit-any` × 57, `detect-object-injection` × 31, `detect-non-literal-fs-filename` × 26, `detect-non-literal-regexp` × 2, autres × 5). Chaque batch = 1 commit dans le lot `lint-cleanup`. Total révisé : **6-8 h répartis**, pas 3-4h.

**F6. SUP-01 SBOM+provenance indivisible artificiel** — le SBOM ne dépend pas d'OIDC npm. **Correction v2** : découpé en :
- **SUP-01-SBOM** : `.github/workflows/publish.yml` avec `anchore/sbom-action` uniquement, dormant (ne push pas), livrable immédiatement — Phase C.b
- **SUP-01-PROV** : ajout `npm publish --provenance` post OIDC configuré Jimmy — reporté v0.4

**F7. C.3+C.4+C.5 séquentiel sous-estime le risque** — Node bump + harden-runner + pin SHA en un seul agent peut casser permissions/caches/ZAP. **Correction v2** : ordre imposé dans le lot `ci-automation` :
1. AUTO-04 Node 22/24 en premier (feature change isolé, verify CI verte)
2. AUTO-01/02/03 workflows nouveaux (feature adds)
3. SEC-05 pin SHA en **DERNIER** (freeze après validation des precedents)

**F8. AUTO-01 auto-merge minor trop permissif** pour OAuth/sécu — minor peut casser comportement runtime. **Correction v2** : auto-merge **patch seulement**. Minor et major restent en review manuel dans le weekly ritual.

**F9. GOV-01 3e voie confirmée** — "posture déclarative self-attested, non-audited" (option c de la Q2 initiale). **Correction v2** : nouveau template `docs/COMPLIANCE-nFADP.md` clairement estampillé "posture déclarative auto-attestée, non-auditée, sans engagement légal", RoPA structuré, DPIA simplifiée, DFD. Réhabilite le claim topic GitHub mais avec la mention "self-attested" dans le README.

### Verdict mode de parallélisation (Q1 tranchée)

Contradictoire GPT-5.5 : **Workflow structuré, pas Agent tool**. Pour ~1 semaine sans surveillance continue, "judge/verify/retry/cache valent plus que l'économie de tokens." → nécessite opt-in Jimmy "**ultracode**" ou "**utilise un workflow**".

Si Jimmy refuse le Workflow → fallback Agent tool avec discipline batching serrée (7 lots au lieu de 30 commits).

### Prédiction point de rupture

Contradictoire GPT-5.5 : la discipline cassera sur **C.12 (lint) ou C.3-C.5 (workflows)** "au moment où la pression de faire passer CI poussera à des suppressions lint ou pins validés trop vite." → mesure défensive v2 : chaque suppression lint doit passer par 2 étapes (proposition dans PR + review humaine Jimmy) au lieu d'être auto-appliquée par un sous-agent.

### Ordonnancement révisé v2

```
Semaine 1 (parallèle) :
  Piste 1 [séquentiel] : A (MAINT-TEST-BEHAV) → B lot obs-runtime → B lot test-behavior
  Piste 2 [parallèle Piste 1] : C lot ci-automation (AUTO-04 → AUTO-01/02/03 → SEC-05)
  Piste 3 [parallèle Pistes 1+2] : C lot governance (GOV-02 + GOV-03 + GOV-04 + GOV-05 + SUP-01-SBOM + GOV-01 self-attested)

Semaine 2 (série) :
  Lot lint-cleanup (batches par règle)
  Lot nice (Phase D)
  Contradictoire final GPT-5.5 sur le résultat + tag v0.4.0
```

Total estimé v2 : **6-9 j calendaires** répartis, avec 3 pistes parallèles en semaine 1.

