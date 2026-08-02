# ADR-0004 — Discipline de maintenance post-release (MVP)

- **Date** : 2026-08-02
- **Statut** : Proposé
- **Décideurs** : Jimmy Blanquet (solo mainteneur)
- **Contexte** : audit stratégique `docs/plans/2026-08-02-audit-maintenance-strategique.md`
- **Version** : v2 — révisée post contradictoire GPT-5.5 (réduit de 4 règles à 3 gates non-négociables)

## Contexte

Après release v0.3.0 (2026-06-02), 6 semaines d'inactivité ont laissé s'accumuler 37 tickets sans qu'aucun signal automatique n'alerte le mainteneur.

Une analyse RCA initiale proposait 4 patterns systémiques (A "silence = succès", B "CI green-washing", C "test miroir de l'impl", D "doc = intention"). Un review contradictoire cross-vendor (GPT-5.5 via codex) a rejeté cette taxonomie comme "trop confortable" et a fait 3 corrections structurelles adoptées ici :

1. **Le refresh token Azure en clair (SEC-01) est un P0 isolé**, pas un exemple de pattern. Il domine le rapport et sort du périmètre de cet ADR (voir ticket SEC-01).
2. **Les 4 patterns ne sont pas des root causes distinctes** — c'est un même système défaillant : **claims non contrôlés + gates non bloquantes + zéro test comportemental sur les flux critiques**. Un 5e pattern manqué s'appelle **"secrets/runtime blind spot"** : les contrôles vérifient la présence de code/doc, jamais l'effet réel en exécution.
3. **Un ADR de 4 règles + rituel weekly + PR template lourd + AST grep + runbook + SBOM + templates ne tient pas 6 mois chez un solo mainteneur.** Le contradictoire propose 3 gates non-négociables + Dependabot auto-PR SLA — le reste est de la décoration qui se délite.

Cet ADR adopte l'approche minimale.

## Décision

**3 gates non-négociables sur `main`** (Règles 1-3) + **1 SLA Dependabot** (Règle 4). Rien d'autre. Tout ce qui vient en plus (rituel weekly, contract-first doc, runbook, PR template) est du bonus optionnel qui peut se déliter sans invalider ces 4 gates.

### Règle 1 — Scanner dépendances bloquant à seuil explicite

- `osv-scanner` (et tout autre scanner deps futur) **DOIT** utiliser `--experimental-fail-severity=high` (ou équivalent) explicite dans `security.yml`.
- `npm audit --audit-level=moderate` **DOIT** être bloquant sur prod deps dans `ci.yml`.
- Pas de mode "warn only" pour les dep vulns HIGH/CRITICAL.

**Raison** : sans ça, on tombe dans le pattern "CI green-washing" observé — les 3 derniers commits main (`b47ea6a`, `abb6d96`, `2dee1d1`) sont des fixes qui retirent des flags pour rendre le workflow vert.

### Règle 2 — `--max-warnings 0` en ESLint

- `npm run lint` **DOIT** utiliser `--max-warnings 0`.
- Chaque `eslint-disable` **DOIT** être inline avec `// justif: <raison>` explicite.
- 121 warnings tolérés collectivement = crédibilité "security-hardened" affaiblie (STRAT-01 finding).

**Raison** : sans ça, on ne distingue pas "faux positif audité" de "vraie dette qu'on ignore". Un auditeur externe (Cure53, blog OSS security) le voit en 5 secondes.

### Règle 3 — Tests comportementaux, pas de grep sur source

- Un test qui contient `SOURCE_CODE.toContain('...')` ou pattern similaire (`grep AST`, regex sur `fs.readFileSync(path)`) **N'EST PAS ACCEPTÉ** en review.
- Chaque BLOCKER identifié en cross-review **DOIT** avoir un test d'intégration comportemental (spawn le serveur / mock req/res / assert effet observable) — pas un grep sur `SERVER_TS`.
- Les tests `src/oauth/__tests__/blockers-N4.test.ts` (grep sur `server.ts`) sont **explicitement classés dette** à refactorer en test HTTP (TEST-01).

**Raison** : sans ça, les protections des BLOCKERS N4 peuvent régresser silencieusement — un refactor qui casse le comportement mais garde la string `"PKCE mandatory"` passe la CI (STRAT-04 Pattern C, confirmé par contradictoire).

### Règle 4 — SLA Dependabot maximum 7 jours

- Toute PR Dependabot patch/minor sur prod deps **DOIT** être mergée sous 7 jours (auto-merge si CI green).
- Toute alerte Dependabot HIGH prod deps **DOIT** être triée (mergée OU justifiée par un ticket) sous 7 jours.
- Notification GitHub Actions failure sur main **DOIT** être activée pour le mainteneur.

**Raison** : sans ça, on retombe dans les 6 semaines de silence observées. Le contradictoire a mesuré : 25 alertes Dependabot ignorées pendant 6 semaines pendant que tous les pairs auto-mergent.

## Ce qui est explicitement HORS scope de cet ADR

Documenté séparément dans `TICKETS.md` (Lots 2-5), mais **n'invalide pas ces 4 gates s'il n'est pas fait** :

- Weekly maintenance ritual formalisé (calendrier partagé)
- OpenSSF Scorecard workflow
- StepSecurity harden-runner
- PR template long avec checkboxes
- `docs/AUDIT_EVENTS.md` avec test AST-grep de contract-first
- Incident response runbook complet
- SBOM CycloneDX + npm provenance (couvert par SUP-01)
- Threat model rejoué (couvert par GOV-02)

Tout ce qui n'est pas dans les 4 gates est **du bonus qui peut se déliter**. Les 4 gates sont **le contrat minimum de crédibilité "hardened"**.

## Anti-patterns explicitement interdits

- Un commit `fix(ci): ...` qui **retire** un flag de gate au lieu de fixer la cause racine
- Un test qui grepe le source-code
- Une phrase README qui promet une observation runtime sans test correspondant
- Un ADR qui modifie l'architecture sans clause `TM: unchanged/to-update/superseded`
- Une claim "compliance X" sans doc `docs/COMPLIANCE-X.md` (GOV-01 nFADP est cette dette)

## Conséquences

### Positives

- Le CI redevient une **porte**, pas une **vitrine**
- Les BLOCKERS ne peuvent plus régresser silencieusement
- Le backlog Dependabot ne peut plus dépasser 7 jours
- La crédibilité "security-hardened" reste défendable face à un auditeur externe

### Négatives

- Toute PR future doit passer les 4 gates → friction supplémentaire
- Effort setup initial : ~2h (activer notifications GitHub + configurer les 3 gates CI)
- Coût récurrent : 5-10 min par PR Dependabot

## Suivi (mesure d'efficacité)

Revoir dans 8 semaines (2026-09-27) :

- **Métriques cibles** :
  - Nb Dependabot alerts ouvertes > 7 jours : cible < 3 (baseline actuelle 25)
  - Nb warnings ESLint sans justif inline : cible 0 (baseline 121)
  - Nb tests `SOURCE.toContain(...)` restants dans src/**/__tests__ : cible 0 (baseline 3)
  - Nb CI runs cron `failure` sans triage sous 7 jours : cible 0 (baseline 5/5)

- **Décision post-audit** :
  - Si les 4 gates ont tenu → ADR-0004 statut "Accepté"
  - Si régression sur ≥ 2 gates → RCA + révision de l'ADR ou renforcement (auto-tooling)

## Références

- Audit source : `docs/plans/2026-08-02-audit-maintenance-strategique.md`
- Contradictoire cross-vendor : agent `reviewer-contradictoire` (GPT-5.5 via codex), 2026-08-02
- Tickets d'implémentation : `TICKETS.md` Lot 2
- ADR précédents : 0001 (cross-LLM review grid), 0002 (superseded), 0003 (Niveau B)
