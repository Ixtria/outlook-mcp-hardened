# Audit maintenance stratégique — 2026-08-02

> **Contexte** : reprise après 6 semaines de silence post-v0.3.0 (dernier commit humain `9f3d080` du 2026-06-02). L'audit est demandé par Jimmy comme point de reprise stratégique, pas comme fix ponctuel. **Aucune modification de code n'a été faite pendant l'audit** — seule production : ce document + tickets + ADR-0004.

## Méthode

4 investigations parallèles READ-ONLY dispatchées à des sous-agents, chacune avec un périmètre disjoint :

| Investigation | Périmètre |
|---|---|
| **MAINT-01** | Dérive dépendances + CI vitality + CodeQL alerts + Node deprecation |
| **MAINT-02** | Cartographie des 380 tests par dimension + gaps |
| **MAINT-03** | Audit-logger coverage vs threat model + PII redactor + format SIEM + rotation |
| **MAINT-04** | Automatisation maintenance long-terme (Scorecard, harden-runner, auto-merge…) |

Puis 4 investigations stratégiques (angle "hauteur") :

| Investigation | Périmètre |
|---|---|
| **STRAT-01** | Cohérence claim (docs) vs réalité (code + tickets) |
| **STRAT-02** | Benchmark industrie vs 6 MCP OAuth OSS "sérieux" |
| **STRAT-03** | Trous structurels absents (dimensions carrément manquantes) |
| **STRAT-04** | Root cause pattern des 24 tickets → 4 changements de process |

Puis 2 investigations d'approfondissement sur findings critiques :

| Investigation | Périmètre |
|---|---|
| **SEC-01/02 investigation** | 3 real CodeQL clear-text-logging + 2 regex-injection (faux positifs) |
| **SEC-03 investigation** | Security CI cron rouge 5/5 semaines — root cause |

Enfin : **contradictoire GPT-5.5 via codex** sur la synthèse — challenge sans complaisance.

---

## Résultat quantitatif

- **37 tickets ouverts** identifiés (SEC-01..05, TEST-01..06, AUTO-01..04, OBS-01..08, GOV-01..05, SUP-01)
- **25 alertes Dependabot** (7 HIGH, 11 MEDIUM, 7 LOW) — 0 il y a 6 semaines
- **47 alertes CodeQL open** dont **5 ERROR** (3 clear-text-logging + 2 regex-injection)
- **CI Security cron rouge 5/5 semaines** depuis 2026-06-29
- **8 PRs Dependabot en attente** (0 mergée depuis avril)

---

## Diagnostic structurel — 4 patterns systémiques (source : STRAT-04)

### Pattern A — "Silence = succès"

Cron sécurité rouge 5 semaines de suite, 25 Dependabot alerts ignorées, health endpoint muet, deprecation Node 20 non trackée. **Aucun canal push (email, PR-check bloquant, dashboard) qui interrompe le flux normal.** L'humain doit aller chercher l'info.

- Tickets couverts : SEC-03, SEC-04, AUTO-04, OBS-06
- Fix process : **weekly maintenance ritual** de 20 min (lundi matin) qui vide 3 files : cron sec, Dependabot, deprecations. + activer notifications GitHub `Failed workflows` sur main.
- Effort/impact : 30 min setup / élimine 4 tickets et prévient toute la classe "dérive silencieuse"

### Pattern B — "CI green-washing"

Les 3 derniers commits main sont des `fix(ci): ...` qui **retirent** des flags pour rendre le workflow vert (`--fail`, `--skip-git`, seuil `--fail-on` absent). `osv-scanner` sans `--fail-on`, 121 warnings ESLint tolérés, actions non SHA-pinned. **Le CI signale l'existence d'un scan, pas son verdict.**

- Tickets couverts : SEC-03, SEC-05, AUTO-01, AUTO-02, AUTO-03, TEST-05
- Fix process : **fail-closed policy** — tout scanner nouveau doit entrer avec seuil `--fail-on high`. Toute suppression `eslint-disable` requiert un `// justif: <raison>` sinon `--max-warnings 0`. Actions pinnées par SHA via Renovate/Dependabot digest updates.
- Effort/impact : 1h de config / élimine 6 tickets, aligne le CI sur "porte" plutôt que "vitrine"

### Pattern C — "Test miroir de l'impl"

Tests BLOCKERS N4 = assertions regex sur strings du source-code (`SERVER_TS.toContain('PKCE mandatory')`). PKCE flood testé par arithmétique. Contract MCP absent. **Le test dit "la fonction existe", pas "l'attaquant échoue".**

- Tickets couverts : TEST-01, TEST-02, TEST-03, TEST-04, OBS-02
- Fix process : **règle "no source-grep tests"** inscrite dans CLAUDE.md + PR template : `[ ] Chaque test appelle du code, pas un grep sur du source. [ ] Chaque BLOCKER a un test end-to-end qui joue l'attaque.` Refuser en review sinon.
- Effort/impact : discipline pure, 0h setup / restaure la valeur de la coverage

### Pattern D — "Doc = intention, code = réalité"

La doc/CHANGELOG/README annoncent une surface (redactor scrub complet, 6 sites `auditLog`, JSON logs, "0 vulns", "CI blocks phone-home") que l'implémentation ne réalise pas. **Aucun test ne compare doc↔code.** `docs/AUDIT_EVENTS.md` inexistant.

- Tickets couverts : OBS-02, OBS-05, OBS-07, SEC-01, STRAT-01 (11 claims dont 3 mensongères)
- Fix process : **contract-first pour tout ce qui est promis** — un fichier `docs/AUDIT_EVENTS.md` (source de vérité) + un test qui vérifie que chaque event listé est effectivement émis par grep AST sur les call-sites `auditLog(...)`. Idem pour la liste des champs redactés (fixture PII → assertion output).
- Effort/impact : 2h setup / élimine 4 tickets, transforme la doc en test exécutable

---

## Positionnement industrie (source : STRAT-02)

Panel comparé : Softeria/ms-365 (upstream), cloudflare/mcp-server-cloudflare, getsentry/sentry-mcp, github/github-mcp-server, jlowin/fastmcp, stripe/agent-toolkit.

### Où on est AU-DESSUS du médian industrie

- **Threat model STRIDE publié + 3 ADR** — *aucun* des 6 pairs ne fait ça
- **Stack SAST/DAST cumulée** : CodeQL + Semgrep 6 packs + OSV + TruffleHog + license + ZAP — aucun pair ne cumule autant
- **Cross-LLM review N0+N1+N2+N3** — méthodologie unique

### Où on est AU NIVEAU

- CI matrix Node 20/22, branch protection, PVR, CODEOWNERS, SECURITY.md

### Où on est EN-DESSOUS (vendor-backed)

- **Backlog Dependabot** — 25 alertes ouvertes vs auto-merge chez tous les pairs
- **Cadence release** — 2 mois sans commit vs semantic-release chez Softeria/Sentry/FastMCP
- **Signature artifacts** — GitHub officiel expose 9 binaires + `checksums.txt` (GoReleaser). Nous : rien
- **Community proof** — 0 stars, 1 contrib (normal pour projet fraîchement publié)

### Verdict

Défendable niveau **"OSS solo-mainteneur security-serious"**. Récit publiable **tient**, sous condition de purger Dependabot et rétablir un CHANGELOG actif. Sans ça, la page Security contredit la promesse "hardened" dès la première visite.

---

## Trous structurels non détectés (source : STRAT-03)

**Meta-diagnostic** : la méthode a couvert profondément 3 axes (crypto/OAuth, tests cross-review, deploy infra) et **oublié 2 axes structurels** : supply-chain moderne 2026 (SBOM/provenance/signing) et conformité juridique (nFADP/GDPR/RoPA/DPIA/DFD). Ces axes ne sortent pas du STRIDE ni des cross-LLM reviews car aucun agent ne les cherche par défaut.

Top 5 absences les plus embarrassantes vs le claim "PME suisse nFADP-compatible + hardened OSS" :

1. **Pas de doc nFADP / GDPR** — le repo se vend "nFADP-compatible" (topic GitHub, README, CLAUDE.md) sans une seule page RoPA/DPIA/DFD (**GOV-01**)
2. **Pas de SBOM ni npm provenance** — le workflow `publish.yml` est documenté mais pas committé (**SUP-01**)
3. **Threat model figé au 2026-05-10** — le pivot ADR-0003 n'a pas déclenché révision TM (**GOV-02**)
4. **Pas d'incident response runbook** (**GOV-03**)
5. **`security.txt` absent + pas d'issue/PR templates + pas de CODE_OF_CONDUCT** (**GOV-04**)

---

## Cohérence claim vs réalité (source : STRAT-01)

Sur 11 claims explicites du README/CHANGELOG/badges, **3 sont frontales mensongères** :

| Claim | Réalité | Preuve |
|---|---|---|
| Badge "npm audit — 0 vulnerabilities" | 23 vulns + 25 Dependabot alerts open | `npm audit` du jour |
| "audit trail JSON per Graph call" (laisse croire à audit OAuth aussi) | `auditLog()` appelé 1 site sur 6+ annoncés | `grep -rn auditLog src/` |
| "CI blocks new dependencies that phone home" | Aucun job CI n'inspecte les deps | `grep -l phone.home\|telemetry .github/workflows/*.yml` → vide |

**5 autres claims** sont partiels/trompeurs :
- "src/oauth/** 100% coverage" → cache que `server.ts` (995 LOC OAuth wiring) est à 0%
- "8 BLOCKERS + 16 IMPORTANT fixed, 380 tests passing" → VRAI mais les régressions N4 sont des `grep` sur strings du source
- "PII redactor scrubs Bearer + JWT + emails" → refresh tokens Azure opaques (`M.C_...`) ne matchent aucun pattern (3 CodeQL ERRORS confirment)
- "systemd score < 1.5" vs "≤ 2.5" — docs contradictoires entre `deploy/outlook-mcp.service:16` et `docs/HANDOFF_INFRA.md:157,328,414`
- "Property-based 200×24" → couvre uniquement `validateRedirectUri` / `intersectScopes` / `resolveClientIp` (modules purs 100% déjà couverts)

---

## Plan d'attaque proposé

### Lot 1 URGENT — débloque l'immédiat (~1 j)

Objectif : refermer les mensonges frontaux, purger le backlog, débloquer la CI.

- **SEC-03** ajouter `--experimental-fail-severity=high` à osv-scanner + merger Dependabot hono + fast-uri
- **SEC-01** fix graph-client.ts:183 (destructuring safeOpts) + auth.ts:312+426 (hashAccount)
- **SEC-02** suppress 2 regex-injection avec justif
- **OBS-01** rotation logs winston (maxsize + maxFiles)
- **STRAT-01 doc urgente** — retirer les 3 claims mensongères du README (badge "0 vulns", "CI blocks phone-home", "audit trail per call" → "per outbound Graph call")

### Lot 2 STRUCTUREL — fixe les patterns (~2-3 j)

Objectif : implémenter l'ADR-0004 discipline de maintenance.

- **ADR-0004** committé (doc uniquement)
- **AUTO-01** auto-merge Dependabot patch/minor (Pattern A)
- **AUTO-02** OpenSSF Scorecard (Pattern B)
- **AUTO-03** StepSecurity harden-runner (Pattern B + supply chain)
- **SEC-05** pin actions par SHA (Pattern B)
- **Weekly maintenance ritual setup** — calendrier partagé, checklist 3 items

### Lot 3 BLINDAGE — comble les trous OSS "sérieux" (~3-4 j)

Objectif : atteindre la baseline OpenSSF 2026 et refermer les trous nFADP.

- **GOV-01** docs/COMPLIANCE-nFADP.md (RoPA + DPIA simplifiée + DFD)
- **SUP-01** `.github/workflows/publish.yml` avec SBOM CycloneDX + npm provenance
- **GOV-03** docs/INCIDENT-RESPONSE.md
- **GOV-04** trio security.txt + issue/PR templates + CODE_OF_CONDUCT
- **GOV-05** RELEASING.md + deprecation/support/LTS policy
- **GOV-02** hook ADR ↔ TM check

### Lot 4 TESTS — restaure la valeur de la coverage (~3-5 j)

Objectif : les BLOCKERS ne peuvent plus régresser silencieusement.

- **TEST-01** E2E HTTP full-stack supertest (8 routes OAuth)
- **TEST-02** PKCE flood test réel
- **TEST-03** contract MCP protocol
- **TEST-06** contract tests RFC 7591/6749/9700/8707
- **OBS-02** auditLog() sur 6 sites OAuth manquants
- **OBS-04** request_id cross-events
- **OBS-03/05/07** redactor étendu meta + winston JSON + splat err

### Lot 5 NICE — hygiène et dette (~2-3 j)

- **TEST-04** chaos audit-salt / secrets
- **TEST-05** 121 warnings ESLint justifiés ligne par ligne
- **AUTO-04** bump Node 22/24
- **OBS-06** health enrichi + docs/AUDIT_EVENTS.md
- **OBS-08** health /ready ≠ /live

**Total estimé** : 11-16 j homme répartis en 5 lots gate-gate. Le Lot 1 est bloquant pour tout le reste.

---

## Suivi

- **ADR-0004** : capture les 4 patterns systémiques → règles de discipline
- **TICKETS.md** : rebâti avec 37 tickets structurés en Lots 1..5
- **CHANGELOG** : nouvelle section `[Unreleased] — maintenance 2026-08-02` documente la reprise
- **Ce document** : `docs/plans/2026-08-02-audit-maintenance-strategique.md` — référentiel de la reprise stratégique, versionné dans le repo (projet ouvert = on montre comment on travaille)

## Annexe — Reviewer contradictoire cross-vendor (GPT-5.5 via codex)

Un review adversarial cross-vendor (agent `reviewer-contradictoire`, moteur GPT-5.5 via `codex exec`) a été lancé sur ma synthèse. **Il a démoli 3 points structurels et j'adopte ses corrections.**

### Corrections adoptées

**1. Le refresh token Azure en clair est un P0 ISOLÉ, pas un exemple de pattern**

Ma synthèse plaçait SEC-01 comme "exemple parmi d'autres" du Pattern D. Contradictoire : c'est le **seul** finding avec impact credential exploitable réel. Il doit dominer le rapport, pas y être noyé. → refactor de `TICKETS.md` : SEC-01 devient **P0 isolé en tête**, hors des 5 lots.

**2. La taxonomie 4 patterns A/B/C/D est fausse**

Contradictoire : pas 4 root causes distinctes mais **1 système défaillant** (claims non contrôlés + gates non bloquantes + zéro test comportemental sur les flux critiques). Il ajoute un **5e pattern manqué : "secrets/runtime blind spot"** — les contrôles vérifient présence code/doc, jamais effet réel en exécution. → ADR-0004 réduit à **3 gates non-négociables** + 1 SLA Dependabot (au lieu de 4 patterns + rituel + PR template + contract-first + …).

**3. "Au-dessus du médian docs sécu" est indéfendable tel quel**

Contradictoire : biais de comparaison. Un auditeur réel regarde les **preuves opérationnelles** (secrets non loggués, CI fail-closed, tests d'intégration OAuth), pas la présence d'ADR ou de threat model. Positionnement corrigé : *"projet en remédiation sécurité, doc avancée mais contrôles encore non fiables"*. Le positionnement "OSS solo-mainteneur security-serious" ne redevient défendable **qu'après fix Lot 1 + P0**.

**4. ADR-0004 initial = théâtre méthodologique**

Contradictoire : un solo-mainteneur tient "2-3 lundis" avant que l'inertie revienne. MVP proposé et adopté :

- osv/audit bloquant à seuil explicite (Règle 1)
- `--max-warnings 0` (Règle 2)
- **un vrai test d'intégration comportemental** (pas un grep) sur PKCE/405/redaction (Règle 3)
- + Dependabot auto-PR SLA hebdo (Règle 4)

Tout le reste (rituel weekly formalisé, PR template lourd, AST grep, runbook, SBOM, templates) reste dans `TICKETS.md` comme **Lots 2-5 optionnels** qui n'invalident pas les 4 gates s'ils se délitent.

**5. Trous structurels mal hiérarchisés**

Contradictoire : SBOM/provenance (P1 supply chain) mélangé avec CODE_OF_CONDUCT (P3 governance communautaire) sous une même liste plate. → Lot 3 restructuré en 3 sous-catégories : Supply chain (P1), Compliance nFADP (bloquant si claim présent), Governance & release (P2), Community (P3).

**6. nFADP absent = faux claim frontal, pas un "trou"**

Contradictoire : la recommandation par défaut n'est PAS d'écrire `docs/COMPLIANCE-nFADP.md` mais de **retirer le claim** tant que le doc n'existe pas. → **Lot 1 DOC-URGENT** inclut maintenant "retirer topic GitHub nFADP-compatible + mentions README + CLAUDE.md" comme alternative à GOV-01.

### Titre embarrassant proposé par le contradictoire

Ce que GPT-5.5 imagine comme titre HN / Krebs / r/netsec **si on ne bouge pas** :

> *"'Security-Hardened' Outlook MCP Server Shipped With 23 Known Vulns, Cleartext Azure Refresh Tokens in Logs, and Tests That Only Grepped the Source Code"*

Le titre est vérifiable ligne par ligne aujourd'hui. Sans SEC-01-P0 + Lot 1 fixés, ce titre est publiable. Après SEC-01-P0 + Lot 1 fixés + le README purgé de ses 3 claims mensongères, il ne l'est plus.

### Verdict GPT-5.5

> "Réviser en profondeur. Le narratif 'security-hardened' doit être retiré ou suspendu tant que contrôles runtime, CI bloquante et fuite de secrets ne sont pas corrigés. Les symptômes identifiés sont réels mais emballés dans une taxonomie 'trop confortable' qui sous-priorise le risque credential ; le plan n'est acceptable que dans sa version minimale, automatique et prouvable — le reste est de la décoration tant que les gates ne bloquent pas vraiment."

### Impact sur le plan d'attaque

- **SEC-01 devient SEC-01-P0** : ticket isolé en tête, non noyé dans un lot
- **ADR-0004 v2** : réduit à 3 gates + 1 SLA (au lieu de 4 règles + rituel)
- **DOC-URGENT (Lot 1)** : inclut retrait du claim nFADP par défaut (alternative à écrire le doc)
- **Lot 3** : re-hiérarchisé en 4 sous-catégories (Supply chain P1 / Compliance / Governance P2 / Community P3)
- **Lot 2 MVP** : réduit de 6 items à 4 gates non-négociables. Le reste (Scorecard, harden-runner, weekly ritual) passe en Lot 5 optionnel

Le plan est plus court, plus dur, plus prouvable.
