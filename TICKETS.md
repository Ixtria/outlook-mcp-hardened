# TICKETS

État après audit stratégique 2026-08-02 + révision post contradictoire GPT-5.5.

Voir :
- `docs/plans/2026-08-02-audit-maintenance-strategique.md` — audit complet + annexe contradictoire
- `docs/adr/0004-discipline-de-maintenance.md` — 4 gates non-négociables

**Total : 38 tickets** dont **1 P0 isolé** + 4 lots priorisés (11-16 j homme total).

Historique v0.2.0 Lots B/C/D/E dans `git log` (pas remis ici — reprise stratégique post 6 semaines de silence).

---

## 🚨 P0 ISOLÉ (bloque tout — dominant, pas noyé dans un pattern)

Le contradictoire GPT-5.5 a rappelé que ce ticket ne doit **jamais** être un item parmi d'autres. Il domine le rapport.

| ID | Titre | Effort |
|---|---|---|
| **SEC-01-P0** | 🚨 **Refresh token Azure opaque (`M.C_...`, `1.A...`) logué en clair dans `mcp-server.log`.** Le PII redactor JWT_RE / BEARER_RE ne matche PAS ce format. Confirmé par 3 findings CodeQL ERROR `js/clear-text-logging` (graph-client.ts:183 + auth.ts:312 + auth.ts:426). Principe #5 du CLAUDE.md ("audit trail sans fuite") violé en pratique. Fix : (a) destructuring `safeOpts` dans graph-client.ts:183, (b) `hashAccount()` sur homeAccountId dans auth.ts:312+426, (c) régénération salt audit + rotation MSAL post-fix pour effacer historique éventuel + test comportemental anti-fuite (fixture token → assert absence dans log file écrit). | 1 h |

**Sans ce fix**, le titre embarrassant proposé par le contradictoire GPT-5.5 est publiable demain :

> *"'Security-Hardened' Outlook MCP Server Shipped With 23 Known Vulns, Cleartext Azure Refresh Tokens in Logs, and Tests That Only Grepped the Source Code"*

---

## Lot 1 — URGENT (débloque l'immédiat, ~½ j hors P0)

Refermer les mensonges frontaux + purger le backlog + débloquer la CI.

| ID | Titre | Effort |
|---|---|---|
| **SEC-02** | 🔴 2× regex-injection CodeQL — suppress avec justif (faux positifs CLI local) | 5 min |
| **SEC-03** | 🔴 Security CI cron rouge 5 semaines — ajouter `--experimental-fail-severity=high` à osv-scanner + merger Dependabot hono + fast-uri (2 HIGH prod) | 15 min |
| **OBS-01** | 🔴 Winston File transport sans rotation → disque plein garanti (maxsize + maxFiles) | 15 min |
| **DOC-URGENT** | 🔴 **Retirer 3 claims mensongères du README** : badge "0 vulns", "CI blocks phone-home", "audit trail per Graph call" (laisse croire à OAuth). Harmoniser systemd score contradictoire 1.5 vs 2.5. **Retirer le claim "nFADP-compatible"** du topic GitHub + README + CLAUDE.md tant que `docs/COMPLIANCE-nFADP.md` n'existe pas (contradictoire GPT-5.5 : "faux claim frontal, pas un trou"). | 30 min |

**Sortie Lot 1** : CI verte, mensonges retirés, backlog Dependabot HIGH prod purgé.

---

## Lot 2 — STRUCTUREL MVP (implémente ADR-0004, ~1 j)

**Réduit du plan original de 6 items à 4 gates non-négociables** suite contradictoire GPT-5.5.

| ID | Titre | Gate ADR-0004 | Effort |
|---|---|---|---|
| **ADR-0004** | 🟠 Committer ADR-0004 "Discipline de maintenance" | — | 5 min (déjà écrit) |
| **AUTO-01** | 🟠 Auto-merge Dependabot patch/minor si CI verte + notifications GitHub failure activées | Règle 4 | 30 min |
| **SEC-05** | 🟠 Pinner les 4 GitHub Actions par SHA 40-char (**TruffleHog `@main` en particulier — critique**, incidents trivy/kics récents) | Règle 1 étendue | 30 min |
| **MAINT-LINT-0** | 🟠 `npm run lint --max-warnings 0` en gate CI + tagger inline les 121 warnings actuels ou fix | Règle 2 | 3-4 h |
| **MAINT-TEST-BEHAV** | 🟠 **1 vrai test d'intégration comportemental** sur PKCE required + POST /authorize 405 + redactor refresh token. Remplace les tests grep de `blockers-N4.test.ts` | Règle 3 | 4-6 h |

**Ce qui reste hors Lot 2 MVP** (délibérément différé, ne pas confondre avec Lot 5) : Scorecard workflow, harden-runner, weekly ritual formalisé, PR template complet. Ces items **n'invalident pas** les 4 gates ADR-0004 s'ils se délitent.

**Sortie Lot 2** : les 4 gates ADR-0004 tiennent au niveau outil.

---

## Lot 3 — BLINDAGE (baseline OSS "sérieux" 2026, ~2-3 j — RE-HIÉRARCHISÉ)

Le contradictoire a demandé de séparer supply chain (P1) vs governance communautaire (P3). Fait ici.

### 3.a — Supply chain (P1)

| ID | Titre | Effort |
|---|---|---|
| **SUP-01** | 🟠 `.github/workflows/publish.yml` avec SBOM CycloneDX + npm `--provenance` (workflow documenté dans docs/GITHUB_SETUP.md mais jamais committé) | 2 h |

### 3.b — Compliance nFADP (bloquant si claim présent)

| ID | Titre | Effort |
|---|---|---|
| **GOV-01** | 🔴 `docs/COMPLIANCE-nFADP.md` — RoPA + DPIA simplifiée + DFD. **Alternative recommandée par contradictoire** : retirer le claim nFADP-compatible partout jusqu'à ce que ce doc existe (couvert par DOC-URGENT Lot 1). Ce ticket est à ouvrir si Jimmy veut préserver le claim. | 1 j |

### 3.c — Governance & release (P2)

| ID | Titre | Effort |
|---|---|---|
| **GOV-02** | 🟠 Hook ADR ↔ TM check : chaque ADR future doit contenir clause `TM: unchanged / to-update / superseded`. Rejouer le TM post pivot ADR-0003. | ½ j |
| **GOV-03** | 🟠 `docs/INCIDENT-RESPONSE.md` : playbook par type d'incident (leak token M365, dep compromise, egress violation, refresh reuse) | 1 j |
| **GOV-05** | 🟠 `docs/RELEASING.md` + deprecation policy + support matrix (Node, MCP protocol) + LTS policy | 3 h |

### 3.d — Community (P3 — vraiment nice-to-have)

| ID | Titre | Effort |
|---|---|---|
| **GOV-04** | 🟡 Trio baseline OSS : `.github/ISSUE_TEMPLATE/*.yml` + `PULL_REQUEST_TEMPLATE.md` + `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) + `security.txt` côté deploy/nginx | 2 h |

---

## Lot 4 — TESTS (restaure la valeur de la coverage, ~3-5 j)

Les BLOCKERS ne peuvent plus régresser silencieusement (Règle 3 ADR-0004).

| ID | Titre | Effort |
|---|---|---|
| **TEST-01** | 🔴 **E2E HTTP full-stack supertest sur les 8 routes OAuth**. Refactor obligatoire : `blockers-N4.test.ts` (grep source) remplacé par vrais tests HTTP. server.ts 0% → cible 80%. **Contradictoire GPT-5.5 : "sans ça, la fiabilité des BLOCKERS Phase B est une illusion".** | 2-3 j |
| **TEST-06** | 🟠 Contract tests labelled par RFC (7591 conformance / 6749 §5.2 / 9700 §2.1.1 PKCE / 8707 resource) | 1 j |
| **OBS-02** | 🟠 `auditLog()` sur 6 sites OAuth manquants + `docs/AUDIT_EVENTS.md` source de vérité + test contract (ne pas se contenter de grep AST — vérifier émission runtime avec assertions sur champs) | 1-2 j |
| **OBS-04** | 🟠 `request_id` cross-events via `crypto.randomUUID()` dans request-context.ts | 2 h |
| **OBS-03 + OBS-07** | 🟠 Redactor étendu récursivement sur `info` entier (pas juste `info.message`) — traite splat `logger.error(msg, err)` + test pipeline end-to-end avec fixture PII → assertion output fichier | 3 h |
| **OBS-05** | 🟡 Winston format printf → JSON + timezone + statiques (`service, version, hostname`) | 1 h |
| **TEST-02** | 🟠 PKCE flood test réel (10 001 requêtes concurrentes, verify éviction + pas de leak) | 1 j |
| **TEST-03** | 🟠 Contract MCP protocol test (validation JSON Schema `list_tools()`) | ½ j |

**Sortie Lot 4** : les mensonges "coverage 100%" et "audit trail" sont vrais.

---

## Lot 5 — NICE (hygiène et dette, ~2-3 j — optionnel)

| ID | Titre | Effort |
|---|---|---|
| **TEST-04** | 🟡 Chaos audit-salt / secrets (fs hostile, TOCTOU, perms 644 au lieu 600) | 1 j |
| **AUTO-02** | 🟡 OpenSSF Scorecard workflow (visibilité continue supply chain) | 30 min |
| **AUTO-03** | 🟡 StepSecurity harden-runner sur tous les workflows | 30 min |
| **AUTO-04** | 🟡 Bump Node 22/24 (deprecation Node 20 annoncée) + engines `>=22` | 2 h |
| **OBS-06** | 🟡 Health endpoint enrichi + docs/AUDIT_EVENTS.md finalisé | 3 h |
| **OBS-08** | 🟡 Health check `/health/live` ≠ `/health/ready` différenciés | 1 h |
| **TEST-05** | 🟡 121 warnings ESLint justifiés ligne par ligne — **DÉPLACÉ vers Lot 2 MAINT-LINT-0** qui est plus brutal (`--max-warnings 0` gate directement). Ce ticket devient redondant. | (fusionné) |

---

## Récapitulatif

- **Total** : 38 tickets ouverts (1 P0 isolé + 37 en 5 lots)
- **Effort total** : 11-16 j homme
- **Bloquant absolu** : **SEC-01-P0** (1 h) — refresh token en clair est un leak credential réel
- **Bloquant crédibilité** : Lot 1 (½ j) — retirer mensonges frontaux + purger backlog
- **Cible v0.3.1** : SEC-01-P0 + Lot 1 + Lot 2 (~1½ j) → CI redevient une porte
- **Cible v0.3.2** : + Lot 3 P1 (SUP-01 + décision GOV-01 vs retrait claim nFADP) (~1½ j)
- **Cible v0.4.0** : + Lot 4 (~4-5 j) → tests réels + audit trail réel
- **Cible v0.5.0** : Lot 5 + refactor architectural mcpAuthRouter drop

## Positionnement (source STRAT-02 + contradictoire GPT-5.5)

- **Avant fix Lot 1** : *"projet en remédiation sécurité, doc avancée mais contrôles encore non fiables"* (verdict contradictoire GPT-5.5)
- **Après Lot 1 + P0 fixé** : "défendable niveau OSS solo-mainteneur security-serious" (verdict STRAT-02)
- **Après Lots 1 à 4** : au niveau OSS vendor-backed sur observability + tests, au-dessus sur méthodologie audit
