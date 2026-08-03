# TICKETS

État après audit stratégique 2026-08-02 + révision post contradictoire GPT-5.5.
**37/37 tickets du cycle v0.4.0 fermés** (voir CHANGELOG v0.4.0). Ce fichier
liste désormais les tickets remontés APRÈS release v0.4.0.

Voir :
- `docs/plans/2026-08-02-audit-maintenance-strategique.md` — audit complet + annexe contradictoire
- `docs/adr/0004-discipline-de-maintenance.md` — 4 gates non-négociables

---

## 🔴 NOUVEAU post-v0.4.0 — remontée bus agent-hub 2026-08-03

### SOV-01 — Client OAuth par défaut NON souverain (client_id Softeria dans le fork Ixtria)

**Signalé par** : hermes via bus agent-hub (conv `conv-20260803-sovereign-default-client`, msg-id `msg-20260803T100442-from-hermes-sovereign-default-client`).

**Contexte terrain** : Hermes a déployé v0.4.0 sur le mini-server et testé le device-code login sur le compte Outlook perso de Jimmy. Au consentement Microsoft AAD, l'app affichée est **"Softeria AS / MS 365 MCP Server"**, PAS Ixtria. Jimmy a refusé le consent — il veut du souverain.

**Root cause** :
- `src/cloud-config.ts:50` : `DEFAULT_CLIENT_IDS.global = '084a3e9f-a9f4-43f7-89f9-d229cf97853e'` = **App Registration Softeria** (héritée de l'upstream, jamais remplacée dans le fork)
- Ce client_id fait référence à une Azure App Registration créée dans le tenant Softeria, tokens émis par Microsoft AAD au nom de cette entité tierce
- **Contradiction directe** avec la promesse README ligne 17 : *"Not affiliated with Microsoft, Anthropic, or Softeria. Independent project published by Ixtria SA"* — mais on utilise leur App par défaut

**Impact utilisateur** :
- User qui `npm install -g @ixtria/outlook-mcp-hardened` + `--login` consent à un client third-party sans le savoir explicitement
- Souveraineté brisée par défaut — raison d'être du fork
- Un consommateur "security-serious" comme Jimmy refuse et cherche à changer, mais rien dans la doc ne l'y aide au moment du refus

**3 options** :

- **(A) Nouveau default client_id Ixtria** (recommandé) : Jimmy crée une Azure App Registration côté tenant Ixtria (~10 min Azure Portal : App type Public client, redirect URIs = `http://localhost:*` + `https://outlook-mcp.ixtria.xyz/callback`, delegated permissions Mail.Read + Mail.ReadWrite + Mail.Send + Calendars.Read + Calendars.ReadWrite + offline_access + User.Read). Remplace le default dans cloud-config.ts:50. Solution alignée avec la raison d'être du fork.

- **(B) Pas de default, exiger `MS365_MCP_CLIENT_ID` au boot** : safer (aucun tiers par défaut) mais casse l'onboarding zéro-conf pour tous les nouveaux users. Recommandation refusée par contradictoire probable.

- **(C) Warning fort au boot + doc INSTALL** : garde Softeria par défaut mais affiche `⚠️ You are about to consent to a THIRD-PARTY app "Softeria/MS 365 MCP Server". For a sovereign install, register your own Azure App and set MS365_MCP_CLIENT_ID (see INSTALL.md#sovereign-setup)`. Patch minimal, promesse toujours cassée par défaut.

**Recommandation combinée A + C** :
1. **A immédiat** : Jimmy crée l'App Ixtria (~10 min Azure Portal, action manuelle requise — ne peut pas être scripté sans Jimmy admin Azure)
2. **C en filet** : warning au boot + section INSTALL "Sovereign setup" pour tous les users qui veulent leur propre App

**Action Jimmy requise** :
- Azure Portal → tenant Ixtria → App Registrations → New → "Ixtria Outlook MCP" (Public client, Multi-tenant si on veut supporter compte perso Microsoft en plus des tenants pro)
- Copier le nouveau `Application (client) ID`
- Le donner à ce projet pour remplacement dans cloud-config.ts

**Effort code** :
- Option A seule : 5 min (1 constante changée) + test smoke
- Option A+C : ~30 min (constante + warning + doc INSTALL)

**Bloque** : la promesse OSS "sovereign / Ixtria-owned". Priorité 🔴 URGENT à traiter en v0.4.1 ou v0.5.

**GitHub Issue** : à créer + linker au retour de Jimmy pour l'App Registration.

---

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
| **AUTH-01** | 🔴 **Client OAuth par défaut non-souverain.** `DEFAULT_CLIENT_IDS.global` (`src/cloud-config.ts:50`) pointe sur l'app registration Softeria (`084a3e9f-a9f4-43f7-89f9-d229cf97853e`). Au device-code login Microsoft, l'écran de consentement affiche **"Softeria AS / MS 365 MCP Server"**, pas Ixtria — contredit frontalement la promesse de souveraineté du fork (retour terrain Jimmy, incident `conv-20260803-sovereign-default-client`). Fix recommandé : enregistrer une app registration Azure AD propre à Ixtria (public client, multi-tenant, device code flow) et en faire le défaut de `DEFAULT_CLIENT_IDS.global` ; documenter `--client-id` pour BYO app en alternative. **Prérequis hors code** : création de l'app registration nécessite un accès Azure AD/Entra côté Jimmy (tenant Ixtria) — bloquant tant que ce n'est pas fait. | 2-3 h (+ dépendance Azure côté Jimmy) |

**Sortie Lot 1** : CI verte, mensonges retirés, backlog Dependabot HIGH prod purgé, client OAuth par défaut souverain (ou warning explicite en attendant).

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

- **Total** : 39 tickets ouverts (1 P0 isolé + 38 en 5 lots)
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
