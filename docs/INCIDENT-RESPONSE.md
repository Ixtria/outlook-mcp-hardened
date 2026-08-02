# Incident Response Runbook

Playbook opérationnel pour `@ixtria/outlook-mcp-hardened`. Chaque section est
une checklist actionable, à suivre dans l'ordre. Objectif : contenir en < 15 min,
récupérer en < 24 h, notifier sous 72 h (nFADP art. 24 / GDPR art. 33).

**Rôles** :
- **IC** (Incident Commander) : Jimmy Blanquet (solo mainteneur) — décide, coordonne.
- **Reporter** : rédige l'incident dans `docs/incidents/YYYY-MM-DD-<slug>.md`.

**Sévérités** :
- **P0** : exfiltration active, compromission code publié, deps runtime compromise.
- **P1** : token fuité par utilisateur, refresh reuse détecté, CVE HIGH sur dep prod.
- **P2** : egress violation isolée, CVE MEDIUM sans exploit connu.

Toute action destructive (revert, révocation, purge) suit le protocole global
"ROLLBACK READY" (`~/.claude/CLAUDE.md` §3) : commande de rollback écrite avant exécution.

---

## Playbook 1 — Fuite de token M365 (utilisateur signale)

**Sévérité** : P1 (P0 si publiée sur canal public : GitHub, Pastebin, screenshot).

### 1. Detection signals
- Utilisateur écrit à `security@ixtria.com` ou ouvre issue GitHub taggée `security`.
- Screenshot d'audit log contenant un `access_token`/`refresh_token` en clair.
- Alerte GitHub secret scanning sur un commit récent (rare — l'audit logger masque).
- Requêtes Graph inattendues visibles dans Azure AD sign-in logs.

### 2. Immediate containment (0-5 min)
- [ ] Confirmer le tenant Azure et l'`account hash` concerné (audit log).
- [ ] Utilisateur : **révoquer immédiatement toutes les sessions** dans Azure Portal → "Users → <user> → Sign-ins → Revoke sessions".
- [ ] Si token dans un log public : demander suppression + noter timestamp fuite pour forensics.

### 3. Recovery (5 min - 2 h)
- [ ] Utilisateur : supprimer cache MSAL local (`~/.mcp-outlook/*` sur sa machine).
- [ ] Utilisateur : ré-exécuter device code flow → nouveau refresh token.
- [ ] Rotation du salt d'audit (`OUTLOOK_MCP_AUDIT_SALT`) → invalide les hashes d'account historiques.
- [ ] Purge locale des logs contenant le hash : `find ~ -name 'mcp-server.log*' -exec grep -l "<hash>" {} \; | xargs shred -u`.
- [ ] Vérifier Azure AD sign-in logs (7 j) pour usage non-autorisé du token révoqué.

### 4. Post-incident (< 72 h)
- [ ] Rédiger RCA dans `docs/incidents/YYYY-MM-DD-token-leak.md` (comment fuité, impact, mesures).
- [ ] Notifier utilisateur : brèche confirmée / non-confirmée, données Graph potentiellement accédées.
- [ ] Si données personnelles UE/CH accédées par tiers : notifier PFPDT (CH) sous 72 h et personnes concernées.
- [ ] Si origine = bug du code (log leak, cache non chiffré) : ouvrir ticket SEC-xx bloquant release.

---

## Playbook 2 — Dépendance compromise (Dependabot / news / advisory)

**Sévérité** : P0 si dep runtime dans dernière release publiée ; P1 sinon.

### 1. Detection signals
- GitHub advisory publiée sur dep présente dans `package-lock.json`.
- Dependabot alert `HIGH`/`CRITICAL` sur dep runtime.
- News (Twitter, HN, Snyk blog) sur package compromis (typo-squat, maintainer takeover, malicious version).
- `osv-scanner` en CI passe soudainement en rouge sur commit sans changement de deps.

### 2. Immediate containment (0-5 min)
- [ ] Confirmer version compromise vs version installée : `npm ls <dep>`.
- [ ] Si dep runtime + version affectée : **retirer immédiatement les tags npm publiés** contenant la version compromise : `npm deprecate @ixtria/outlook-mcp-hardened@<versions> "SECURITY: compromised dep <dep>@<ver>, do not install"`.
- [ ] Épingler le tag `latest` sur dernière version SAINE : `npm dist-tag add @ixtria/outlook-mcp-hardened@<safe-ver> latest`.

### 3. Recovery (30 min - 4 h)
- [ ] Identifier commit d'introduction : `git log --all -- package-lock.json | grep -B2 <dep>`.
- [ ] Revert ou upgrade vers version patched : `npm install <dep>@<safe-version> --save-exact`.
- [ ] Rotation de tous les secrets ayant transité via runtime infecté : `OUTLOOK_MCP_AUDIT_SALT`, credentials MSAL machine identity (Infisical), tokens GitHub/npm publish.
- [ ] Audit runtime : sur toute machine ayant exécuté la version compromise, scanner processus + connexions sortantes non-allowlist + fichiers modifiés dans `~/.mcp-outlook/`.
- [ ] Release patch `x.y.z+1` avec dep saine + note SECURITY dans CHANGELOG.

### 4. Post-incident (< 72 h)
- [ ] Notifier consumers via GitHub Security Advisory + email direct aux tenants Ixtria connus.
- [ ] RCA : comment la dep est passée les 3 gates ADR-0004 ? Ajuster `--experimental-fail-severity` si nécessaire.
- [ ] Si origine = maintainer takeover : évaluer alternatives à la dep, ouvrir ticket TECH-xx.

---

## Playbook 3 — Egress violation détectée en runtime

**Sévérité** : P1 (P0 si le host non-allowlist correspond à un domaine C2 connu).

### 1. Detection signals
- Log stderr contient `EgressViolationError: host <domain> not in allowlist`.
- Utilisateur signale crash au boot ou pendant un appel Graph.
- Audit log montre pattern anormal (fréquence, endpoints jamais vus).

### 2. Immediate containment (0-5 min)
- [ ] **Ne pas relancer le serveur MCP** sur la machine affectée avant analyse.
- [ ] Capturer : stack trace complète, valeur du host bloqué, timestamp, `account hash`, version du package (`npm ls @ixtria/outlook-mcp-hardened`).
- [ ] Sauvegarder `mcp-server.log*` + `~/.mcp-outlook/` (dump chiffré, `chmod 600`) pour forensics.

### 3. Recovery (30 min - 4 h)
- [ ] Analyser code path : `grep -rn "<host-bloqué>" src/` → l'egress guard a fonctionné (bon signe) mais qui a tenté l'appel ?
- [ ] Si origine = code upstream nouveau (dep bump récent) : revert + investigation dep.
- [ ] Si origine = injection prompt (LLM appelant génère URL malveillante) : renforcer `injection-wrapper.ts` + ticket SEC-xx.
- [ ] Si origine = code Ixtria modifié (régression) : revert commit + hotfix release.
- [ ] Rotation cache MSAL utilisateur : suppression `~/.mcp-outlook/` + ré-auth device code.

### 4. Post-incident (< 72 h)
- [ ] RCA : pourquoi le code a tenté ce host ? Test comportemental ajouté dans `src/security/egress-guard.test.ts` reproduisant le cas.
- [ ] Vérifier que l'egress guard **n'a jamais été bypassé** : si oui = P0, playbook 2 + audit code path complet.
- [ ] Notifier utilisateur (breach probable si allowlist bypassed ; simple bug sinon).

---

## Playbook 4 — Refresh token reuse détecté (replay attack)

**Sévérité** : P1 (P0 si multiple accounts concurrents).

### 1. Detection signals
- Audit log montre 2 refresh depuis même `account hash` dans fenêtre < 30 s.
- Azure AD sign-in logs : IP/geo différentes pour même compte, corrélées à un refresh.
- Utilisateur signale déconnexion inattendue (le vrai token invalidé par attaquant).

### 2. Immediate containment (0-5 min)
- [ ] Révocation immédiate de la session Azure : Portal → "Users → <user> → Revoke sessions".
- [ ] Bloquer temporairement l'utilisateur en Azure Conditional Access si abus confirmé.
- [ ] Capturer les 2 refresh events + IPs source + user-agent depuis Azure sign-in logs.

### 3. Recovery (30 min - 4 h)
- [ ] Utilisateur : supprimer `~/.mcp-outlook/` sur toutes ses machines connues.
- [ ] Utilisateur : ré-exécuter device code flow → nouveau refresh token (l'ancien devenant orphelin).
- [ ] Rotation `OUTLOOK_MCP_AUDIT_SALT` si l'attaquant a pu voir les logs audit.
- [ ] Forensics Azure : quels endpoints Graph l'attaquant a-t-il appelés ? Extraire de "Microsoft Graph activity logs" (si Premium P1+).
- [ ] Si code exfiltrable via Mail.Read : préparer notification data breach.

### 4. Post-incident (< 72 h)
- [ ] RCA : d'où vient la fuite du refresh token ? (cache non chiffré, log leak, machine compromise ?)
- [ ] Ajouter détection continue : audit rule qui alerte si 2 refresh même hash < 30 s.
- [ ] Notification PFPDT/GDPR selon nature des données accédées.
- [ ] Ticket SEC-xx si le cache MSAL local était en clair (interdit — vérifier ADR-0002/0003).

---

## Playbook 5 — CVE critique sur dépendance prod

**Sévérité** : P0 si exploit public + dep runtime ; P1 sinon.

### 1. Detection signals
- GitHub Dependabot alert `CRITICAL`.
- `osv-scanner` CI fail avec severity HIGH+.
- Advisory NIST/GHSA/Snyk publiée sur dep listée dans `package.json` (deps runtime, pas devDeps).

### 2. Immediate containment (0-5 min)
- [ ] Évaluer exposition : est-ce que le code path vulnérable est **atteignable** dans notre usage ? (`grep -rn "<vulnerable-api>" src/`).
- [ ] Si code path atteignable + exploit public : `npm deprecate @ixtria/outlook-mcp-hardened@<affected-versions> "SECURITY: <CVE-id>, upgrade to <patched>"`.
- [ ] Si non atteignable : pas d'urgence release, mais ticket SEC-xx dans les 7 j.

### 3. Recovery (2 h - 24 h)
- [ ] `npm update <dep>` vers version patched, `npm ls <dep>` pour confirmer.
- [ ] `npm run verify` (lint + build + test) doit passer sans warning.
- [ ] Ajouter test de non-régression si le vecteur est reproductible côté MCP (ex : payload egress malveillant).
- [ ] Release patch `x.y.z+1` avec note CHANGELOG citant le CVE et le commit fix.
- [ ] Publier GitHub Security Advisory (`gh api repos/Ixtria/outlook-mcp-hardened/security-advisories`).

### 4. Post-incident (< 72 h)
- [ ] Communiqué : email tenants Ixtria connus + note en tête de README pour 7 j.
- [ ] RCA : pourquoi le scanner ne l'a pas attrapé avant merge ? Gate ADR-0004 R1 tenue ?
- [ ] Si dep = infra critique récurrente (msal, sdk MCP) : évaluer contract test additionnel.

---

## Checklist post-incident universelle

Pour TOUT incident, avant clôture :

- [ ] Fichier `docs/incidents/YYYY-MM-DD-<slug>.md` rédigé (contexte, timeline, RCA, actions).
- [ ] Backlog : ticket SEC-xx ou TECH-xx ouvert pour chaque action de fond restante.
- [ ] `CHANGELOG.md` mis à jour si release patch.
- [ ] Audit log : entrée `incident_closed` avec référence RCA.
- [ ] Si notification externe faite : conserver preuve (email, ticket PFPDT) 5 ans.

## Références

- ADR-0004 — Discipline de maintenance (`docs/adr/0004-discipline-de-maintenance.md`)
- Global rules — Infrastructure safety (`~/.claude/CLAUDE.md` §Infrastructure/DevOps)
- Threat model (`docs/threat-model/`)
- nFADP (loi fédérale CH sur la protection des données) — art. 24 (notification)
- GDPR — art. 33 (notification breach)
