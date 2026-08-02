# nFADP — Posture déclarative (self-attested)

> **Document auto-attesté, non audité par un tiers.** Ne constitue pas une preuve de conformité formelle. Un déploiement soumis à la nFADP en Suisse doit être validé par un DPO ou juriste conforme.

Ce document décrit la posture du projet `@ixtria/outlook-mcp-hardened` vis-à-vis de la nouvelle Loi fédérale suisse sur la protection des données (nFADP, en vigueur depuis le 1er septembre 2023). Il s'agit d'une posture **déclarative** : le mainteneur atteste des choix techniques et organisationnels au meilleur de sa connaissance, sans que ces déclarations aient fait l'objet d'un audit indépendant.

Le projet est un **outil MCP local** (Model Context Protocol) : il ne collecte pas de données, il ne les héberge pas, il n'agit pas comme responsable de traitement pour un tiers. L'opérateur qui déploie l'outil reste le responsable de traitement au sens de la nFADP.

---

## 1. Traitements de données (RoPA)

Registre des activités de traitement effectuées par l'outil lorsqu'il tourne chez l'opérateur.

| Traitement | Base légale | Catégories de données | Destinataires | Rétention | Transferts |
|---|---|---|---|---|---|
| Lecture email Outlook via MCP | Consentement utilisateur (device code OAuth) | Emails perso/pro de l'opérateur (contenu + métadonnées) | Aucun — traitement local | Aucune — pas de storage | Microsoft AAD/Graph (Azure EU si tenant EU) |
| Lecture/écriture Calendar Outlook via MCP | Consentement utilisateur (device code OAuth) | Événements calendrier de l'opérateur (titres, participants, horaires) | Aucun — traitement local | Aucune — pas de storage | Microsoft AAD/Graph (Azure EU si tenant EU) |
| Envoi email (opt-in `--enable-send`) | Consentement explicite (flag CLI activé par l'opérateur) | Emails composés par le client MCP | Destinataires du mail (via Microsoft Graph) | Aucune côté outil | Microsoft AAD/Graph |
| Cache token MSAL local | Nécessaire à la fourniture du service | Access token + refresh token OAuth de l'opérateur | Local uniquement | Jusqu'à révocation par l'opérateur (`auth_logout`) | Aucun (keytar OS keychain ou fichier chiffré AES-256) |
| Audit trail interne | Intérêt légitime (traçabilité sécurité) | Hash HMAC de user ID + méta appel (tool, scope, status HTTP, timestamp) | Local uniquement (stderr + fichier rotation) | Rotation 5 fichiers × 10 MB (winston) | Aucun |

**Note** : le contenu des emails et événements calendar transite par le processus MCP en mémoire uniquement — aucun contenu applicatif n'est écrit sur disque par cet outil (seuls les tokens et les logs métadonnées le sont).

## 2. DPIA simplifiée

Analyse d'impact simplifiée sur la vie privée, adaptée à un outil open source local.

- **Nécessité + proportionnalité** : le MCP expose **UNIQUEMENT** Mail + Calendar (54 tools filtrés à partir des ~200 endpoints Graph amont), pas SharePoint / OneDrive / Teams. L'egress réseau est **hardcodé** (`login.microsoftonline.com` + `graph.microsoft.com` uniquement) : toute autre destination réseau provoque un crash immédiat au boot. La surface d'attaque est réduite au strict nécessaire à la fonction.
- **Risques identifiés** :
  - *Fuite de token utilisateur* — mitigé par le redactor (fix SEC-01-P0, tokens jamais loggés en clair)
  - *Interception réseau* — mitigé par TLS uniquement + `trusted-proxy` check en mode HTTP
  - *Compromission stockage disque local* — mitigé par audit-salt en `chmod 0600`, respect `XDG_STATE_HOME`, rotation des logs, chiffrement AES-256 du fallback fichier
  - *Prompt injection depuis le contenu des mails* — mitigé par wrapper `<untrusted_content>` (SEC-02) sur le body retourné aux clients MCP
  - *Escalade de permission via `--enable-send`/`--enable-write`* — mitigé par le double opt-in (flag CLI explicite + consentement OAuth)
- **Mesures organisationnelles** : SEC-01 / SEC-02 / SEC-03 fixés, ADR-0004 (discipline de maintenance) publié, threat model STRIDE publié dans `docs/threat-model/`, CI durcie (`--audit-level=moderate`, `--max-warnings 0`).

## 3. Data flow diagram (DFD)

```
[Client MCP (Claude Desktop / Hermès / autre)]
              |
              | stdio (défaut) ou HTTP (mode --http, gated)
              v
[outlook-mcp-hardened]  ---egress-guard---> DENY tout ce qui n'est pas Graph/Login
      |         |         |
      |         |         +--> HTTPS TLS --> [login.microsoftonline.com] (OAuth device code)
      |         |         +--> HTTPS TLS --> [graph.microsoft.com]        (Mail + Calendar API)
      |         |
      |         +--> [audit-logger] --> stderr (JSON structuré)
      |                              --> winston File $XDG_STATE_HOME/outlook-mcp/logs/ (rotation 5×10MB)
      |
      +--> [token store] --> keytar (OS keychain)
                          OU fichier chiffré AES-256 local (fallback)
```

Aucun flux ne quitte la machine de l'opérateur en dehors des connexions HTTPS vers Microsoft.

## 4. Sous-traitants + transferts hors CH

- **Microsoft Corporation** (siège US, filiale Suisse Microsoft Schweiz GmbH) — traite les données via Azure AAD + Microsoft Graph. Choix opérateur recommandé : tenant Azure Europe (data residency EU) pour réduire les transferts extra-CH. Microsoft dispose de clauses contractuelles types (SCC) et est certifié Data Privacy Framework CH-US pour les transferts CH→US.
- **Aucun autre sous-traitant** : pas de CDN, pas d'analytics, pas de télémétrie, pas de service tiers.

Le mainteneur du projet (Ixtria) n'est **pas** sous-traitant au sens de la nFADP : il ne traite aucune donnée personnelle pour le compte de l'opérateur. Il fournit un logiciel.

## 5. Droits des personnes concernées

Le MCP est un **OUTIL**, pas un service. Les droits nFADP (art. 25 ss : accès, rectification, effacement, portabilité, opposition) s'exercent auprès de **l'opérateur qui déploie**, pas auprès du mainteneur.

L'opérateur (utilisateur final ou PME) qui met cet outil en production doit :

- Documenter dans SA propre politique de traitement l'usage de cet outil et les traitements qu'il opère via lui
- Faire remonter les demandes d'accès / rectification / effacement à Microsoft pour les données email/calendar stockées côté Microsoft 365
- Purger les logs locaux (`$XDG_STATE_HOME/outlook-mcp/logs/mcp-server.log` + audit-salt + cache MSAL) sur demande d'effacement
- Prévoir la révocation des tokens OAuth (`auth_logout` MCP tool ou révocation côté portail Microsoft) en cas de départ d'un collaborateur

## 6. Suivi

- Ce document est révisé **au moins 1× / an** ou à chaque pivot architectural
- Dernière révision : **2026-08-02**
- Prochain check prévu : **2027-08-02**
- Toute évolution majeure des données traitées, des sous-traitants, ou de la surface réseau doit être capturée dans un ADR (`docs/adr/`) **et** entraîner une révision de ce document

## 7. Contact

`security@ixtria.ch` — signaler tout gap dans cette posture, tout risque non couvert, ou toute imprécision dans le RoPA / DFD.

Rappel : ce document est **auto-attesté**. Pour un déploiement soumis à la nFADP en contexte professionnel, l'opérateur doit faire valider sa configuration par un DPO ou un juriste qualifié.
