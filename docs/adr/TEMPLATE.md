# ADR-NNNN — <Titre court>

**Date** : YYYY-MM-DD
**Statut** : Proposé | Accepté | Déprécié | Remplacé par ADR-XXXX
**Décideur** : <nom>
**Reviewers** : <peer/LLM listés>

## Contexte

Quel problème on cherche à résoudre ? Quels signaux ont déclenché la décision ?

Cite les évidences : findings cross-review, incidents, lectures RFC, retours peer.

## Décision

### D1 — <Sous-décision claire>

Texte normatif. Format : règle d'abord, raison ensuite.

### D2 — <…>

…

## Conséquences

### Positives

- …

### Négatives

- …

### Risques résiduels

- **R1** — description. Mitigation : …

## Alternatives envisagées et rejetées

### Op-A — <Nom>

Idée. Pourquoi rejetée.

### Op-B — <Nom>

…

## Plan d'application

Étapes concrètes ou pointeurs vers tickets / lots.

## Threat Model Impact

**Clause obligatoire** — toute PR qui ajoute un ADR sans cette section est refusée en review (règle process installée par GOV-02 / ticket audit 2026-08-02, cf. ADR-0004 "Anti-patterns explicitement interdits").

- **TM courant** : `docs/threat-model/<date>-<nom>.md` (lien vers le TM en vigueur)
- **Statut** : **`TM: unchanged`** | **`TM: to-update`** | **`TM: superseded`**
  - `unchanged` — cet ADR ne modifie aucune surface, acteur, hypothèse de confiance, ni contre-mesure listés dans le TM courant. Justifier en 1-2 phrases pourquoi.
  - `to-update` — cet ADR touche une surface / une contre-mesure / un acteur. Un ticket de mise à jour du TM courant est ouvert : **`<TICKET-ID>`**. Le TM sera révisé sous **7 jours** après merge de cet ADR (SLA aligné ADR-0004 Règle 4).
  - `superseded` — cet ADR change l'architecture d'un ordre tel que le TM courant devient trompeur (ex. pivot ADR-0002 → ADR-0003). Un **nouveau TM** est produit et lié ici : `docs/threat-model/<nouvelle-date>-<nouveau-nom>.md`. L'ancien TM est marqué `superseded` en tête.

**Pourquoi cette clause** : un TM figé sur une archi qui n'existe plus (cas ADR-0003 → TM 2026-05-10, corrigé 12 semaines plus tard par GOV-02) est **pire qu'un TM absent** — il induit en erreur qui l'audit. Sans hook explicite ADR ↔ TM, personne ne rejoue STRIDE spontanément après un pivot d'archi.

## Références

- RFC / spec / incident / ADR liée
- Threat Model courant lié dans la section ci-dessus
