# Cross-review YYYY-MM-DD — <label / git range>

**Range** : `<base>..<head>`
**Commits** : N
**Diff size** : K KB
**Reviewers invoqués** : N0 (Claude sub-agent) + N1 (codex) + N2 (ixtriasrv) + N3 (mcp-vault peer, optionnel)

## Résumé

X BLOCKER, Y IMPORTANT, Z OBSERVATION. Statut merge : **bloqué | conditionnel | OK**.

---

## N0 — Claude sub-agent `pr-review-toolkit:code-reviewer`

Cf. section ADR-0001 §Schema Finding V3. Pour chaque finding BLOCKER/IMPORTANT :

```finding
id: B1
severity: BLOCKER
file: src/oauth/dcr.ts:42
claim: <one-line>
reasoning: |
  …
  Alternative considérée : <…>. Rejetée car <…>.
evidence:
  tool: runtime
  repro_runtime: |
    npm test -- --run src/oauth/__tests__/dcr.test.ts -t "rejects wildcard"
fix: <correction>
confidence: 92
```

---

## N1 — codex review (gpt-5.4, cross-school)

Idem schema. Sources externes (RFC, OWASP) bienvenues dans `evidence.tool: rfc | doc`.

---

## N2 — ixtriasrv (qwen36-27b + devstral-small-2)

Synthèse + findings clés. Annotations `[N2-qwen]` / `[N2-devstral]`.

---

## N3 — mcp-vault peer (optionnel)

Si patterns OAuth / rate-limit / audit / trust-proxy partagés. Retour JSON structuré du bus.

---

## Convergence / divergence

Tableau cross-finding :

| ID | N0 | N1 | N2 | N3 | Verdict |
|---|---|---|---|---|---|
| B1 | ✓ | ✓ | – | ✓ | confirmé, fix obligatoire |
| I8 | – | ✓ | – | ✗ | divergence cross-projet — voir notes |

## Décisions et plan de remédiation

1. Fix B1 dans commit dédié, branche `fix/<id>-<slug>`, test régression
2. …

## Tag attendu post-remédiation

`vX.Y.Z` après que tous les BLOCKER + au moins 80% des IMPORTANT sont fixés.
