# Cross-review 2026-05-10 — OAuth first wave (commit b60a690)

**Range** : `HEAD~1..HEAD` (commit `b60a690` — première vague Lot B)
**Commits** : 1
**Diff size** : ~7 KB
**Reviewers invoqués** : N0 (Claude `pr-review-toolkit:code-reviewer`) + N1 (`codex review` gpt-5.4)

## Résumé

| Niveau | BLOCKER | IMPORTANT | OBSERVATION |
|---|---|---|---|
| N0 sur mes 3 modules | 1 | 2 | 4 |
| N1 sur le repo entier | 2 | 4 | 1 |

**Statut merge** : ✅ post-fix après commit `<TBD>` (3 fixes intégrés).

---

## N0 — Claude sub-agent — focus modules de b60a690

### B1 N0 — userinfo bypass (BLOCKER conf 95) ✅ FIXÉ

```finding
id: N0-B1
severity: BLOCKER
file: src/oauth/redirect-uri.ts:38
claim: normalizeRedirectUri drops the URL userinfo component, so `https://attacker@claude.ai/api/mcp/auth_callback` validates as TRUE against `https://claude.ai/api/mcp/auth_callback`.
reasoning: |
  URL parse exposes username/password separately. The normalizer built form
  from `protocol + host + pathname + ...` only, silently stripping userinfo.
  Result: input string with extra material was treated as equivalent under
  `===`. Breaks exact-match contract (SPECS §5 step 5), violates RFC 6749
  §3.1.2, and userinfo is a known phishing vector (RFC 3986 §3.2.1).
  Alternative rejected: "userinfo harmless because browser navigates host
  anyway" — but the AS contract is string-equal, and downstream audit
  comparisons would diverge.
evidence:
  tool: runtime
  repro_runtime: |
    cd /home/jimb/Projets/outlook-mcp-hardened
    # Inline repro reproduit en test, vérifie le bypass pré-fix
    cat > /tmp/repro.test.ts << 'EOF'
    import { validateRedirectUri } from '../src/oauth/redirect-uri.js';
    test('B1', () => expect(validateRedirectUri(
      'https://attacker@claude.ai/api/mcp/auth_callback',
      new Set(['https://claude.ai/api/mcp/auth_callback'])
    )).toBe(false));
    EOF
fix: |
  Ajout de 2 lignes dans normalizeRedirectUri :
    if (parsed.username !== '' || parsed.password !== '') return null;
  + 3 tests régression couvrant `user@`, `u:p@`, `:secret@`.
confidence: 95
```

**Status post-fix** : `validateRedirectUri('https://attacker@claude.ai/api/mcp/auth_callback', ...)` retourne `false`. 3 tests régression ajoutés (suite `userinfo bypass`).

### I1 N0 — DANGEROUS_PERCENT incomplet (IMPORTANT conf 80) ✅ FIXÉ

```finding
id: N0-I1
severity: IMPORTANT
file: src/oauth/redirect-uri.ts:20
claim: DANGEROUS_PERCENT bloque seulement %2F/%5C/%00 mais pas %0A/%0D (CRLF anti audit-injection) ni %2E (anti `..` smuggling).
fix: regex étendu à /%2[EeFf]|%5[Cc]|%00|%0[AaDd]/. 5 tests régression : %0A, %0D, %2E, %2E%2E, lowercase variants.
confidence: 80
```

**Status post-fix** : `%0A`, `%0D`, `%2E`, `%2E%2E` rejetés ; lowercase variants aussi.

### I2 N0 — IPv4-mapped IPv6 silent attribution bug (IMPORTANT conf 82) ✅ FIXÉ

```finding
id: N0-I2
severity: IMPORTANT
file: src/lib/trust-proxy.ts:29
claim: Node sur dual-stack délivre `::ffff:10.0.0.1` comme socket.remoteAddress pour un peer IPv4. La fonction faisait `Set.has(socketIp)` strict, donc TRUSTED_PROXIES listant `10.0.0.1` ne matchait pas. Pas une régression sécu (fail-closed), mais attribution rate-limit silencieusement cassée.
fix: |
  Ajout helper `normalizeIp()` qui strip `::ffff:` prefix si le suffixe est
  un dotted-quad IPv4 valide (octets 0-255). Appliqué au socket peer ET à
  chaque hop XFF. 4 tests régression : socket IPv4-mapped, XFF IPv4-mapped,
  vraie IPv6 préservée, malformed IPv4-mapped préservé littéralement.
confidence: 82
```

**Status post-fix** : `resolveClientIp('::ffff:10.0.0.1', '1.2.3.4', new Set(['10.0.0.1']))` retourne `'1.2.3.4'` au lieu de `'::ffff:10.0.0.1'`.

### Observations N0 (non bloquantes)

- 🟡 `pathname` URL-parsed collapse `..` — ajouter test asserting behavior (à intégrer prochaine vague)
- 🟡 `hops[0]` fallback retourne un trusted proxy quand tous trusted — ajouter warn log (à intégrer wiring)
- 🟡 `split(/\s+/)` trop permissif (RFC 6749 §3.3 stricte `\s` = space ASCII uniquement) — non bloquant car KNOWN filter est la frontière sécurité, à durcir si besoin v0.3
- 🟡 Test `serializeScope` déterministe non couvert par valeur littérale — trivial via `.sort()`, à clarifier dans le test

### Positive durable patterns (N0)

- **Test thoroughness** : 60 tests V0, 73 tests V1 (post-fix), chaque cas négatif lié à une CVE-class
- **In-file traceability** : JSDoc référence codex finding ID + SPECS §X + ADR clause
- **Pure-function design** : facilite review et repro runtime ≤30 lignes
- **eslint-disable justifié** : commentaire explique pourquoi, conforme discipline `// HARDENED:` du projet

---

## N1 — codex/gpt-5.4 — focus repo entier (legacy v0.1)

N1 n'a pas pu lire les SHA locaux directement (sandbox bwrap n'accède pas au range non-pushé — bug connu, ADR-0001 §règle méta 5). A reviewé le repo public sur GitHub. Findings portent sur le code **legacy v0.1**, pas sur mes 3 modules de b60a690.

### N1-B1 — `trust proxy=true` global (BLOCKER conf 96) — legacy v0.1

```finding
id: N1-B1
severity: BLOCKER
file: src/server.ts:177
claim: `app.set('trust proxy', true)` accepte les XFF de n'importe quel hop, pas seulement d'une whitelist. Contredit ADR-0002 et MODES.md.
fix planned: TKT-C2 (wiring trust-proxy.ts dans request-context.ts) + TKT-C3 (boot guard refuse si TRUSTED_PROXIES manquant en http-public).
```

**Status** : ⏳ planifié Lot C, dans le scope explicite des tickets C1-C3. **PAS un bug à fixer dans b60a690 — c'est exactement ce que le wiring corrige.**

### N1-B2 — `/register` legacy non-wiré (BLOCKER conf 94) — legacy v0.1

```finding
id: N1-B2
severity: BLOCKER
file: src/server.ts:287,301-331
claim: /register actuel echo `redirect_uris` sans persistance, /authorize ne lit pas les URIs enregistrées → pas de binding client_id ↔ redirect_uri.
fix planned: TKT-B3 (`src/oauth/dcr.ts` avec persistance SQLite) + TKT-B4 (`src/oauth/authorize.ts` lit `auth_codes` + valide registered URIs) + TKT-B11 (suppression `/register` et `/authorize` legacy).
```

**Status** : ⏳ planifié Lot B (commits suivants). C'est le cœur même du Lot B.

### N1-I1 à N1-I4 — bugs legacy v0.1

| ID | File | Claim | Lot |
|---|---|---|---|
| N1-I1 | server.ts:317-331 | scope forwardé sans intersection | TKT-B4/B6 (wiring `scope.ts`) |
| N1-I2 | server.ts:377-379 | Fallback scope contient `Files.Read` (hors surface Outlook) | TKT-B4 (suppression fallback statique + scope policy-driven) |
| N1-I3 | server.ts:241-254 | Discovery publie `scopes_supported` sans tenir compte write policy | TKT-B8 (`src/oauth/discovery.ts` policy-aware) |
| N1-I4 | README.md:50, auth.ts:320-337 | Doc dit "encrypted file" mais MSAL cache est plaintext 0o600 | **Hors scope OAuth — à traiter séparément, doc OR vrai chiffrement keytar fallback** |

**Status** : ⏳ N1-I1/I2/I3 dans le Lot B planifié. N1-I4 nécessite une décision séparée (mettre à jour README ou implémenter chiffrement at-rest cache MSAL).

### META-CRITIQUE N1

> "Le code semble encore raisonner comme un proxy OAuth pratique plus qu'un AS rigoureux. C'est précisément là que N0 peut survalider des changements locaux corrects (redirect-uri.ts, scope.ts, trust-proxy.ts) tout en ratant que la chaîne complète reste incohérente."

**Réponse** : la chaîne sera reconstruite Lot B commits suivants (TKT-B0 à B12). Les 3 modules de b60a690 sont la **fondation pure** ; leur wiring dans un AS rigoureux est le scope explicite des prochains tickets. La METAcritique est valide et tracée comme prérequis E1 (cross-review finale avant tag v0.2.0).

### Sources N1

- RFC 6749, 7239, 7591
- Express "Behind Proxies" doc
- MCP Authorization 2025-11-25
- README public Ixtria/outlook-mcp-hardened

---

## Convergence / divergence

| Finding ID | N0 | N1 | Verdict |
|---|---|---|---|
| Userinfo bypass redirect-uri | ✓ BLOCKER conf 95 | – (sandbox n'a pas vu le commit) | Confirmé, **fixé dans ce commit** |
| DANGEROUS_PERCENT incomplet | ✓ IMPORTANT conf 80 | – | Confirmé, **fixé dans ce commit** |
| IPv4-mapped IPv6 attribution | ✓ IMPORTANT conf 82 | – | Confirmé, **fixé dans ce commit** |
| trust proxy=true legacy | – (N0 a vu uniquement b60a690) | ✓ BLOCKER conf 96 | Confirmé, **planifié Lot C** |
| /register legacy non-wiré | – | ✓ BLOCKER conf 94 | Confirmé, **planifié Lot B suite** |
| Scope forwardé sans intersection legacy | – | ✓ IMPORTANT conf 92 | Confirmé, **planifié Lot B suite** |
| Files.Read dans fallback legacy | – | ✓ IMPORTANT conf 98 | Confirmé, **planifié Lot B suite** |
| Discovery scope policy ignorée legacy | – | ✓ IMPORTANT conf 95 | Confirmé, **planifié Lot B suite** |
| README "encrypted file" inexact | – | ✓ IMPORTANT conf 99 | **Nouveau, à arbitrer séparément** |

**Aucune contradiction cross-school** : N0 et N1 ont reviewé des surfaces différentes (modules de b60a690 vs repo legacy entier) car N1 n'a pas pu lire le range local. Les findings sont complémentaires, pas conflictuels.

## Décisions et plan de remédiation

### Fixes intégrés dans ce cycle (post-cross-review)

1. ✅ N0-B1 userinfo bypass — `src/oauth/redirect-uri.ts` + 3 tests régression
2. ✅ N0-I1 DANGEROUS_PERCENT étendu — regex + 5 tests régression
3. ✅ N0-I2 IPv4-mapped IPv6 — `normalizeIp()` helper + 4 tests régression

### Bugs legacy v0.1 planifiés Lot B/C/D

- N1-B1 (trust proxy global) → TKT-C2 + TKT-C3
- N1-B2 (DCR legacy non-wiré) → TKT-B3 + TKT-B4 + TKT-B11
- N1-I1 (scope no intersect) → TKT-B4 + TKT-B6
- N1-I2 (Files.Read fallback) → TKT-B4
- N1-I3 (discovery scope policy) → TKT-B8

### À arbitrer hors plan OAuth

- N1-I4 (README "encrypted file" vs `auth.ts` plaintext+0o600) : **soit** mettre à jour README pour parler honnêtement de "plaintext + 0o600 permissions", **soit** implémenter vrai chiffrement at-rest. **Recommandation** : mettre à jour README v0.1.1 patch (rapide, honnête), traiter chiffrement at-rest dans v0.3.

## Tag attendu

Après les 3 fixes intégrés : commit `fix(oauth+lib): cross-review N0 findings — userinfo, percent-encoded CRLF, IPv6 mapped`. Pas de tag (on continue Lot B).

Cross-review **finale** (E1+E2+E3) à lancer après TKT-B12 (E2E full flow) et TKT-C6 (headers sécurité). À ce moment-là : tag `v0.2.0-rc1` puis `v0.2.0` après ré-review fingerprint cache.

## Annexes

- Output complet N0 : agent task `a2be5fbdfa610a3eb`
- Output complet N1 : `/tmp/claude-1000/.../tasks/bmv8z1unr.txt` (avant ce cycle) + sortie courante dans le buffer codex
