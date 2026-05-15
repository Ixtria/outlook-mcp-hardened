# Tickets — Lot B/C/D/E v0.2.0

> ⚠️ **POST-PIVOT Niveau B (2026-05-10, ADR-0003)** : la majorité du Lot B (TKT-B0..B12) est **DROP**. Reste applicable :
> - Lot A : ✅ tous terminés
> - Modules pures déjà commités (TKT-B3 partiel, TKT-B6 partiel via scope.ts, équivalent TKT-C2 via trust-proxy.ts) : ✅
> - **Nouveaux tickets actifs** : **T19** (wire 3 modules dans `oauth-provider.ts`) + **T20** (wire trust-proxy dans `request-context.ts`) + **T21** (cross-review finale)
> - Lot C boot guards : à reprendre mais sans préconditions AS intégré
> - Lot D audit : étendre `audit-logger.ts` avec events OAuth proxy minimum (verify_token_success/fail, scope_filtered, redirect_rejected)
> - Tag visé v0.2.0 : ~1 jour de travail restant
>
> Les tickets ci-dessous restent listés pour traçabilité, mais marqués DROP ou ADAPTÉ.

> Checklist atomique dérivée de MIGRATION-PLAN-FROM-MCP-VAULT.md v2. Chaque ticket = un commit (ou une PR si touche surface auth), avec tests TDD avant le code applicatif.

**Convention** : tickets référencés par leur ID dans les messages de commit (`feat(oauth/dcr): exact-match redirect uris [TKT-B3]`).

**Prérequis transverses** :
- `npm run verify` doit passer (lint + types + build + tests + coverage ≥80% sur les modules touchés).
- Cross-review obligatoire (N0+N1 minimum) avant merge si modif `src/oauth/`, `src/security/`, `src/request-context.ts`, `src/auth.ts`, `src/server.ts`.

---

## Lot A — Méthode & qualité ✅ quasi-fait

| ID | Subject | Statut | Critères acceptation |
|---|---|---|---|
| TKT-A1 | ADR-0001 cross-LLM review grid | ✅ | `docs/adr/0001-cross-llm-review-grid.md` présent, ≥3 sections |
| TKT-A2 | ADR-0002 OAuth trust policy & AS arch | ✅ | `docs/adr/0002-*.md` présent ; trois options évaluées ; D1-D6 normatifs |
| TKT-A3 | CHANGELOG keepachangelog | ✅ | Section Unreleased pour v0.2.0 ; pas de backfill |
| TKT-A4 | SECURITY.md durci | ✅ | Threat model linké ; cross-review section ; hors scope explicite |
| TKT-A5 | THREAT-MODEL OAuth AS | ✅ | STRIDE par surface ; politiques recovery R1-R4 |
| TKT-A6 | MODES.md matrice exécution | ✅ | Trois modes ; préconditions bloquantes ; algo trust-proxy |
| TKT-A7 | SPECS-OAUTH-MCP.md v2 | ✅ | 13 findings codex tracés §17 |
| TKT-A8 | Templates ADR + plans | ✅ | `docs/adr/TEMPLATE.md` + `docs/plans/TEMPLATE.md` |
| **TKT-A9** | Quality gate husky + coverage ≥80% | ⏳ | `.husky/pre-commit` ; `vitest.config.ts` thresholds ; `npm run verify` enforce |

---

## Lot B (post-pivot Niveau B) — wiring chirurgical

| ID | Subject | Statut | Note |
|---|---|---|---|
| **T19** | Wire `validateRedirectUri` + `intersectScopes` dans `MicrosoftOAuthProvider.getClient` / `server.ts /authorize` | 🔧 actif | ~30 LOC + tests |
| **T20** | Wire `resolveClientIp` dans `request-context.ts`, remplacer `app.set('trust proxy', true)` global | 🔧 actif | ~30 LOC + tests |
| **T21** | Cross-review finale N0+N1 sur diff Niveau B | ⏳ post T19+T20 | bloque tag v0.2.0 |

### Lot B legacy (DROP per ADR-0003)

| ID | Subject | Dépend | Test régression clé |
|---|---|---|---|
| **TKT-B0** | Setup `src/oauth/` skeleton + deps (`jose`, `better-sqlite3`, `eta`, `@node-rs/bcrypt`) | TKT-A9 | `import * as oauth from './oauth'` compile |
| **TKT-B1** | `src/oauth/storage.ts` schéma + migrations + helpers atomiques | B0 | `test_storage_begin_immediate_atomic`, `test_storage_unique_jti` |
| **TKT-B2** | `src/oauth/key-manager.ts` Ed25519 + AES-256-GCM + rotation grace 7j | B0 | `test_keys_rotation_grace_period`, `test_keys_retired_invalid` |
| **TKT-B3** | `src/oauth/dcr.ts` registered-only / trusted-dcr / open-dcr + IAT + exact-match | B1 | `test_dcr_rejects_wildcard_redirect`, `test_dcr_rejects_trailing_newline`, `test_dcr_iat_required_in_trusted_mode`, `test_dcr_disabled_in_registered_only` |
| **TKT-B4** | `src/oauth/authorize.ts` flow + erreur locale pré-validation + auth_requests | B1, B3 | `test_authorize_local_error_if_client_unknown`, `test_authorize_local_error_if_redirect_mismatch`, `test_authorize_redirects_error_only_post_validation`, `test_authorize_scope_intersection`, `test_authorize_rejects_plain_pkce` |
| **TKT-B5** | `src/oauth/consent.ts` template eta + CSRF + session cookie + CSP | B4 | `test_consent_rejects_missing_csrf`, `test_consent_rejects_session_mismatch`, `test_consent_emits_frame_ancestors_none` |
| **TKT-B6** | `src/oauth/token.ts` code grant atomic + refresh family + reuse detection | B1, B2 | `test_token_code_replay_rejected`, `test_token_code_verifier_mismatch`, `test_token_resource_mismatch`, `test_token_refresh_reuse_revokes_family`, `test_token_refresh_rotation_new_jti` |
| **TKT-B7** | `src/oauth/verifier.ts` alg figé + kid strict + aud RFC 8707 | B2 | `test_verifier_rejects_non_eddsa`, `test_verifier_rejects_unknown_kid`, `test_verifier_rejects_aud_wrong`, `test_verifier_rejects_iss_wrong` |
| **TKT-B8** | `src/oauth/discovery.ts` well-known + jwks.json | B2 | `test_discovery_resource_indicators_supported_true`, `test_discovery_omits_registration_endpoint_in_registered_only` |
| **TKT-B9** | `src/oauth/token-exchange.ts` mapping outlook_sub → MSAL | B6, src/auth.ts | `test_token_exchange_rejects_unknown_sub`, `test_token_exchange_msal_account_isolation` |
| **TKT-B10** | `src/oauth/admin-cli.ts` issue-iat / revoke-refresh / rotate-jwt-key / post-restore-cleanup | B1, B2, B6 | `test_admin_issue_iat_creates_row`, `test_admin_revoke_refresh_by_jti`, `test_admin_post_restore_cleanup_truncates_codes_and_refresh` |
| **TKT-B11** | Suppression `src/oauth-provider.ts` legacy + wiring nouveau dans `src/server.ts` | B7, B8, B9 | `test_server_routes_authorize_to_new_as` ; tests E2E (cf. TKT-B12) |
| **TKT-B12** | E2E full flow supertest + MCPJam (CI) | B11 | `test_e2e_full_oauth_flow_then_mcp_call`, `test_e2e_refresh_then_reuse_detected` |

---

## Lot C — Mode http-public durci

| ID | Subject | Dépend | Test régression clé |
|---|---|---|---|
| **TKT-C1** | `src/rate-limit.ts` token-bucket per-IP, persistance SQLite, multi-bucket | B1 | `test_ratelimit_per_ip_not_per_token`, `test_ratelimit_bucket_separation`, `test_ratelimit_persistence_across_restart` |
| **TKT-C2** | `src/request-context.ts` étendu — `clientIp` resolved via trust-proxy | C1 | `test_trustproxy_ignores_xff_if_peer_untrusted`, `test_trustproxy_walks_right_to_left_skipping_trusted`, `test_trustproxy_nginx_append`, `test_trustproxy_nginx_prepend`, `test_trustproxy_spoofed_xff` |
| **TKT-C3** | Boot guards — refus 0.0.0.0, refus open-dcr en http-public, vérif TRUSTED_PROXIES | C2 | `test_boot_refuses_0_0_0_0`, `test_boot_refuses_open_dcr_in_http_public`, `test_boot_refuses_missing_trusted_proxies`, `test_boot_refuses_http_public_url` |
| **TKT-C4** | `deploy/outlook-mcp.service` systemd durci | C3 | smoke test manuel (lot infra) |
| **TKT-C5** | `docs/HANDOFF_INFRA.md` | C4 | review humaine (peer infra) |
| **TKT-C6** | Headers sécurité globaux (HSTS, X-Frame-Options, CSP) | B11 | `test_headers_hsts_present`, `test_headers_csp_default_src_none` |

---

## Lot D — Audit / observabilité

| ID | Subject | Dépend | Test régression clé |
|---|---|---|---|
| **TKT-D1** | `src/security/audit-logger.ts` étendu — events OAuth complets | B7 | `test_audit_event_oauth_register_emitted`, `test_audit_event_refresh_reuse_alert`, `test_audit_event_egress_violation_alert` |
| **TKT-D2** | `__tests__/no-secret-in-logs.test.ts` anti-fuite | D1 | `test_no_jwt_in_logs`, `test_no_bearer_in_logs`, `test_no_client_secret_in_logs`, `test_no_msal_token_in_logs` |
| **TKT-D3** | `docs/AUDIT_EVENTS.md` référentiel | D1 | review humaine, doc complète SPECS §14 |

---

## Lot E — Cross-review finale + release v0.2.0

| ID | Subject | Dépend | Critère acceptation |
|---|---|---|---|
| **TKT-E1** | `/pf-cross-review HEAD~N..HEAD` (range Lots B+C+D) | B12, C6, D3 | Rapport `docs/plans/2026-XX-XX-cross-review-outlook-v0.2.0.md` ; 0 BLOCKER restant |
| **TKT-E2** | N3 peer mcp-vault via bus agent-hub | E1 | Réponse JSON structurée, intégrée au rapport |
| **TKT-E3** | Fix findings BLOCKER + ≥80% des IMPORTANT, ré-review fingerprint cache | E1, E2 | Tag candidat `v0.2.0-rc1` |
| **TKT-E4** | CHANGELOG section [0.2.0] (déplacer depuis Unreleased) + tag annoté + push | E3 | `git tag -a v0.2.0` + GH release notes auto |

---

## Critères généraux de "Done" par ticket

1. Code écrit en TS strict (`"strict": true`, `"noUncheckedIndexedAccess": true`).
2. Tests TDD : test rouge AVANT le code, test vert APRÈS, coverage du module ≥80%.
3. `npm run verify` PASS.
4. Pas de commentaire `// TODO:`/`// FIXME:` sans ticket associé.
5. Commit message : `type(scope): description [TKT-XX]`.
6. Si touche surface auth/sécu : ADR-0001 cross-review N0 minimum AVANT merge.

---

## Risques / blocages connus

- **R-B6** : refresh family reuse detection peut faux-positiver si client rejoue par bug réseau (timeout retry). Mitigation : grace window 5s, audit warn-only first occurrence, alert second.
- **R-B11** : suppression `src/oauth-provider.ts` legacy peut casser tests v0.1 existants. Mitigation : checker `__tests__/graph-tools.test.ts` ne dépend pas du provider auth.
- **R-C3** : boot guards peuvent bloquer dev local si env vars manquantes. Mitigation : messages d'erreur explicites + section "Quickstart dev local" dans README.
- **R-E2** : N3 mcp-vault peut être timeout 300s. Mitigation : passer en async (`peer-ask-async.sh`) si gros range.

---

*Last update : 2026-05-10. Mettre à jour à chaque clôture de ticket.*
