# Modes d'exécution — matrice normative

**Date** : 2026-05-10
**Auteur** : Jimmy Blanquet
**Origine** : codex finding O2 — "le plan mélange stdio et HTTP sans expliciter le seuil de garanties sécurité"

`outlook-mcp-hardened` peut tourner dans trois modes mutuellement exclusifs, chacun avec ses préconditions bloquantes et son périmètre de sécurité. **Le binaire refuse de démarrer si une précondition obligatoire n'est pas remplie pour le mode demandé.**

## Synthèse

| Mode | Auth ingress | Auth egress (Graph) | Bind | TLS | OAuth AS | Rate-limit | Trust-proxy | Audit |
|---|---|---|---|---|---|---|---|---|
| **stdio** | aucune (transport stdin/stdout, client local) | MSAL device code | n/a | n/a | non | n/a | n/a | obligatoire |
| **http-loopback** | OAuth AS intégré JWT | MSAL device code | `127.0.0.1` strict | non | obligatoire | optionnel | non | obligatoire |
| **http-public** | OAuth AS intégré JWT | MSAL device code | `127.0.0.1` strict (TLS via reverse proxy) | délégué reverse proxy | obligatoire | obligatoire | obligatoire | obligatoire |

## Mode `stdio` (défaut, dev local + Claude Code stdio)

### Activation

```bash
outlook-mcp-hardened              # implicite, transport stdio
outlook-mcp-hardened --enable-send --enable-write
```

### Cas d'usage

- Claude Code en local (transport stdio, IPC sécurisé OS).
- Test manuel via `mcp-inspector`.
- Pas de réseau ingress du tout.

### Préconditions bloquantes (refus boot si non remplies)

- Aucune. Le mode stdio est le moins exigeant.

### Garanties

- **Pas d'auth ingress** : le client local a le même UID que le serveur, on assume confiance.
- **Egress strict** : `egress-guard.ts` actif (login.microsoftonline.com + graph.microsoft.com only).
- **Audit** : JSON stderr pour chaque appel Graph.
- **Anti-injection** : `<untrusted_content>` wrapper actif sur mail bodies.

### Hors garanties

- Pas de protection si le poste est compromis (file:// access, autre user UID).
- Pas de chiffrement at-rest des tokens MSAL (sauf si keytar disponible).

## Mode `http-loopback` (test OAuth local, CI E2E)

### Activation

```bash
outlook-mcp-hardened --http 127.0.0.1:3000
```

### Cas d'usage

- Tests d'intégration `MCPJam/inspector` ou reproduction Claude.ai flow en local.
- Pas exposé au LAN ni à Internet.

### Préconditions bloquantes (refus boot si non remplies)

- Bind address DOIT être `127.0.0.1` (literal, pas `localhost` ni `0.0.0.0`). Refus boot sinon.
- `OAUTH_TRUST_MODE` ∈ {`registered-only`, `registered-trusted-dcr`, `open-dcr`} — toutes valeurs OK en loopback.
- `JWT_PRIVATE_KEY_PASSPHRASE` env var présente (sinon refus boot).
- Fichier SQLite path writable (`OUTLOOK_MCP_DB_PATH` env, default `./outlook-mcp.sqlite`).

### Garanties

- OAuth AS intégré actif (DCR si activé, /authorize, /token, JWKS, consent).
- Audit OAuth events + audit Graph calls.
- Rate-limit IP optionnel (off par défaut en loopback car peu utile).

### Hors garanties

- Pas de TLS (loopback assumé local).
- `TRUSTED_PROXIES` n'est PAS lu (toujours `socket.remoteAddress` = `127.0.0.1`).
- Si l'host n'est pas single-user, n'importe quel local user peut hit `127.0.0.1:3000` — ce mode n'est pas adapté aux serveurs multi-user.

## Mode `http-public` (déploiement remote derrière reverse proxy)

### Activation

```bash
OUTLOOK_MCP_MODE=http-public outlook-mcp-hardened --http 127.0.0.1:3000
```

Le flag `OUTLOOK_MCP_MODE=http-public` active toutes les garde-fous renforcés.

### Cas d'usage

- Déploiement production souverain pour expo à Claude.ai (sur Internet).
- Derrière un reverse proxy (Caddy / nginx) qui termine TLS et propage `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`.

### Préconditions bloquantes (refus boot si non remplies)

- Bind address DOIT être `127.0.0.1` (literal). Si `0.0.0.0` → refus boot avec message explicite.
- `OUTLOOK_MCP_TRUSTED_PROXIES` env var DOIT être renseigné (au moins une IP, format `1.2.3.4,5.6.7.8` ou `127.0.0.1`).
- `OUTLOOK_MCP_PUBLIC_URL` env var DOIT être un `https://...` valide. Sera l'`issuer` JWT et le `resource_metadata.resource`.
- `OAUTH_TRUST_MODE` DOIT être ∈ {`registered-only`, `registered-trusted-dcr`}. Mode `open-dcr` → refus boot.
- Si `OAUTH_TRUST_MODE=registered-trusted-dcr`, alors `OAUTH_DCR_INITIAL_TOKEN` DOIT être présent (refus sinon).
- `JWT_PRIVATE_KEY_PASSPHRASE` env var présente.
- `OUTLOOK_MCP_DB_PATH` writable, mode WAL.
- Fichier `config/oauth-clients.json` présent et valide (parse OK, schéma OK).
- Vérification au boot : la conn SQLite peut `BEGIN IMMEDIATE` + `ROLLBACK` (test de write atomique).
- `NODE_ENV=production` (sinon warning au boot).

### Garanties

- OAuth AS intégré, exact-match redirect, scope intersection strict, refresh family rotation, JWT EdDSA figé.
- Trust-proxy model : XFF lu uniquement si peer IP ∈ `TRUSTED_PROXIES`. Algo :
  ```
  function resolveClientIp(req):
      peer = socket.remoteAddress
      if peer not in TRUSTED_PROXIES:
          return peer   # XFF ignoré, on refuse de faire confiance
      xff = req.headers['x-forwarded-for'] // case-insensitive
      if not xff:
          return peer
      # Strip whitespace, split by comma
      hops = [h.strip() for h in xff.split(",") if h.strip()]
      if not hops:
          return peer
      # Walk from rightmost backward, skipping every IP that is itself a trusted proxy
      for ip in reversed(hops):
          if ip not in TRUSTED_PROXIES:
              return ip
      # All hops are trusted proxies → fallback to leftmost (= original client per convention)
      return hops[0]
  ```
  → Résout simultanément le finding **codex I8** (XFF rightmost faux en général) ET le retour **mcp-vault v0.3.3 fix I2** (rightmost = vrai client si nginx append). La règle est : on ne fait confiance à un hop que s'il est dans la liste, et on s'arrête au premier hop non-trusted en partant de la droite.
- Rate-limit IP obligatoire (token bucket 100 req/min/IP, configurable via `OUTLOOK_MCP_RATELIMIT_PER_MIN`).
- Audit OAuth + Graph + rate-limit + reuse-detection events.
- Headers sécurité émis : `Strict-Transport-Security`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; ...`, `Referrer-Policy: no-referrer`.

### Préconditions infra (handoff au peer `infra`, hors scope outlook-mcp)

Documentées dans `docs/HANDOFF_INFRA.md` (à créer en lot C). Résumé :

- Reverse proxy termine TLS avec cert valide (Let's Encrypt).
- Reverse proxy injecte `X-Forwarded-For` avec **append** (config nginx `$proxy_add_x_forwarded_for`).
- IP du reverse proxy listée dans `OUTLOOK_MCP_TRUSTED_PROXIES`.
- Reverse proxy bloque `X-Forwarded-For` venant du client (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` ; pas de `$http_x_forwarded_for`).
- Service systemd durci (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, seccomp `@system-service`).
- Backups SQLite cohérents (snapshot avec `.backup` SQLite command ou pause writes).

## Diagramme décision boot

```
                ┌──────────────────────────┐
                │ Lecture flags + env vars │
                └────────────┬─────────────┘
                             │
                  ┌──────────▼──────────┐
                  │ --http <bind> set ? │
                  └─────┬─────────────┬─┘
                       NON           OUI
                        │             │
                ┌───────▼────┐  ┌─────▼─────────────────┐
                │ MODE=stdio │  │ bind == 127.0.0.1 ?   │
                └────────────┘  └───┬───────────────┬───┘
                                  NON              OUI
                                   │                │
                              ┌────▼──────┐  ┌──────▼────────────────────┐
                              │ EXIT 1    │  │ OUTLOOK_MCP_MODE=http-pub │
                              │ refus 0/0 │  │   set or required ?       │
                              └───────────┘  └──┬─────────────────────┬──┘
                                                NON                   OUI
                                                 │                    │
                                       ┌─────────▼──────┐ ┌───────────▼────────────────┐
                                       │ MODE=http-     │ │ Vérif: TRUSTED_PROXIES set?│
                                       │   loopback     │ │ PUBLIC_URL https?          │
                                       └────────────────┘ │ TRUST_MODE != open-dcr?    │
                                                          │ IAT si DCR ?               │
                                                          │ JWT passphrase ?           │
                                                          │ DB writable + BEGIN IMMED? │
                                                          └──┬─────────────────────┬───┘
                                                            NON                   OUI
                                                             │                    │
                                                       ┌─────▼─────┐    ┌─────────▼──────┐
                                                       │ EXIT 1    │    │ MODE=http-     │
                                                       │ message   │    │   public       │
                                                       │ exact     │    │ (start server) │
                                                       └───────────┘    └────────────────┘
```

## Tests régression

- `test_boot_refuses_0_0_0_0` — refus si bind 0.0.0.0
- `test_boot_refuses_open_dcr_in_public_mode` — refus mode open-dcr en http-public
- `test_boot_refuses_missing_trusted_proxies` — http-public sans TRUSTED_PROXIES
- `test_boot_refuses_http_public_url` — http-public avec PUBLIC_URL en http://
- `test_boot_refuses_db_not_writable` — DB en mode read-only
- `test_resolve_client_ip_*` — matrice nginx append/prepend, X-Forwarded-For spoofé, trusted proxies absents

## Versions supportées

| Mode | v0.1 (stdio uniquement) | v0.2 (cible) | v0.3+ |
|---|---|---|---|
| stdio | ✅ supporté | ✅ supporté | ✅ supporté |
| http-loopback | ❌ | ✅ planifié | ✅ |
| http-public | ❌ | ✅ planifié | ✅ |
