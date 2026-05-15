# Specs — Remote MCP Server + OAuth 2.1 intégré (TypeScript / Node 20)

> **Version** : v2 — révision post cross-review (codex 13 findings + mcp-vault peer + ADR-0002)
> **Date** : 2026-05-10
> **Scope** : AS intégré côté ingress (Claude.ai) + RS validation, avec token-exchange interne vers MSAL device code côté egress (Graph). Applicable au mode `http-public` (cf. [`docs/MODES.md`](docs/MODES.md)).

---

## 1. Décisions verrouillées

Voir [`docs/adr/0002-oauth-trust-policy-and-as-architecture.md`](docs/adr/0002-oauth-trust-policy-and-as-architecture.md) pour le détail. Synthèse :

| # | Décision | Raison |
|---|---|---|
| D1 | **SDK MCP officiel TypeScript** (`@modelcontextprotocol/sdk` ≥1.29) — **pas** FastMCP | Code déjà sur ce SDK, FastMCP côté Python uniquement, OAuth proxy FastMCP a advisory RFC 8707 ouverte |
| D2 | **AS intégré côté ingress** (RFC 8693 token-exchange interne) — `src/oauth-provider.ts` legacy remplacé | Conformité RFC 8707, indépendance roadmap AAD, audit clair |
| D3 | **MSAL device code conservé côté egress** | Déjà éprouvé, multi-account géré, scope du fork |
| D4 | **`OAUTH_TRUST_MODE=registered-only`** par défaut, DCR désactivé | Codex B2 fix : pas d'enrollment ouvert |
| D5 | **`redirect_uri` exact-match `===`** après normalisation, **aucun wildcard** | Codex B1 fix |
| D6 | **`alg=EdDSA` figé** (Ed25519) | Codex I7 fix : pas de confusion `alg`, simplicité crypto |
| D7 | **`lib jose`** (panva/jose, MIT) pour JOSE TS | Lib mature, audit-friendly, peu de transitives |
| D8 | **SQLite** via `better-sqlite3` (sync, WAL) | Pattern aligné mcp-vault, transactions atomiques natives |
| D9 | **Endpoints à la racine** (`/authorize`, `/token`, `/register`, `/jwks.json`, `/.well-known/*`) | Workaround bug Claude.ai #82 |
| D10 | **Zéro télémétrie**, allowlist egress hardcodée inchangée | Principe fondateur fork |

---

## 2. Stack

```
Runtime         : Node.js 20 LTS
MCP SDK         : @modelcontextprotocol/sdk ^1.29
JOSE            : jose ^5 (panva/jose, MIT)
HTTP            : Streamable HTTP du SDK MCP (Node http + transport)
SQLite          : better-sqlite3 ^11 (sync API, WAL)
Bcrypt          : @node-rs/bcrypt ^1.10 (pour IAT hashing — pas pour user passwords)
HTML templating : eta ^3 (lightweight, safe-by-default escaping) pour consent page
Tests           : vitest ^2 + supertest pour HTTP intégration
Lint            : eslint + @typescript-eslint strict
```

**Interdit (rappel)** : axios, node-fetch, express (le SDK MCP fournit son propre serveur HTTP), Sentry, toute lib avec phone-home, FastMCP (Python only).

---

## 3. Architecture

```
                                 ┌─────────────────────────────────────────────┐
                                 │  src/oauth/                                  │
   Claude.ai (public client) ───▶│  as-server.ts   (router HTTP)               │
                                 │  ├─ dcr.ts            (POST /register)      │
                                 │  ├─ authorize.ts      (GET/POST /authorize) │
                                 │  ├─ token.ts          (POST /token)         │
                                 │  ├─ jwks.ts           (GET /jwks.json)      │
                                 │  ├─ discovery.ts      (well-known)          │
                                 │  ├─ consent.ts        (HTML + CSRF)         │
                                 │  ├─ verifier.ts       (Bearer middleware)   │
                                 │  ├─ key-manager.ts    (JWKS + rotation)     │
                                 │  └─ storage.ts        (SQLite, transactions)│
                                 │                                              │
   /mcp + Bearer JWT outlook ───▶│  src/server.ts (mcp router) ──┐             │
                                 │                                │             │
                                 │  src/oauth/token-exchange.ts ◀─┘             │
                                 │  ├─ map outlook_sub → MSAL account           │
                                 │  └─ src/auth.ts (MSAL device, INCHANGÉ)     │
                                 │                                              │
                                 │  src/graph-client.ts (INCHANGÉ + audit)     │──▶ graph.microsoft.com
                                 │  src/security/egress-guard.ts (INCHANGÉ)    │
                                 │  src/security/audit-logger.ts (étendu OAuth)│
                                 │                                              │
                                 │  SQLite (outlook-mcp.sqlite)                 │
                                 │  ├─ oauth_clients (registered + DCR)         │
                                 │  ├─ initial_access_tokens (IAT)              │
                                 │  ├─ auth_codes                               │
                                 │  ├─ refresh_tokens (avec family_id)          │
                                 │  ├─ jwks_keys                                │
                                 │  ├─ user_account_mapping                     │
                                 │  └─ rate_limit_buckets                       │
                                 └─────────────────────────────────────────────┘
```

---

## 4. Endpoints publics

Tous à la racine du domaine MCP (`https://mcp.example.com/`).

| Méthode | Path | RFC | Activation |
|---|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | 8414 | Toujours |
| GET | `/.well-known/oauth-protected-resource` | 9728 | Toujours |
| POST | `/register` | 7591 | Si `OAUTH_TRUST_MODE != registered-only` |
| GET | `/authorize` | 6749 + 7636 | Toujours (mode http-*) |
| POST | `/authorize/consent` | n/a | Toujours |
| POST | `/token` | 6749 + 8707 | Toujours |
| GET | `/jwks.json` | 7517 | Toujours |
| POST | `/mcp` | MCP spec | Toujours (Bearer-protégé) |

---

## 5. `/register` — DCR (RFC 7591)

### Activation

L'endpoint **n'existe pas** (404) si `OAUTH_TRUST_MODE=registered-only`.

### Pré-conditions (mode `registered-trusted-dcr`)

- Header `Authorization: Bearer <IAT>` obligatoire ; IAT validé contre table `initial_access_tokens` (hash bcrypt, lookup constant-time). Sinon `403`.
- Le `client_name` du body DOIT être dans `OAUTH_DCR_TRUSTED_CLIENTS` (env var, JSON map).
- Tous les `redirect_uris` du body DOIVENT être dans l'allowlist du `client_name` correspondant.

### Validation `redirect_uri` (fix codex B1, fullmatch hygiène mcp-vault v0.3.4)

```typescript
function validateRedirectUri(uri: string, allowlist: ReadonlySet<string>): boolean {
  // 1. Reject trailing whitespace / newlines / null bytes
  if (/[\s\x00]/.test(uri)) return false;
  // 2. Reject percent-encoded slashes/backslashes (response-splitting)
  if (/%2F|%5C|%00/i.test(uri)) return false;
  // 3. Parse URL, reject if invalid or non-https
  let url: URL;
  try { url = new URL(uri); } catch { return false; }
  if (url.protocol !== 'https:') return false;
  // 4. Normalize: lowercase scheme + host, path as-is (case-sensitive)
  const normalized = `${url.protocol}//${url.host.toLowerCase()}${url.pathname}${url.search}${url.hash}`;
  // 5. EXACT-MATCH against allowlist
  return allowlist.has(normalized);
}
```

### Request (Claude.ai)

```json
{
  "redirect_uris": [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback"
  ],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_name": "claude",
  "scope": "mcp:read"
}
```

### Response

`201 Created` avec metadata enrichie : `client_id` (UUIDv4), `client_id_issued_at`.

### Persistence

```sql
INSERT INTO oauth_clients (client_id, client_name, redirect_uris_json, scope, token_endpoint_auth_method, registered_via, created_at)
VALUES (?, ?, ?, ?, ?, 'dcr', ?);
```

### Rate-limit

10 tentatives `/register` par IP par heure (token-bucket in-memory + persistant SQLite pour survie redémarrage). Au-delà : `429`.

### Audit

`oauth.register` event : `client_id`, `client_name`, `redirect_uris_hash` (SHA-256 du JSON.stringify trié), `iat_label`, `ip_hash`, `status`.

---

## 6. `/authorize` — Authorization endpoint

### Query params requis

- `response_type=code`
- `client_id` (lookup en SQLite, sinon erreur LOCALE non redirigée — fix codex I2)
- `redirect_uri` (compare `===` contre `redirect_uris` du client, sinon erreur LOCALE)
- `code_challenge` + `code_challenge_method=S256` (refus `plain`)
- `state` (opaque, propagé tel quel)
- `scope` (peut être absent ; sera intersecté)
- `resource` **obligatoire** = `<PUBLIC_URL>/mcp` strict (RFC 8707)

### Flow (fix codex I2 + I3)

```
1. Parse params.
2. Lookup client_id.
   - Si absent: render page locale erreur. STOP. Pas de redirect.
3. Validate redirect_uri == registered (exact-match).
   - Si non: render page locale erreur. STOP.
4. À partir d'ici, toute erreur peut redirect vers redirect_uri.
5. Validate code_challenge, S256, scope syntax, resource.
   - Erreur: 302 vers redirect_uri?error=<err>&state=<state>
6. Intersect effective_scope = requested ∩ registered ∩ KNOWN.
   - Si vide: 302 invalid_scope.
7. Si user non authentifié → redirect vers /login?continue=<auth_request_id>.
8. Sinon: générer auth_request_id (32 bytes urlsafe), stocker en SQLite avec TTL 5min:
     {auth_request_id, client_id, user_id, redirect_uri, code_challenge, scope (effective), resource, state, csrf_token}
9. Render page consent avec:
     - cookie session HttpOnly; Secure; SameSite=Strict
     - hidden input csrf_token
     - form action=POST /authorize/consent
     - CSP: default-src 'self'; script-src 'none'; frame-ancestors 'none'
     - X-Frame-Options: DENY
```

### `POST /authorize/consent`

Body form-encoded : `auth_request_id`, `csrf_token`, `decision` (allow/deny).

Validation :
- Session cookie présente + `session.user_id == auth_request.user_id` (fix codex I3).
- CSRF token `===` celui stocké en SQLite (constant-time compare).
- `decision == allow` → générer `code` (32 bytes urlsafe), TTL 60s, insert atomique :
  ```sql
  BEGIN IMMEDIATE;
  INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, code_challenge, scope, resource, expires_at, used)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0);
  COMMIT;
  ```
- Audit `oauth.authorize.consent` : `client_id`, `user_id_hash`, `scope`, `resource`, `decision`, `ip_hash`.
- 302 vers `redirect_uri?code=<code>&state=<state>`.
- `decision == deny` → 302 `redirect_uri?error=access_denied&state=<state>`.

### Page consent — structure HTML

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Authorize <%= clientName %></title>
  <style>/* minimal inline, no external resources */</style>
</head>
<body>
  <h1>Authorize <%= clientName %>?</h1>
  <p><%= clientName %> wants to access:</p>
  <ul>
    <% scopeList.forEach(s => { %>
      <li><code><%= s %></code> — <%= scopeDescriptions[s] %></li>
    <% }); %>
  </ul>
  <p>You are signed in as <strong><%= userEmailMasked %></strong>.</p>
  <form action="/authorize/consent" method="POST">
    <input type="hidden" name="auth_request_id" value="<%= authRequestId %>">
    <input type="hidden" name="csrf_token" value="<%= csrfToken %>">
    <button type="submit" name="decision" value="allow">Authorize</button>
    <button type="submit" name="decision" value="deny">Deny</button>
  </form>
</body>
</html>
```

### Auth utilisateur (hors scope de cette spec — futur lot)

Pour v0.2, l'authentification utilisateur primaire est **session admin** (un seul utilisateur, le propriétaire du serveur) — équivalent au pattern mcp-vault Bearer multi-token mais une seule identité. Login via password admin + cookie session.

Multi-utilisateur reporté v0.3.

---

## 7. `/token` — Token endpoint (RFC 6749 + 8707)

### Grant `authorization_code`

Body form-encoded :
- `grant_type=authorization_code`
- `code`, `redirect_uri`, `client_id`, `code_verifier`
- `resource` (obligatoire, DOIT matcher celui stocké au `/authorize` — RFC 8707 strict)

### Validation atomique (fix codex I4)

```typescript
const result = db.prepare(`
  BEGIN IMMEDIATE;
  UPDATE auth_codes
    SET used = 1
    WHERE code = ?
      AND used = 0
      AND expires_at > ?
  RETURNING client_id, user_id, redirect_uri, code_challenge, scope, resource;
`).get(code, now());
if (!result) throw oauthError('invalid_grant');
```

Puis valider en mémoire :
- `result.redirect_uri == request.redirect_uri` (constant-time)
- `result.client_id == request.client_id`
- `sha256(code_verifier).base64url() == result.code_challenge`
- `result.resource == request.resource`

### JWT access_token claims

```json
{
  "iss": "https://<PUBLIC_URL>",
  "sub": "<user_id>",
  "aud": "https://<PUBLIC_URL>/mcp",
  "exp": <iat + 3600>,
  "iat": <now>,
  "nbf": <now>,
  "jti": "<uuidv4>",
  "scope": "<effective_scope>",
  "client_id": "<client_id>",
  "client_name": "<client_name>"
}
```

Signé EdDSA (Ed25519) avec la clé active courante (`kid` du header JWT).

### Refresh token (fix codex I5 — token family + reuse detection)

Génération :
- `refresh_token` = 32 bytes urlsafe (string opaque)
- `family_id` = UUIDv4 (créé à la première authorization, propagé sur toutes les rotations)
- `parent_token_hash` = SHA-256 du parent (null pour le premier)
- Insert atomique :
  ```sql
  BEGIN IMMEDIATE;
  INSERT INTO refresh_tokens (token_hash, family_id, parent_token_hash, client_id, user_id, scope, resource, issued_at, expires_at, revoked)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0);
  COMMIT;
  ```

### Grant `refresh_token`

```typescript
function refreshFlow(presented: string) {
  const tokenHash = sha256(presented);
  // Atomic rotation
  const row = db.prepare(`
    BEGIN IMMEDIATE;
    UPDATE refresh_tokens
      SET revoked = 1
      WHERE token_hash = ?
        AND revoked = 0
        AND expires_at > ?
    RETURNING family_id, client_id, user_id, scope, resource;
  `).get(tokenHash, now());
  if (!row) {
    // Possible reuse: was this token ever issued in any family?
    const reused = db.prepare(`SELECT family_id FROM refresh_tokens WHERE token_hash = ?`).get(tokenHash);
    if (reused) {
      auditLog({ event: 'oauth.refresh.reuse_detected', family_id: reused.family_id });
      revokeFamily(reused.family_id);
      throw oauthError('invalid_grant', 'Refresh token reuse detected, family revoked');
    }
    throw oauthError('invalid_grant');
  }
  // Issue new refresh + new access in the same family
  const newRefresh = generateRefresh();
  insertRefresh({ family_id: row.family_id, parent: tokenHash, ... });
  return { access_token: issueAccess(row), refresh_token: newRefresh, ... };
}
```

### Audit

- `oauth.token.issued` : `client_id`, `jti`, `aud`, `scope`, `resource`, `user_id_hash`, `via` ∈ {`code`, `refresh`}
- `oauth.refresh.reuse_detected` : ALERT, `family_id`, `user_id_hash`, `ip_hash`
- `oauth.token.error` : `error_code`, `client_id`, `reason`, `ip_hash`

---

## 8. Resource Server — validation JWT sur `/mcp` (RFC 9728)

### Middleware

1. Extraire `Authorization: Bearer <jwt>`.
2. Si absent → `401` avec header :
   ```
   WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://<PUBLIC_URL>/.well-known/oauth-protected-resource"
   ```
3. Parse JWT header — refus si `alg != EdDSA` (fix codex I7).
4. Lookup `kid` strict dans cache JWKS local. Pas de fallback "essaie toutes". Si inconnu → `401`.
5. Verify signature avec la clé du `kid`.
6. Verify claims : `iss == PUBLIC_URL`, `aud == PUBLIC_URL/mcp`, `exp > now`, `nbf <= now`, `iat <= now + 60s` (clock skew).
7. Inject `{user_id, scope, client_id, jti}` dans `RequestContext`.
8. Audit event `mcp.auth.verified` à chaque appel — minimal, juste pour traçabilité.

### Implémentation TS (target)

```typescript
import { jwtVerify, importJWK } from 'jose';

export async function verifyAccessToken(token: string): Promise<TokenClaims> {
  const protectedHeader = decodeProtectedHeader(token);
  if (protectedHeader.alg !== 'EdDSA') {
    throw new UnauthorizedError('alg_not_allowed');
  }
  const kid = protectedHeader.kid;
  if (!kid) throw new UnauthorizedError('kid_missing');
  const key = await keyManager.getPublicKey(kid);
  if (!key) throw new UnauthorizedError('kid_unknown');
  const { payload } = await jwtVerify(token, key, {
    algorithms: ['EdDSA'],
    issuer: PUBLIC_URL,
    audience: `${PUBLIC_URL}/mcp`,
    clockTolerance: 60,
  });
  return payload as TokenClaims;
}
```

---

## 9. JWKS — Key management & rotation

### Génération initiale (boot)

Au premier boot, si `jwks_keys` est vide :
- Générer paire Ed25519 (jose `generateKeyPair('EdDSA')`).
- Sérialiser private en PEM, chiffrer AES-256-GCM (passphrase `JWT_PRIVATE_KEY_PASSPHRASE`).
- Insert : `kid=uuidv4()`, `alg='EdDSA'`, `public_jwk=...`, `private_pem_enc=...`, `created_at=now`, `active=1`.

### Rotation

Commande CLI : `outlook-mcp admin rotate-jwt-key`.

- Génère une nouvelle paire, `active=1`.
- Marque l'ancienne `active=0` mais ne la `retired_at` PAS (grace period).
- 7 jours plus tard (cron ou check au boot), `retired_at = now` sur l'ancienne ; elle disparaît de JWKS publique mais reste dans `jwks_keys` 30j pour audit historique.

### `/jwks.json`

```json
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "x": "...", "kid": "<uuid>", "use": "sig", "alg": "EdDSA" }
  ]
}
```

Inclut toutes les clés `retired_at IS NULL`.

### Audit

- `oauth.jwks.rotated` : `old_kid`, `new_kid`, `via` ∈ {`cli`, `auto`}.
- `oauth.jwks.retired` : `kid`.
- `oauth.jwks.rotation_failed` : ALERT, `error`, `stack`.

---

## 10. Schéma SQLite

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE oauth_clients (
  client_id                    TEXT PRIMARY KEY,
  client_name                  TEXT NOT NULL,
  redirect_uris_json           TEXT NOT NULL,
  scope                        TEXT NOT NULL,
  token_endpoint_auth_method   TEXT NOT NULL,
  registered_via               TEXT NOT NULL CHECK (registered_via IN ('static','dcr')),
  created_at                   INTEGER NOT NULL,
  last_used_at                 INTEGER
);

CREATE TABLE initial_access_tokens (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  label          TEXT NOT NULL UNIQUE,
  token_hash     TEXT NOT NULL,
  client_name    TEXT,
  created_at     INTEGER NOT NULL,
  used_at        INTEGER,
  revoked        INTEGER DEFAULT 0
);

CREATE TABLE auth_requests (
  auth_request_id  TEXT PRIMARY KEY,
  client_id        TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  redirect_uri     TEXT NOT NULL,
  code_challenge   TEXT NOT NULL,
  scope            TEXT NOT NULL,
  resource         TEXT NOT NULL,
  state            TEXT NOT NULL,
  csrf_token       TEXT NOT NULL,
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  consumed         INTEGER DEFAULT 0,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)
);

CREATE TABLE auth_codes (
  code             TEXT PRIMARY KEY,
  client_id        TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  redirect_uri     TEXT NOT NULL,
  code_challenge   TEXT NOT NULL,
  scope            TEXT NOT NULL,
  resource         TEXT NOT NULL,
  expires_at       INTEGER NOT NULL,
  used             INTEGER DEFAULT 0
);
CREATE INDEX idx_auth_codes_cleanup ON auth_codes(expires_at);

CREATE TABLE refresh_tokens (
  token_hash         TEXT PRIMARY KEY,
  family_id          TEXT NOT NULL,
  parent_token_hash  TEXT,
  client_id          TEXT NOT NULL,
  user_id            TEXT NOT NULL,
  scope              TEXT NOT NULL,
  resource           TEXT NOT NULL,
  issued_at          INTEGER NOT NULL,
  expires_at         INTEGER NOT NULL,
  revoked            INTEGER DEFAULT 0
);
CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_cleanup ON refresh_tokens(expires_at);

CREATE TABLE jwks_keys (
  kid              TEXT PRIMARY KEY,
  alg              TEXT NOT NULL CHECK (alg = 'EdDSA'),
  public_jwk       TEXT NOT NULL,
  private_pem_enc  BLOB NOT NULL,
  active           INTEGER NOT NULL DEFAULT 1,
  created_at       INTEGER NOT NULL,
  rotated_at       INTEGER,
  retired_at       INTEGER
);

CREATE TABLE user_account_mapping (
  outlook_user_id   TEXT PRIMARY KEY,
  msal_home_account TEXT NOT NULL,
  email_hash        TEXT NOT NULL,
  created_at        INTEGER NOT NULL
);

CREATE TABLE rate_limit_buckets (
  bucket_key       TEXT PRIMARY KEY,
  tokens           REAL NOT NULL,
  last_refill      INTEGER NOT NULL
);
```

---

## 11. Rate-limit (mode `http-public`)

Token-bucket in-memory + persistance SQLite pour survie redémarrage.

Buckets distincts :
- `register:ip:<ip_hash>` — 10/h (DCR)
- `authorize:ip:<ip_hash>` — 100/min
- `token:ip:<ip_hash>` — 100/min
- `mcp:ip:<ip_hash>` — `OUTLOOK_MCP_RATELIMIT_PER_MIN` (default 100)/min

Clé toujours **IP**, jamais token (anti-bypass par rotation Bearer, fix mcp-vault v0.3.3 I1).

---

## 12. Trust-proxy model (fix codex I8 + arbitrage mcp-vault I2)

Voir [`docs/MODES.md`](docs/MODES.md) section "Mode http-public". Algo :

```typescript
function resolveClientIp(socketIp: string, xff: string | undefined, trustedProxies: ReadonlySet<string>): string {
  if (!trustedProxies.has(socketIp)) return socketIp;     // peer non trusted → ignore XFF
  if (!xff) return socketIp;
  const hops = xff.split(',').map(h => h.trim()).filter(Boolean);
  if (hops.length === 0) return socketIp;
  for (let i = hops.length - 1; i >= 0; i--) {
    if (!trustedProxies.has(hops[i])) return hops[i];     // premier non-trusted en partant de droite
  }
  return hops[0];                                          // tous trusted → leftmost convention
}
```

Tests régression couvrant : nginx prepend, nginx append, XFF spoofé par client direct, chain de 3 proxies trusted, etc.

---

## 13. Discovery metadata

### `/.well-known/oauth-authorization-server` (RFC 8414)

```json
{
  "issuer": "<PUBLIC_URL>",
  "authorization_endpoint": "<PUBLIC_URL>/authorize",
  "token_endpoint": "<PUBLIC_URL>/token",
  "registration_endpoint": "<PUBLIC_URL>/register",
  "jwks_uri": "<PUBLIC_URL>/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "scopes_supported": ["mcp:read"],
  "resource_indicators_supported": true
}
```

Le champ `registration_endpoint` est OMIS si `OAUTH_TRUST_MODE=registered-only`.

### `/.well-known/oauth-protected-resource` (RFC 9728)

```json
{
  "resource": "<PUBLIC_URL>/mcp",
  "authorization_servers": ["<PUBLIC_URL>"],
  "scopes_supported": ["mcp:read"],
  "bearer_methods_supported": ["header"]
}
```

---

## 14. Audit events — schéma complet

| Event | Severity | Fields |
|---|---|---|
| `oauth.register` | info | client_id, client_name, redirect_uris_hash, iat_label, ip_hash, status |
| `oauth.register.rejected` | warn | reason, client_name, ip_hash |
| `oauth.authorize.start` | info | client_id, user_id_hash, ip_hash |
| `oauth.authorize.consent` | info | client_id, user_id_hash, scope, resource, decision, ip_hash |
| `oauth.authorize.rejected` | warn | reason, client_id, ip_hash |
| `oauth.token.issued` | info | client_id, jti, aud, scope, resource, user_id_hash, via |
| `oauth.token.error` | warn | error_code, client_id, reason, ip_hash |
| `oauth.refresh.reuse_detected` | **alert** | family_id, user_id_hash, ip_hash |
| `oauth.jwks.rotated` | info | old_kid, new_kid, via |
| `oauth.jwks.retired` | info | kid |
| `oauth.jwks.rotation_failed` | **alert** | error, stack |
| `mcp.auth.verified` | debug | client_id, user_id_hash, jti |
| `mcp.auth.failed` | warn | reason, ip_hash |
| `mcp.tool.invoked` | info | tool, scope, account_hash, status, duration_ms |
| `ratelimit.exceeded` | warn | bucket, ip_hash |
| `egress.violation` | **alert** | hostname, url, reason |

Pas de PII en clair. Tous les `*_hash` = SHA-256.

---

## 15. Tests — TDD obligatoire (target coverage ≥80%)

### Modules sensibles

| Module | Test min |
|---|---|
| `src/oauth/dcr.ts` | rejette wildcard, rejette trailing `\n`, rejette IAT absent, rate-limit, audit présent |
| `src/oauth/authorize.ts` | redirect_uri exact-match, erreur LOCALE si client_id invalide, scope intersection, CSRF token, S256 only, resource obligatoire |
| `src/oauth/token.ts` | consommation atomique du code, replay rejeté, code_verifier mismatch, refresh family reuse detection, resource mismatch |
| `src/oauth/verifier.ts` | alg figé, kid inconnu, aud wrong, iss wrong, exp past |
| `src/oauth/key-manager.ts` | rotation grace period, retired key invalide, signature pendant rotation |
| `src/oauth/storage.ts` | BEGIN IMMEDIATE atomicity, transactions concurrent reads |
| `src/request-context.ts` | trusted-proxy matrice (nginx prepend/append/spoofed) |
| `src/security/egress-guard.ts` | déjà couvert v0.1 |
| `src/security/audit-logger.ts` | pas de PII en clair, pas de JWT/Bearer fuité |

### Tests E2E

Reproduction du flow Claude.ai via `supertest` + `MCPJam/inspector` :
1. GET discovery → endpoints corrects
2. POST /register (mode DCR) avec IAT
3. GET /authorize + consent flow → code
4. POST /token (code grant) → JWT outlook
5. POST /mcp avec Bearer → réponse MCP OK
6. POST /token (refresh) → JWT rotated
7. POST /token (refresh REUSED) → 400 + family revoked + audit ALERT

---

## 16. Hors scope v0.2

- Revocation endpoint RFC 7009 (CLI admin à la place : `outlook-mcp admin revoke-refresh --jti X`)
- Introspection endpoint RFC 7662 (JWT self-contained)
- Authentification utilisateur primaire multi-user (v0.2 = single admin password)
- mTLS client OAuth
- Chiffrement at-rest SQLite (champs sensibles déjà hashés)

---

## 17. Findings cross-review tracés

Cette spec v2 intègre les findings codex 2026-05-10 :

| Finding | Sévérité | Traité dans |
|---|---|---|
| B1 — redirect_uri wildcard | BLOCKER | §1 D5, §5, §6 |
| B2 — DCR ouvert | BLOCKER | §1 D4, §5 (IAT obligatoire) |
| I1 — scope intersection non normative | IMPORTANT | §6 step 6 |
| I2 — open redirect sur erreur /authorize | IMPORTANT | §6 step 2-4 (erreurs locales avant validation) |
| I3 — consent CSRF/frame-ancestors | IMPORTANT | §6 POST consent + page HTML |
| I4 — TOCTOU codes/refresh | IMPORTANT | §7 atomic UPDATE + RETURNING |
| I5 — refresh reuse + family | IMPORTANT | §7 refreshFlow + family_id |
| I6 — SQLite backup ressuscite tokens | IMPORTANT | THREAT-MODEL §R1, MODES.md |
| I7 — confusion alg/kid | IMPORTANT | §1 D6, §8 verifier strict |
| I8 — XFF rightmost faux | IMPORTANT | §12 + MODES.md trust-proxy model |
| I9 — trusted-redirect exception | IMPORTANT | rejeté (cf. ADR-0002 D5) |
| O1 — test révocation v1 | OBSERVATION | retiré §15 E2E |
| O2 — pas de matrice modes | OBSERVATION | MODES.md créé |

Et le retour mcp-vault peer 2026-05-10 :

| Réserve mcp-vault | Traité dans |
|---|---|
| Lire tout le package `oauth/` (1043 LOC) | §3 architecture inspirée package complet |
| Tests Python non portables as-is | §15 spec fonctionnelle, pas template |
| Format V3 documenté ADR-0001 | ADR-0001 §"Schema Finding V3" |
| Consent template Jinja non partageable | §6 template eta TS pur ~35 lignes |
| Pas d'alignement timeline v0.2 mcp-vault | confirmé ADR-0002 conséquences |

---

*Fin spec v2 — à re-soumettre cross-review N0+N1 après implémentation (T16).*
