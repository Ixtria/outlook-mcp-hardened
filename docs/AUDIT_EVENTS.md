# Audit events — source of truth

Ownership : OBS-02 (2026-08-02). Any change to an event name, field, or
emission point MUST land in this file in the same commit as the code change.

Consumers reading `mcp-server` audit lines (stderr, JSON, one line per event
— see [`src/security/audit-logger.ts`](../src/security/audit-logger.ts))
MUST rely on this document as the canonical schema. Silent additions of new
event types are permitted ; silent renames of existing types are a breaking
change and require a `docs/adr/*` entry.

## Schema

Every audit line is a single-line JSON object with **exactly** the following
fields (see [`AuditEntry`](../src/security/audit-logger.ts)) :

| Field         | Type      | Meaning |
| ------------- | --------- | ------- |
| `ts`          | string    | ISO 8601 UTC timestamp, millisecond precision. |
| `tool`        | string    | Event type (see table below). Dot-separated namespace. |
| `method`      | string    | HTTP verb of the underlying request (`GET`/`POST`) — `"GET"` for stdio-mode Graph calls. |
| `path`        | string    | Endpoint path being audited (`/register`, `/authorize`, `/token`, `/mcp`, Graph API path, or `(egress)` for guard violations). |
| `scopes`      | string[]  | Requested/effective OAuth scopes. `[]` when the event has no scope context. |
| `account`     | string    | Either `"none"` or `hmac-sha256:<32 hex>` — never the raw email/UPN. Salted HMAC via [`hashAccount()`](../src/security/audit-logger.ts). |
| `status`      | number    | Numeric outcome. HTTP status when applicable ; `0` for pre-HTTP failures (network, egress). |
| `duration_ms` | number    | Handler wall time in milliseconds. `0` when no timing was captured. |
| `request_id`  | string?   | Correlation ID from [`X-Request-Id`](../src/request-context.ts) (OBS-04). Omitted outside HTTP requests. |

The wire format is `JSON + "\n"` written to `process.stderr`. The MCP stdio
protocol uses stdout — writing audit lines to stderr keeps the JSON-RPC
framing intact.

## Event catalog

The eight OAuth audit event types below are emitted by
[`src/oauth/http-routes.ts`](../src/oauth/http-routes.ts),
[`src/oauth-provider.ts`](../src/oauth-provider.ts), and
[`src/server.ts`](../src/server.ts) (via the wrappers exported by
`oauth-provider.ts`).

### `oauth.client.register`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| POST `/register` (Dynamic Client Registration, RFC 7591) — both success (201) and reject (400 : missing `redirect_uris`, unlisted `redirect_uri`). | `path=/register`, `method=POST`, `scopes=[]`, `account=null`, `status=201\|400`, `duration_ms`. | `redirect_uris` values, `client_name`, `client_secret` (never present anyway — public clients only). | 90 days (operator's log aggregator). |

Emission site : [`createRegisterHandler`](../src/oauth/http-routes.ts).

### `oauth.authorize.request`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| GET `/authorize` accepted → 302 redirect to `login.microsoftonline.com`. One event per successful redirect. | `path=/authorize`, `method=GET`, `scopes=<effective intersection>`, `account=null` (no identity yet), `status=302`, `duration_ms`. | `state` (only tracked internally, never emitted), `redirect_uri`, `code_challenge`. | 90 days. |

Emission site : [`createAuthorizeHandler`](../src/oauth/http-routes.ts).

### `oauth.authorize.reject`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| GET `/authorize` rejected (400) : missing / unlisted `redirect_uri`, PKCE method not `S256`, `state` too long, missing `code_challenge` (PKCE mandatory), empty scope intersection. Also POST `/authorize` (405 — MUST be GET). | `path=/authorize`, `method=GET\|POST`, `scopes=[]` (or requested when computed pre-reject), `account=null`, `status=400\|405`, `duration_ms`. | `state`, `redirect_uri`, `code_challenge`, `code_challenge_method` (all treated as sensitive query metadata). | 90 days — heightened operator interest, correlate with `client_ip` in the winston stream via `request_id`. |

Emission sites : [`createAuthorizeHandler`](../src/oauth/http-routes.ts) and
[`createRejectPostAuthorizeHandler`](../src/oauth/http-routes.ts).

### `oauth.token.request`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| POST `/token` succeeded — AAD returned a valid token pair for either `grant_type=authorization_code` or `grant_type=refresh_token`. | `path=/token`, `method=POST`, `scopes=<AAD-returned scope string>`, `account=null`, `status=200`, `duration_ms`. | `code`, `code_verifier`, `refresh_token`, `access_token`, `id_token`, `client_secret` — none of these are ever passed to `auditLog()`. | 90 days. |

Emission site : [`withTokenExchangeAudit`](../src/oauth-provider.ts), wired
in [`server.ts`](../src/server.ts) around `exchangeCodeForToken` and
`refreshAccessToken`.

### `oauth.token.reject`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| POST `/token` failed — AAD 4xx (`invalid_client`, `invalid_grant`, `invalid_scope`, etc.), network error, or egress guard violation. | `path=/token`, `method=POST`, `scopes=[]`, `account=null`, `status=500` (or `502` for egress-blocked), `duration_ms`. | Same set as `oauth.token.request` — no request or response body content. | 90 days. |

**Not covered** by this event (see followup ticket) : the 400 pre-validation
paths inside `/token` that reject before `exchangeCodeForToken` runs — missing
`grant_type`, missing body, `unsupported_grant_type`. Those cases surface in
the winston warn stream but are not (yet) audited.

Emission site : same wrapper as `oauth.token.request`.

### `oauth.mcp.request`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| POST/GET `/mcp` — Bearer token was accepted by the Microsoft Graph `/me` verifier. One event per verified request ; the MCP transport then dispatches the JSON-RPC call. | `path=/mcp`, `method=GET`, `scopes=[]` (aud check delegated to AAD), `account=<userPrincipalName>` (hashed via `hashAccount`), `status=200`, `duration_ms`. | Bearer token, refresh token, raw UPN. | 90 days. |

Emission site : [`verifyMicrosoftAccessToken`](../src/oauth-provider.ts).

### `oauth.mcp.reject`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| POST/GET `/mcp` — Bearer token verifier threw. Either Graph returned non-2xx (invalid / expired / revoked / wrong audience) or the fetch itself failed (network, egress guard). | `path=/mcp`, `method=GET`, `scopes=[]`, `account=null` (no identity was established), `status=<Graph HTTP status or 0>`, `duration_ms`. | Bearer token. | 90 days — pair with rate-limiting / alerting. |

Emission site : [`verifyMicrosoftAccessToken`](../src/oauth-provider.ts).

### `oauth.egress.violation`

| When emitted | Fields | Redacted / never emitted | Retention |
| ------------ | ------ | ------------------------- | --------- |
| A `fetch()` reached by an OAuth flow was blocked by the [egress guard](../src/security/egress-guard.ts) (host not in `{login.microsoftonline.com, graph.microsoft.com}` or non-`https:`/non-443). Emitted from the OAuth-provider `catch` around the token-exchange wrappers and the Bearer verifier. | `path=<attempted URL or endpoint>`, `method=POST\|GET`, `scopes=[]`, `account=null`, `status=0`, `duration_ms=0`. | The offending URL's query string (never propagated) — only the path fragment is retained. | 90 days — **P0** signal, alert immediately (indicates either a bug in the trimmed OpenAPI client or a supply-chain compromise). |

Emission site : [`verifyMicrosoftAccessToken`](../src/oauth-provider.ts) and
[`withTokenExchangeAudit`](../src/oauth-provider.ts). The egress guard itself
lives in [`src/security/egress-guard.ts`](../src/security/egress-guard.ts) and
throws `EgressViolationError` synchronously ; the OAuth-provider wrappers
catch it, emit `oauth.egress.violation`, and re-throw.

## Retention & operator responsibilities

The MCP server itself does NOT rotate or ship these events off-box. The
stderr stream is expected to be consumed by :

- systemd journal (`journalctl -u outlook-mcp`) when running as a service
- Docker's json-file driver when containerized
- A sidecar shipper (vector, fluent-bit) when centralized logging is desired

Operators SHOULD :

1. Retain the audit stream for at least 90 days to enable incident forensics.
2. Alert on `oauth.egress.violation` (should be zero in steady state).
3. Alert on sustained bursts of `oauth.mcp.reject` (credential-stuffing indicator).
4. Cross-reference `request_id` between the audit stream and the winston
   application log for full-context debugging without needing to correlate
   on timestamps.
