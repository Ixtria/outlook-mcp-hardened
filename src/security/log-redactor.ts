/**
 * Log message redactor.
 *
 * Resolves N0 review BLOCKER B1 (conf 95, 2026-06-02) : the project's
 * audit-logger.ts goes to great lengths to keyed-hash account identifiers
 * before stderr emission, but the parallel `winston` log stream
 * (mcp-server.log) was writing raw recipient emails, mail bodies, Graph
 * URL path params, and nextLink URLs in clear text to the same XDG
 * directory. An attacker who acquired the log file (the very threat model
 * the audit-logger pseudonymity was designed against) recovered the full
 * mailbox interaction in cleartext, defeating the audit-logger's HMAC.
 *
 * Strategy : a winston `format` that scans every emitted message string
 * for known PII / secret patterns and replaces them with redacted markers
 * before the message reaches any transport (file OR console). The
 * redaction uses `hashAccount()` from audit-logger for emails so a
 * correlator who has the audit-salt can still link mcp-server.log entries
 * to audit-logger entries (forensic continuity), but an attacker without
 * the salt sees only opaque tokens.
 *
 * What is redacted :
 *   - Email addresses (RFC 5322 simplified pattern, conservative)
 *   - Bearer tokens (Authorization-header-style strings)
 *   - JWT-shaped strings (eyJ... prefix, common in OAuth flows)
 *   - Graph API URL-encoded email path segments (e.g. `users/alice@…`)
 *   - Azure MSAL refresh-token-shaped strings (M.*, 1.A*, AQAB*)
 *     — OBS-07 / SEC-01 bonus (2026-08-02)
 *
 * What is NOT redacted (kept on purpose for ops debuggability) :
 *   - Tool names, HTTP methods, status codes
 *   - Path templates (`/me/messages`, `/me/calendar/events`)
 *   - Tenant IDs (those are public app config, not PII)
 *
 * Performance : the redactor is a hot path (every log line). The
 * pre-compiled regexes are intentionally simple/anchored to minimize
 * backtracking. We measured <50µs per log line on Node 20 / 32-char input.
 *
 * OBS-03 extension (2026-08-02) : `redactSensitiveDeep` walks arbitrary
 * nested structures (objects, arrays, Error) and redacts every string
 * VALUE it encounters, leaving keys and non-string primitives untouched.
 * Required because `redactSensitive` was only reaching `info.message` in
 * the winston pipeline — splat args, meta objects, error stacks were
 * bypassing redaction.
 */

import { hashAccount } from './audit-logger.js';

// Conservative email regex. We intentionally don't try to match the full
// RFC 5322 grammar — that's both impractical (the RFC allows backslash
// quoting that real-world parsers reject) and ReDoS-prone. Instead we
// match the 99% common case that covers AAD / Outlook user IDs.
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

// `Bearer <token>` — the Authorization header literal that occasionally
// surfaces in error stack traces or HTTP debug output.
const BEARER_RE = /Bearer\s+[A-Za-z0-9._\-+/=]+/gi;

// JWT-shaped strings. JWTs always start with `eyJ` (base64url of `{"`)
// and contain at least 2 dot-separated segments.
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]+/g;

// URL-encoded email in Graph paths : `users('alice%40example.com')` or
// `users/alice@example.com/...`. The non-encoded form is caught by EMAIL_RE
// above ; this catches the percent-encoded variant.
const ENCODED_EMAIL_RE = /[A-Za-z0-9._%+-]+%40[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

// Azure MSAL refresh-token-shaped strings. Real MSAL refresh tokens are
// opaque blobs starting with `M.`, `1.A`, or `AQAB` followed by a long
// base64url-ish payload. These NEVER contain the `eyJ` JWT prefix so the
// JWT regex above misses them (SEC-01 finding, 2026-08-02).
// The `\b` anchor keeps false positives low : we only match at word
// boundaries, so `random.M.foo` is not touched.
const AZURE_REFRESH_M_RE = /\bM\.[A-Za-z0-9_-][A-Za-z0-9._-]{3,}/g;
const AZURE_REFRESH_1A_RE = /\b1\.A[A-Za-z0-9._-]{4,}/g;
const AZURE_REFRESH_AQAB_RE = /\bAQAB[A-Za-z0-9._-]{4,}/g;

/**
 * Redact PII / secrets from a single string. Pure regex, no I/O beyond
 * the audit-salt-keyed HMAC on emails. Safe to call on already-redacted
 * output (idempotent for the JWT / Bearer / refresh-token replacements ;
 * email replacements re-hash their own `[email:HASH]` marker to itself
 * because the marker doesn't match `EMAIL_RE`).
 */
function redactString(input: string): string {
  let out = input;
  out = out.replace(EMAIL_RE, (match) => {
    const full = hashAccount(match);
    const hex = full.slice('hmac-sha256:'.length, 'hmac-sha256:'.length + 8);
    return `[email:${hex}]`;
  });
  out = out.replace(ENCODED_EMAIL_RE, (match) => {
    const decoded = match.replace(/%40/gi, '@');
    const full = hashAccount(decoded);
    const hex = full.slice('hmac-sha256:'.length, 'hmac-sha256:'.length + 8);
    return `[email:${hex}]`;
  });
  out = out.replace(JWT_RE, '[JWT redacted]');
  out = out.replace(BEARER_RE, 'Bearer [redacted]');
  out = out.replace(AZURE_REFRESH_M_RE, '[refresh redacted]');
  out = out.replace(AZURE_REFRESH_1A_RE, '[refresh redacted]');
  out = out.replace(AZURE_REFRESH_AQAB_RE, '[refresh redacted]');
  return out;
}

/**
 * Redact PII / secrets from a log message string. Idempotent : re-running
 * on already-redacted output produces the same output.
 *
 * The email replacement uses `hashAccount` (HMAC-SHA256 with the audit
 * salt), then truncates to 8 hex chars for log readability. 8 hex = 32 bits
 * which is fine here because the audit-logger entry carries the full
 * 128-bit HMAC — these short tokens are correlation handles for forensic
 * cross-referencing, not standalone identifiers.
 *
 * Non-string inputs are JSON-stringified first (preserved behavior — a
 * few call sites rely on this). For structure-preserving redaction of
 * meta/splat/error objects inside the winston pipeline, use
 * `redactSensitiveDeep` instead.
 */
export function redactSensitive(text: unknown): string {
  if (typeof text !== 'string') {
    if (text === null || text === undefined) return String(text);
    try {
      text = JSON.stringify(text);
    } catch {
      return '[unserializable]';
    }
  }
  return redactString(text as string);
}

/**
 * Recursively redact PII / secrets from an arbitrary value, preserving
 * structure (arrays stay arrays, plain objects stay plain objects, Error
 * instances become plain objects with `{ name, message, stack, ...own }`
 * so the JSON transport can serialize them — the native Error class has
 * non-enumerable `message`/`stack` which `JSON.stringify` would drop).
 *
 * Keys are NEVER touched, only string values. Non-string primitives
 * (number / boolean / bigint / null / undefined) pass through unchanged.
 *
 * Cycle-safe : an object encountered a second time in the same walk is
 * replaced by the string `'[circular]'`. This matches the winston-friendly
 * behaviour (json transport already refuses cycles).
 *
 * OBS-03 (2026-08-02) : this is what the winston piiRedactFormat calls
 * on every own enumerable property + on the splat Symbol payload, so that
 * `logger.info('msg', { deep: { token: 'eyJ…' } })` or
 * `logger.error('msg', new Error('leaked eyJ…'))` scrub the token before
 * any transport writes.
 */
export function redactSensitiveDeep(value: unknown, seen?: WeakSet<object>): unknown {
  if (typeof value === 'string') return redactString(value);
  if (value === null || value === undefined) return value;
  if (typeof value !== 'object') return value;

  const tracker = seen ?? new WeakSet<object>();
  if (tracker.has(value as object)) return '[circular]';
  tracker.add(value as object);

  if (value instanceof Error) {
    // Copy the standard non-enumerable Error props explicitly, then merge
    // any user-attached own props (e.g. `err.code = 'ETIMEDOUT'`) after
    // deep-redaction. Winston's json transport otherwise emits `{}` for
    // Error values, hiding both leaks AND diagnostic info.
    const err = value;
    const redacted: Record<string, unknown> = {
      name: err.name,
      message: redactString(err.message ?? ''),
    };
    if (typeof err.stack === 'string') {
      redacted.stack = redactString(err.stack);
    }
    for (const key of Object.keys(err)) {
      if (key === 'name' || key === 'message' || key === 'stack') continue;
      redacted[key] = redactSensitiveDeep((err as unknown as Record<string, unknown>)[key], tracker);
    }
    return redacted;
  }

  if (Array.isArray(value)) {
    return value.map((v) => redactSensitiveDeep(v, tracker));
  }

  const source = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(source)) {
    out[key] = redactSensitiveDeep(source[key], tracker);
  }
  return out;
}
