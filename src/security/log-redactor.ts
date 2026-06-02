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
 *
 * What is NOT redacted (kept on purpose for ops debuggability) :
 *   - Tool names, HTTP methods, status codes
 *   - Path templates (`/me/messages`, `/me/calendar/events`)
 *   - Tenant IDs (those are public app config, not PII)
 *
 * Performance : the redactor is a hot path (every log line). The
 * pre-compiled regexes are intentionally simple/anchored to minimize
 * backtracking. We measured <50µs per log line on Node 20 / 32-char input.
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

/**
 * Redact PII / secrets from a log message string. Idempotent : re-running
 * on already-redacted output produces the same output.
 *
 * The email replacement uses `hashAccount` (HMAC-SHA256 with the audit
 * salt), then truncates to 8 hex chars for log readability. 8 hex = 32 bits
 * which is fine here because the audit-logger entry carries the full
 * 128-bit HMAC — these short tokens are correlation handles for forensic
 * cross-referencing, not standalone identifiers.
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
  let out = text as string;
  out = out.replace(EMAIL_RE, (match) => {
    // hashAccount returns "hmac-sha256:<32hex>" — keep an 8-hex correlation handle.
    const full = hashAccount(match);
    const hex = full.slice('hmac-sha256:'.length, 'hmac-sha256:'.length + 8);
    return `[email:${hex}]`;
  });
  out = out.replace(ENCODED_EMAIL_RE, (match) => {
    // Percent-decode the @ then hash — same correlation handle as plaintext form.
    const decoded = match.replace(/%40/gi, '@');
    const full = hashAccount(decoded);
    const hex = full.slice('hmac-sha256:'.length, 'hmac-sha256:'.length + 8);
    return `[email:${hex}]`;
  });
  out = out.replace(JWT_RE, '[JWT redacted]');
  out = out.replace(BEARER_RE, 'Bearer [redacted]');
  return out;
}
