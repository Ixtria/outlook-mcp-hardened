import { createHmac } from 'node:crypto';
import { getAuditSalt } from './audit-salt.js';

/**
 * Audit logger: every Graph call emits one JSON line to stderr so an
 * operator (or a sidecar shipper) can reconstruct exactly which tool
 * reached which API with which scope, without ever seeing the payload
 * content or the raw account identifier.
 *
 * Writes to stderr on purpose — the MCP stdio transport uses stdout for
 * the protocol. Any stray write to stdout would corrupt the JSON-RPC
 * framing and brick the session.
 *
 * Account hashing : N0 cross-review OBSERVATION O1 fix (2026-05-10). The
 * raw account identifier (email, home account id) is keyed-hashed with
 * a per-installation salt (HMAC-SHA256) — see `audit-salt.ts`. The output
 * is prefixed `hmac-sha256:` to distinguish from the legacy `sha256:`
 * scheme (unsalted) — operators upgrading from <v0.3 will see the prefix
 * change in their log stream.
 */

export interface AuditEntry {
  tool: string;
  method: string;
  path: string;
  scopes: string[];
  /** Raw account identifier (email, home account id, etc.). Will be hashed
   *  before emission. Pass null when no account context applies (e.g.
   *  pre-auth calls). */
  account: string | null;
  status: number;
  duration_ms: number;
}

interface EmittedEntry {
  ts: string;
  tool: string;
  method: string;
  path: string;
  scopes: string[];
  account: string;
  status: number;
  duration_ms: number;
}

export function hashAccount(raw: string): string {
  const canonical = raw.trim().toLowerCase();
  const salt = getAuditSalt();
  // 32 hex chars = 128 bits — collision-resistant for any realistic operator
  // account count, and shorter than the full 256 bits which would clutter
  // the log without security gain.
  const digest = createHmac('sha256', salt).update(canonical).digest('hex').slice(0, 32);
  return `hmac-sha256:${digest}`;
}

export function auditLog(entry: AuditEntry): void {
  const emitted: EmittedEntry = {
    ts: new Date().toISOString(),
    tool: entry.tool,
    method: entry.method,
    path: entry.path,
    scopes: entry.scopes,
    account: entry.account === null ? 'none' : hashAccount(entry.account),
    status: entry.status,
    duration_ms: entry.duration_ms,
  };
  process.stderr.write(JSON.stringify(emitted) + '\n');
}
