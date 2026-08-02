import { createHmac } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getAuditSalt, resetAuditSaltCache } from './audit-salt.js';
import { getRequestId } from '../request-context.js';

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
 *
 * Runtime salt posture (RUNTIME-SEC-01, 2026-08-02) : before every audit
 * emission, we re-stat the on-disk salt file to catch three failure modes
 * that a boot-only check would miss :
 *   - permissions regression (mode widened after boot),
 *   - ownership change (uid drift after a chown/mv incident),
 *   - salt rotation (file replaced — inode/mtime change → cache invalidate).
 * The check is rate-limited (see AUDIT_SALT_VALIDATION_INTERVAL_MS) so we
 * don't pay a syscall on every log line ; the first hash after boot always
 * validates.
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
  /**
   * Correlation id (OBS-04, 2026-08-02). When omitted, `auditLog()` falls
   * back to `getRequestId()` from the AsyncLocalStorage store populated by
   * `createRequestIdMiddleware`. The emitted JSON only carries a
   * `request_id` field when a value could be resolved — omitting the key
   * for non-HTTP call sites (background timers, stdio mode) keeps the
   * schema backwards-compatible with downstream shippers.
   */
  request_id?: string;
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
  request_id?: string;
}

// --- Runtime salt posture (RUNTIME-SEC-01) ---------------------------------
//
// The salt path is computed locally (kept in sync with getSaltPath() in
// audit-salt.ts). Duplicated on purpose : audit-logger owns the posture
// check, audit-salt owns the read/write. A shared helper module was
// considered but rejected — it would push audit-salt's private path
// resolution into a public surface just to satisfy this one caller.

const AUDIT_SALT_VALIDATION_INTERVAL_MS = 30_000;

let lastValidationAt = 0;
let lastSeenIno: number | null = null;
let lastSeenMtimeMs: number | null = null;

function getSaltPath(): string {
  const base = process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state');
  return join(base, 'outlook-mcp', 'audit-salt');
}

/**
 * True when the test-override env var is set to a valid value AND we are
 * not in production. Under this mode, the on-disk salt file is bypassed
 * and posture validation has nothing to check.
 */
function envOverrideActive(): boolean {
  const envOverride = process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
  if (!envOverride || envOverride.length !== 32) return false;
  // NODE_ENV === 'production' will make audit-salt throw when consulted —
  // that path handles its own error, so we only report "override active"
  // when the override would actually be honoured.
  return process.env.NODE_ENV !== 'production';
}

/**
 * Validates the on-disk audit salt file : permissions, ownership, non-empty,
 * not a symlink. Throws with an operator-actionable message on any failure.
 * Also detects rotation (inode or mtime change since last observation) and
 * invalidates the in-process salt cache so the next `hashAccount()` call
 * re-reads the fresh salt from disk.
 *
 * No-op when the env test override is active (no file to validate) or when
 * the file does not exist yet (bootstrap will create it under safe
 * O_EXCL + mode 0o600 semantics on the next `getAuditSalt()` call).
 *
 * Exported for tests + call sites that want to fail fast at boot rather
 * than at first audit emission.
 */
export function validateAuditSaltFile(): void {
  if (envOverrideActive()) {
    lastValidationAt = Date.now();
    return;
  }

  const saltPath = getSaltPath();
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(saltPath);
  } catch (err) {
    // eslint-disable-next-line no-undef -- justif: NodeJS.ErrnoException is a TS ambient type, not a runtime global
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      // File not materialised yet ; audit-salt bootstrap will create it
      // with O_EXCL + mode 0o600. Reset rotation trackers so the next
      // validation after creation records baseline mtime/inode.
      lastSeenIno = null;
      lastSeenMtimeMs = null;
      lastValidationAt = Date.now();
      return;
    }
    throw err;
  }

  if (stat.isSymbolicLink()) {
    throw new Error(
      `audit-salt refuses to run: ${saltPath} is a symlink ` +
        `(RUNTIME-SEC-01). Remove the symlink and restart to regenerate a real file.`
    );
  }
  if (stat.size === 0) {
    throw new Error(
      `audit-salt refuses to run: ${saltPath} is empty ` +
        `(RUNTIME-SEC-01). Delete the file and restart to regenerate a valid salt.`
    );
  }
  const mode = stat.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `audit-salt permissions unsafe: mode 0o${mode.toString(8)} on ${saltPath} ` +
        `(group/other bits set). RUNTIME-SEC-01: chmod 0600 and restart.`
    );
  }
  const processUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (processUid !== undefined && stat.uid !== processUid) {
    throw new Error(
      `audit-salt ownership unsafe: file uid=${stat.uid}, process uid=${processUid} ` +
        `on ${saltPath}. RUNTIME-SEC-01: chown to the running user and restart.`
    );
  }

  // Rotation detection : if the file has been replaced (different inode)
  // or overwritten in place (different mtime) since our last check, drop
  // the cached salt so the next hash call re-reads the fresh key material.
  if (lastSeenIno !== null && (lastSeenIno !== stat.ino || lastSeenMtimeMs !== stat.mtimeMs)) {
    resetAuditSaltCache();
  }
  lastSeenIno = stat.ino;
  lastSeenMtimeMs = stat.mtimeMs;
  lastValidationAt = Date.now();
}

/**
 * Test-only helper to reset the validation state machine (last-checked
 * timestamp + rotation trackers). Production code must not call this —
 * validation is meant to be rate-limited across the process lifetime.
 */
export function resetAuditSaltValidationState(): void {
  lastValidationAt = 0;
  lastSeenIno = null;
  lastSeenMtimeMs = null;
}

function loadValidatedSalt(): Buffer {
  const now = Date.now();
  if (now - lastValidationAt > AUDIT_SALT_VALIDATION_INTERVAL_MS) {
    validateAuditSaltFile();
  }
  try {
    return getAuditSalt();
  } catch (err) {
    // eslint-disable-next-line no-undef -- justif: NodeJS.ErrnoException is a TS ambient type, not a runtime global
    const code = (err as NodeJS.ErrnoException).code;
    // Salt persistence failures : translate common fs errno into an explicit
    // operator-facing message. Without this, an ENOSPC on first-use would
    // bubble up as a bare Error and the operator has to grep the stack for
    // the salt path. RUNTIME-SEC-01 asks for "explicit error, not silent
    // crash" — this is the explicit part.
    if (code === 'ENOSPC' || code === 'EDQUOT' || code === 'EROFS' || code === 'EACCES') {
      throw new Error(
        `audit-salt: cannot persist salt file at ${getSaltPath()}: ${code} ` +
          `(RUNTIME-SEC-01). Audit correlation requires a stable salt on ` +
          `disk — refusing to hash accounts without it.`
      );
    }
    throw err;
  }
}

export function hashAccount(raw: string): string {
  const canonical = raw.trim().toLowerCase();
  const salt = loadValidatedSalt();
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
  // OBS-04 (2026-08-02) : correlation id. Explicit `entry.request_id` wins
  // (call site had context we don't); otherwise pull from the ALS store
  // populated by createRequestIdMiddleware. Emit only when non-empty so
  // stdio-mode audit lines don't gain a null "request_id": null field.
  const resolvedRequestId = entry.request_id ?? getRequestId();
  if (resolvedRequestId) {
    emitted.request_id = resolvedRequestId;
  }
  process.stderr.write(JSON.stringify(emitted) + '\n');
}
