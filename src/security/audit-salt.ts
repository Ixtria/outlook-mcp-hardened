/**
 * Audit salt — per-installation random secret used to keyed-hash account
 * identifiers (emails, home account ids) before they hit the audit log.
 *
 * Resolves N0 cross-review OBSERVATION O1 (2026-05-10) : unsalted SHA256 of
 * a known operator email is trivially reversible via rainbow tables. The
 * audit log's pseudonymity claim was therefore broken for any attacker who
 * acquired the log file (e.g. via local read or backup leak).
 *
 * Strategy : 16 bytes of random salt, generated at first use, persisted in
 * `XDG_STATE_HOME/outlook-mcp/audit-salt` (mode 0600, parent dir 0700).
 * On every subsequent process, the salt is loaded from disk and cached in
 * memory. Result : log lines are still reversible TO THE OPERATOR (who owns
 * the salt file), but useless to anyone without filesystem access — which is
 * the realistic threat model for a single-tenant local deployment.
 *
 * For test determinism : `OUTLOOK_MCP_AUDIT_SALT_HEX` env var overrides the
 * file-backed salt. Production code should NEVER set this — it exists solely
 * so test suites can pin a known salt and assert reproducible HMAC output.
 *
 * Future enhancement (v0.4+): keytar OS keychain primary, with file fallback.
 * Not done in v0.3 because the file approach is sync (HMAC stays sync) and
 * keytar's async API would propagate through hashAccount's call sites.
 */

import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readSync,
  statSync,
  writeSync,
  chmodSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';

const SALT_BYTES = 16;

function getSaltPath(): string {
  const base = process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state');
  return join(base, 'outlook-mcp', 'audit-salt');
}

let cachedSalt: Buffer | null = null;

/**
 * Returns the audit salt, generating + persisting it on first call.
 * Synchronous by design : caller (`hashAccount`) is on the hot path of every
 * audit emit and cannot afford an async hop.
 *
 * N0-I2 fix (2026-06-02) : every file open uses `O_NOFOLLOW` so a pre-planted
 * symlink at the salt path cannot redirect our writes to an attacker-chosen
 * location. Same for the read side — if the salt path is a symlink, we
 * refuse to use it.
 *
 * N0-I3 fix (2026-06-02) : the test-override env var `OUTLOOK_MCP_AUDIT_
 * SALT_HEX` is refused in production (`NODE_ENV === 'production'`) — its
 * sole legitimate purpose is test determinism, and a leaked CI/Docker/k8s
 * ConfigMap entry would otherwise silently share the HMAC key across
 * installations, defeating the per-install pseudonymity invariant.
 */
export function getAuditSalt(): Buffer {
  if (cachedSalt) return cachedSalt;

  // Test override — DETERMINISTIC, production code MUST not set this.
  const envOverride = process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
  if (envOverride && envOverride.length === SALT_BYTES * 2) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'OUTLOOK_MCP_AUDIT_SALT_HEX is set in production. ' +
          'This env var exists only for test determinism and disables the ' +
          'per-installation random salt design (cf. N0-I3 audit). Unset it ' +
          'and let the server generate + persist a salt in XDG_STATE_HOME.'
      );
    }
    cachedSalt = Buffer.from(envOverride, 'hex');
    return cachedSalt;
  }

  const saltPath = getSaltPath();
  if (existsSync(saltPath)) {
    // O_NOFOLLOW : if saltPath is a symlink, openSync throws ELOOP. This
    // blocks a pre-planted-symlink attacker from redirecting our reads.
    let fd: number;
    try {
      fd = openSync(saltPath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ELOOP') {
        throw new Error(
          `Audit salt at ${saltPath} is a symlink — refusing to follow ` +
            `(N0-I2 symlink-attack defense). Remove the symlink and let the ` +
            `server regenerate a real file.`
        );
      }
      throw err;
    }
    try {
      const stat = fstatSync(fd);
      if (stat.size !== SALT_BYTES) {
        throw new Error(
          `Audit salt at ${saltPath} has unexpected length ${stat.size} (expected ${SALT_BYTES}). ` +
            `Refusing to use — delete the file to regenerate, but ALL existing log entries will become un-correlatable.`
        );
      }
      const buf = Buffer.alloc(SALT_BYTES);
      readSync(fd, buf, 0, SALT_BYTES, 0);
      // Defensive : narrow perms back to 0600 if widened externally.
      const mode = stat.mode & 0o777;
      if (mode !== 0o600) {
        try {
          chmodSync(saltPath, 0o600);
        } catch {
          // Best-effort hardening; not fatal.
        }
      }
      cachedSalt = buf;
      return cachedSalt;
    } finally {
      closeSync(fd);
    }
  }

  // First use — generate + persist with O_NOFOLLOW + O_EXCL (atomic create,
  // fails if any file exists at the path — defense against TOCTOU between
  // the existsSync check above and this open call).
  const salt = randomBytes(SALT_BYTES);
  mkdirSync(dirname(saltPath), { recursive: true, mode: 0o700 });
  const fd = openSync(
    saltPath,
    fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      (fsConstants.O_NOFOLLOW ?? 0),
    0o600
  );
  try {
    writeSync(fd, salt);
  } finally {
    closeSync(fd);
  }
  cachedSalt = salt;
  return cachedSalt;
}

/**
 * Test-only helper to reset the in-process salt cache. Production code must
 * not call this — the salt is meant to be stable for the lifetime of the
 * process to keep audit log correlation working across multiple emits.
 */
export function resetAuditSaltCache(): void {
  cachedSalt = null;
}
