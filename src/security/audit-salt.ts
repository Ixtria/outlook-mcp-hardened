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
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  statSync,
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
 */
export function getAuditSalt(): Buffer {
  if (cachedSalt) return cachedSalt;

  // Test override — DETERMINISTIC, production code must not set this.
  const envOverride = process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
  if (envOverride && envOverride.length === SALT_BYTES * 2) {
    cachedSalt = Buffer.from(envOverride, 'hex');
    return cachedSalt;
  }

  const saltPath = getSaltPath();
  if (existsSync(saltPath)) {
    const buf = readFileSync(saltPath);
    if (buf.length !== SALT_BYTES) {
      throw new Error(
        `Audit salt at ${saltPath} has unexpected length ${buf.length} (expected ${SALT_BYTES}). ` +
          `Refusing to use — delete the file to regenerate, but ALL existing log entries will become un-correlatable.`
      );
    }
    // Defensive : if perms were widened externally, narrow back to 0600.
    try {
      const stat = statSync(saltPath);
      const mode = stat.mode & 0o777;
      if (mode !== 0o600) chmodSync(saltPath, 0o600);
    } catch {
      // Best-effort hardening; not fatal.
    }
    cachedSalt = buf;
    return cachedSalt;
  }

  // First use — generate + persist.
  const salt = randomBytes(SALT_BYTES);
  mkdirSync(dirname(saltPath), { recursive: true, mode: 0o700 });
  writeFileSync(saltPath, salt, { mode: 0o600 });
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
