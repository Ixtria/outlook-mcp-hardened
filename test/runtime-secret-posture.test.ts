/**
 * RUNTIME-SEC-01 — Runtime secret posture (5e pattern GPT-5.5).
 *
 * These tests exercise the on-disk audit salt file across the boot +
 * runtime lifecycle from an adversarial angle : widened permissions,
 * ownership drift, empty payload, symlink swap, mid-flight rotation,
 * write failures, deletion + regen. The audit logger's contract is
 * that any posture violation surfaces as an operator-actionable error
 * BEFORE a hash is emitted with an unsafe key.
 *
 * All tests operate against an isolated tmp XDG_STATE_HOME to avoid
 * touching dev state.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  hashAccount,
  resetAuditSaltValidationState,
  validateAuditSaltFile,
} from '../src/security/audit-logger.js';
import { resetAuditSaltCache } from '../src/security/audit-salt.js';

const SALT_REL_PATH = 'outlook-mcp/audit-salt';

function saltPathFor(base: string): string {
  return join(base, SALT_REL_PATH);
}

function writeValidSalt(base: string, mode = 0o600): string {
  const path = saltPathFor(base);
  mkdirSync(join(base, 'outlook-mcp'), { recursive: true, mode: 0o700 });
  writeFileSync(path, Buffer.from('0123456789abcdef', 'utf8'), { mode });
  chmodSync(path, mode); // umask can strip bits during writeFileSync
  return path;
}

describe('runtime secret posture (RUNTIME-SEC-01)', () => {
  let tmpBase: string;
  let savedXdg: string | undefined;
  let savedEnvHex: string | undefined;

  beforeEach(() => {
    tmpBase = mkdtempSync(join(tmpdir(), 'runtime-secret-posture-'));
    savedXdg = process.env.XDG_STATE_HOME;
    savedEnvHex = process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    process.env.XDG_STATE_HOME = tmpBase;
    // Force the file-backed code path — every posture assertion in this
    // file needs the on-disk salt, never the env-override shortcut.
    delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    resetAuditSaltCache();
    resetAuditSaltValidationState();
  });

  afterEach(() => {
    rmSync(tmpBase, { recursive: true, force: true });
    if (savedXdg === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = savedXdg;
    if (savedEnvHex === undefined) delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    else process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = savedEnvHex;
    resetAuditSaltCache();
    resetAuditSaltValidationState();
  });

  describe('boot-time validation', () => {
    it('passes when the salt file is 0600 and owned by the current uid', () => {
      writeValidSalt(tmpBase, 0o600);
      expect(() => validateAuditSaltFile()).not.toThrow();
    });

    it('throws when the salt file has group-read permission (0640)', () => {
      writeValidSalt(tmpBase, 0o640);
      expect(() => validateAuditSaltFile()).toThrowError(/permissions unsafe/);
    });

    it('throws when the salt file is world-readable (0644)', () => {
      writeValidSalt(tmpBase, 0o644);
      expect(() => validateAuditSaltFile()).toThrowError(/permissions unsafe/);
    });

    it('throws when the salt file is empty', () => {
      const path = saltPathFor(tmpBase);
      mkdirSync(join(tmpBase, 'outlook-mcp'), { recursive: true, mode: 0o700 });
      writeFileSync(path, Buffer.alloc(0), { mode: 0o600 });
      chmodSync(path, 0o600);
      expect(() => validateAuditSaltFile()).toThrowError(/empty/);
    });

    it('throws when the salt path is a symlink', () => {
      const decoy = join(tmpBase, 'attacker-controlled-salt');
      writeFileSync(decoy, Buffer.from('DEADBEEFDEADBEEF', 'utf8'), { mode: 0o600 });
      mkdirSync(join(tmpBase, 'outlook-mcp'), { recursive: true, mode: 0o700 });
      symlinkSync(decoy, saltPathFor(tmpBase));
      expect(() => validateAuditSaltFile()).toThrowError(/symlink/);
    });

    it('is a no-op when the salt file does not exist yet', () => {
      // No file created — first hash call will trigger bootstrap.
      expect(() => validateAuditSaltFile()).not.toThrow();
    });

    it.skipIf(process.getuid?.() !== 0)(
      'throws when the salt file is owned by a different uid (root-only test)',
      () => {
        // Only meaningful when we can chown to a foreign uid. Skipped in
        // developer environments to avoid a false negative on unprivileged
        // CI runners. Exercised in the container test matrix.
        // eslint-disable-next-line @typescript-eslint/no-require-imports -- justif: dynamic import awkward inside sync test, guarded by root-only skipIf
        const { chownSync } = require('node:fs');
        writeValidSalt(tmpBase, 0o600);
        chownSync(saltPathFor(tmpBase), 65534, 65534); // nobody
        expect(() => validateAuditSaltFile()).toThrowError(/ownership unsafe/);
      }
    );
  });

  describe('rotation detection', () => {
    it('re-reads the salt from disk after the file is replaced', () => {
      // Seed a known salt, hash a value, then replace the salt on disk
      // and hash the same value again. If rotation is detected, the two
      // hashes must differ (different HMAC key ⇒ different output).
      const path = saltPathFor(tmpBase);
      mkdirSync(join(tmpBase, 'outlook-mcp'), { recursive: true, mode: 0o700 });
      writeFileSync(path, Buffer.from('AAAAAAAAAAAAAAAA', 'utf8'), { mode: 0o600 });
      chmodSync(path, 0o600);
      const originalMtimeSec = statSync(path).mtimeMs / 1000;

      // Fake timers : we need to advance PAST the rate-limiter window
      // (AUDIT_SALT_VALIDATION_INTERVAL_MS = 30s) to trigger a re-stat.
      // Resetting the validation trackers would also work but would wipe
      // the rotation baseline (lastSeenIno/mtime), defeating the check.
      vi.useFakeTimers({ shouldAdvanceTime: false });
      try {
        const hashBeforeRotation = hashAccount('alice@example.com');

        writeFileSync(path, Buffer.from('BBBBBBBBBBBBBBBB', 'utf8'), { mode: 0o600 });
        chmodSync(path, 0o600);
        // Bump mtime by a clearly-observable delta to survive filesystems
        // with 1s mtime resolution.
        utimesSync(path, originalMtimeSec + 5, originalMtimeSec + 5);

        vi.advanceTimersByTime(60_000);

        const hashAfterRotation = hashAccount('alice@example.com');
        expect(hashBeforeRotation).not.toBe(hashAfterRotation);
      } finally {
        vi.useRealTimers();
      }
    });

    it('keeps returning stable hashes across calls when the salt is untouched', () => {
      writeValidSalt(tmpBase, 0o600);
      const a = hashAccount('alice@example.com');
      const b = hashAccount('alice@example.com');
      expect(a).toBe(b);
    });
  });

  describe('runtime salt deletion + regen', () => {
    it('regenerates a fresh salt cleanly after the file is deleted at runtime', () => {
      // First hash bootstraps the salt file.
      const first = hashAccount('alice@example.com');
      const saltPath = saltPathFor(tmpBase);
      expect(statSync(saltPath).size).toBe(16);
      const originalBytes = readFileSync(saltPath);

      // Simulate a fresh process boot after an operator wipe : file gone,
      // in-memory cache empty, validation state empty.
      rmSync(saltPath);
      resetAuditSaltCache();
      resetAuditSaltValidationState();

      // Next hash must succeed (regen path), and the on-disk salt must
      // be a valid 16-byte file with 0600 perms — same posture as boot.
      const second = hashAccount('alice@example.com');
      const stat = statSync(saltPath);
      expect(stat.size).toBe(16);
      expect(stat.mode & 0o777).toBe(0o600);

      // The regenerated salt is fresh entropy ⇒ different HMAC output.
      const regeneratedBytes = readFileSync(saltPath);
      expect(regeneratedBytes.equals(originalBytes)).toBe(false);
      expect(first).not.toBe(second);
    });
  });

  describe('write-failure surface', () => {
    it('surfaces a bootstrap write failure as an explicit operator error, not a silent crash', () => {
      // Make the parent directory read-only so audit-salt's mkdirSync +
      // O_CREAT|O_EXCL open path cannot land the file. This exercises the
      // same code shape as ENOSPC : write attempt fails with a POSIX errno.
      const parent = join(tmpBase, 'outlook-mcp');
      mkdirSync(parent, { recursive: true, mode: 0o500 }); // r-x, no write
      try {
        expect(() => hashAccount('alice@example.com')).toThrowError(/audit-salt/);
      } finally {
        // Restore perms so afterEach rmSync can clean up.
        chmodSync(parent, 0o700);
      }
    });
  });

  describe('error message safety (redaction)', () => {
    it('does not leak salt bytes when reporting a posture failure', () => {
      // Even though our stat-based checks never read the file content,
      // pin this as a contract test : posture errors must expose the
      // path (operator needs it to remediate) but never file bytes.
      const path = saltPathFor(tmpBase);
      mkdirSync(join(tmpBase, 'outlook-mcp'), { recursive: true, mode: 0o700 });
      const saltPayload = 'SECRETSALTPAYLOAD';
      writeFileSync(path, Buffer.from(saltPayload, 'utf8'), { mode: 0o644 });
      chmodSync(path, 0o644);

      let caught: unknown;
      try {
        validateAuditSaltFile();
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(Error);
      const message = (caught as Error).message;
      expect(message).not.toContain(saltPayload);
      // Sanity: the operator does get the path they need to remediate.
      expect(message).toContain(path);
    });
  });
});
