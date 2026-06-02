import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getAuditSalt, resetAuditSaltCache } from '../src/security/audit-salt.js';

describe('audit-salt (N0 O1 fix)', () => {
  let tmpDir: string;
  let savedXdg: string | undefined;
  let savedEnvHex: string | undefined;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'outlook-mcp-audit-test-'));
    savedXdg = process.env.XDG_STATE_HOME;
    savedEnvHex = process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    process.env.XDG_STATE_HOME = tmpDir;
    delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    resetAuditSaltCache();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    if (savedXdg === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = savedXdg;
    if (savedEnvHex === undefined) delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    else process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = savedEnvHex;
    resetAuditSaltCache();
  });

  describe('first-use bootstrap', () => {
    it('generates a 16-byte salt and persists it under XDG_STATE_HOME', () => {
      const salt = getAuditSalt();
      expect(salt.length).toBe(16);
      const expectedPath = join(tmpDir, 'outlook-mcp', 'audit-salt');
      const onDisk = readFileSync(expectedPath);
      expect(onDisk.equals(salt)).toBe(true);
    });

    it('persists salt with mode 0600 (owner read+write only)', () => {
      getAuditSalt();
      const expectedPath = join(tmpDir, 'outlook-mcp', 'audit-salt');
      const stat = statSync(expectedPath);
      expect(stat.mode & 0o777).toBe(0o600);
    });

    it('creates parent directory with mode 0700', () => {
      getAuditSalt();
      const parent = join(tmpDir, 'outlook-mcp');
      const stat = statSync(parent);
      // 0700 may be masked by umask; we test owner-bits at minimum.
      expect(stat.mode & 0o700).toBe(0o700);
    });

    it('generates entropy-different salt across resets', () => {
      const a = getAuditSalt();
      // Force regen by wiping disk + cache.
      rmSync(join(tmpDir, 'outlook-mcp'), { recursive: true });
      resetAuditSaltCache();
      const b = getAuditSalt();
      expect(a.equals(b)).toBe(false);
    });
  });

  describe('returning-process load', () => {
    it('reloads the same salt from disk on a new process simulation', () => {
      const first = getAuditSalt();
      resetAuditSaltCache(); // simulate fresh process
      const second = getAuditSalt();
      expect(first.equals(second)).toBe(true);
    });

    it('repairs widened file perms (defensive)', () => {
      getAuditSalt();
      const path = join(tmpDir, 'outlook-mcp', 'audit-salt');
      chmodSync(path, 0o644); // simulate operator misstep
      resetAuditSaltCache();
      getAuditSalt();
      const stat = statSync(path);
      expect(stat.mode & 0o777).toBe(0o600);
    });

    it('refuses to use a tampered salt of wrong length', () => {
      const path = join(tmpDir, 'outlook-mcp', 'audit-salt');
      // Pre-populate with bad-length file
      const parentDir = join(tmpDir, 'outlook-mcp');
      const { mkdirSync } = require('node:fs');
      mkdirSync(parentDir, { recursive: true, mode: 0o700 });
      writeFileSync(path, Buffer.from('TOO-SHORT'), { mode: 0o600 });
      resetAuditSaltCache();
      expect(() => getAuditSalt()).toThrow(/unexpected length/);
    });
  });

  describe('test override via env var', () => {
    it('uses OUTLOOK_MCP_AUDIT_SALT_HEX when valid 32-char hex (16 bytes)', () => {
      process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = '00112233445566778899aabbccddeeff';
      resetAuditSaltCache();
      const salt = getAuditSalt();
      expect(salt.toString('hex')).toBe('00112233445566778899aabbccddeeff');
    });

    it('ignores OUTLOOK_MCP_AUDIT_SALT_HEX when wrong length (falls back to file)', () => {
      process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = 'cafebabe'; // 4 bytes — wrong
      resetAuditSaltCache();
      const salt = getAuditSalt();
      expect(salt.length).toBe(16); // generated fresh, not from env
    });
  });

  describe('cache semantics', () => {
    it('returns the same Buffer reference on repeated calls (single process)', () => {
      const a = getAuditSalt();
      const b = getAuditSalt();
      expect(a).toBe(b);
    });

    it('resetAuditSaltCache forces re-load from disk', () => {
      const a = getAuditSalt();
      resetAuditSaltCache();
      const b = getAuditSalt();
      // Different Buffer object references…
      expect(a).not.toBe(b);
      // …but same content (loaded from same file).
      expect(a.equals(b)).toBe(true);
    });
  });
});
