/**
 * OBS-06 — health endpoint (enriched shape + alerting-relevant flags).
 *
 * Boots the exact production Express app (`createHardenedOAuthApp`) on an
 * ephemeral loopback port and exercises GET /health as a real HTTP
 * round-trip — no source-content assertions (ADR-0004 rule 3).
 *
 * The audit-logger readiness flag is backed by the RUNTIME-SEC-01 boot-time
 * posture check (`validateAuditSaltFile`) against an isolated
 * `XDG_STATE_HOME`, so this suite can deterministically flip
 * `audit_logger_ready` by corrupting the on-disk salt file's permissions.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import {
  startFullOauthFixture,
  type FullOauthFixture,
} from './helpers/oauth-server-fixture.js';
import { installEgressGuard, uninstallEgressGuard } from '../src/security/egress-guard.js';
import { resetAuditSaltCache } from '../src/security/audit-salt.js';
import { resetAuditSaltValidationState } from '../src/security/audit-logger.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const packageJson = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as {
  version: string;
};

const SALT_REL_PATH = 'outlook-mcp/audit-salt';

function saltPathFor(base: string): string {
  return join(base, SALT_REL_PATH);
}

/**
 * Plain node:http GET — deliberately NOT `globalThis.fetch`. These tests
 * call `installEgressGuard()` (to make `egress_guard_active` observably
 * true), which monkey-patches `globalThis.fetch` to reject any non-Graph
 * host — including our own loopback test client. `node:http` is untouched
 * by the guard, so it stays a faithful "real HTTP round-trip" client.
 */
function httpGetJson(url: string): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode ?? 0, body: JSON.parse(data) });
          } catch (err) {
            reject(err);
          }
        });
      })
      .on('error', reject);
  });
}

describe('GET /health (OBS-06)', () => {
  let fixture: FullOauthFixture;
  let tmpBase: string;
  let savedXdg: string | undefined;

  beforeEach(() => {
    tmpBase = mkdtempSync(join(tmpdir(), 'health-endpoint-test-'));
    savedXdg = process.env.XDG_STATE_HOME;
    process.env.XDG_STATE_HOME = tmpBase;
    resetAuditSaltCache();
    resetAuditSaltValidationState();
    installEgressGuard();
  });

  afterEach(async () => {
    await fixture?.close();
    uninstallEgressGuard();
    rmSync(tmpBase, { recursive: true, force: true });
    if (savedXdg === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = savedXdg;
    resetAuditSaltCache();
    resetAuditSaltValidationState();
  });

  it('returns 200 with the enriched shape when all components are healthy', async () => {
    fixture = await startFullOauthFixture();

    const { status, body } = await httpGetJson(`${fixture.baseUrl}/health`);
    expect(status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.version).toBe(packageJson.version);
    expect(typeof body.uptime_s).toBe('number');
    expect(body.uptime_s).toBeGreaterThanOrEqual(0);
    expect(body.node_version).toBe(process.version);
    expect(body.mcp_server_ready).toBe(true);
    expect(body.egress_guard_active).toBe(true);
    expect(body.audit_logger_ready).toBe(true);
  });

  it('returns 503 when the audit-logger posture check fails (world-readable salt)', async () => {
    // Corrupt the on-disk salt BEFORE the app is even asked for health, so
    // the very first /health call observes the unsafe posture.
    const saltPath = saltPathFor(tmpBase);
    mkdirSync(join(tmpBase, 'outlook-mcp'), { recursive: true, mode: 0o700 });
    writeFileSync(saltPath, Buffer.from('0123456789abcdef', 'utf8'), { mode: 0o644 });
    chmodSync(saltPath, 0o644); // umask can strip bits during writeFileSync

    fixture = await startFullOauthFixture();

    const { status, body } = await httpGetJson(`${fixture.baseUrl}/health`);
    expect(status).toBe(503);
    expect(body.status).toBe('error');
    expect(body.audit_logger_ready).toBe(false);
    // Other components are unaffected by the audit-logger failure.
    expect(body.mcp_server_ready).toBe(true);
    expect(body.egress_guard_active).toBe(true);
  });

  it('reports egress_guard_active=false and 503 when the guard was never installed', async () => {
    // Simulate a boot path that skipped installEgressGuard() (should never
    // happen in production — index.ts calls it unconditionally — but the
    // health check must still catch the drift if it ever did).
    uninstallEgressGuard();
    fixture = await startFullOauthFixture();

    const resp = await fetch(new URL('/health', fixture.baseUrl));
    expect(resp.status).toBe(503);

    const body = await resp.json();
    expect(body.egress_guard_active).toBe(false);
    expect(body.status).toBe('error');
  });
});
