/**
 * OBS-08 — /live vs /ready differentiation (k8s-style liveness/readiness).
 *
 * `/live`  : the process answers HTTP — always 200 while the app is up.
 * `/ready` : the service is ready for traffic — 200 only when
 *            mcp_server_ready && egress_guard_active && audit_logger_ready.
 * `/health`: backward-compatible alias of `/ready` (same status semantics).
 *
 * This suite exercises the real Express app (`createHardenedOAuthApp`) over
 * an actual HTTP round-trip, forcing readiness into a failing state and
 * asserting that /live stays 200 while /ready (and /health) flip to 503.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';

import {
  startFullOauthFixture,
  type FullOauthFixture,
} from './helpers/oauth-server-fixture.js';
import { installEgressGuard, uninstallEgressGuard } from '../src/security/egress-guard.js';
import { resetAuditSaltCache } from '../src/security/audit-salt.js';
import { resetAuditSaltValidationState } from '../src/security/audit-logger.js';

/**
 * Plain node:http GET — deliberately NOT `globalThis.fetch`. Several tests
 * below call `installEgressGuard()` (to make `egress_guard_active`
 * observably true), which monkey-patches `globalThis.fetch` to reject any
 * non-Graph host — including our own loopback test client. `node:http` is
 * untouched by the guard, so it stays a faithful "real HTTP round-trip"
 * client regardless of the guard's install state.
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

describe('GET /live vs GET /ready (OBS-08)', () => {
  let fixture: FullOauthFixture;
  let tmpBase: string;
  let savedXdg: string | undefined;

  beforeEach(() => {
    tmpBase = mkdtempSync(join(tmpdir(), 'health-live-ready-test-'));
    savedXdg = process.env.XDG_STATE_HOME;
    process.env.XDG_STATE_HOME = tmpBase;
    resetAuditSaltCache();
    resetAuditSaltValidationState();
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

  it('both /live and /ready return 200 when everything is healthy', async () => {
    installEgressGuard();
    fixture = await startFullOauthFixture();

    const live = await httpGetJson(`${fixture.baseUrl}/live`);
    const ready = await httpGetJson(`${fixture.baseUrl}/ready`);

    expect(live.status).toBe(200);
    expect(ready.status).toBe(200);
  });

  it('/live stays 200 while /ready (and its alias /health) return 503 when the egress guard is not installed', async () => {
    // Do NOT call installEgressGuard() — simulates a readiness-blocking
    // failure without touching the process's liveness at all.
    fixture = await startFullOauthFixture();

    const live = await fetch(new URL('/live', fixture.baseUrl));
    const ready = await fetch(new URL('/ready', fixture.baseUrl));
    const health = await fetch(new URL('/health', fixture.baseUrl));

    expect(live.status).toBe(200);
    expect(ready.status).toBe(503);
    expect(health.status).toBe(503);

    const readyBody = await ready.json();
    expect(readyBody.egress_guard_active).toBe(false);

    const healthBody = await health.json();
    // /health is an alias of /ready — same shape and status flags. uptime_s
    // is excluded from the comparison because each request captures a fresh
    // `process.uptime()` sample and will differ by a few milliseconds.
    expect({ ...healthBody, uptime_s: undefined }).toEqual({
      ...readyBody,
      uptime_s: undefined,
    });
  });

  it('/live never includes the readiness component flags (liveness has a narrower contract)', async () => {
    fixture = await startFullOauthFixture();

    const resp = await fetch(new URL('/live', fixture.baseUrl));
    const body = await resp.json();

    expect(resp.status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.mcp_server_ready).toBeUndefined();
    expect(body.egress_guard_active).toBeUndefined();
    expect(body.audit_logger_ready).toBeUndefined();
  });

  it('/live returns 200 even when /ready would be 503 for a disabled /mcp mount', async () => {
    installEgressGuard();
    fixture = await startFullOauthFixture({ disableMcpRoutes: true });

    const live = await httpGetJson(`${fixture.baseUrl}/live`);
    const ready = await httpGetJson(`${fixture.baseUrl}/ready`);

    expect(live.status).toBe(200);
    expect(ready.status).toBe(503);
    expect(ready.body.mcp_server_ready).toBe(false);
  });
});
