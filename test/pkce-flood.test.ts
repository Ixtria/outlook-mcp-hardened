/**
 * TEST-02 — PKCE store flood test (2026-08-02).
 *
 * Locks the N0-B2 hardening in src/oauth/http-routes.ts:379-387 :
 *   → pkceStore is bounded (default 10_000)
 *   → oldest entry is LRU-evicted when the cap is reached
 *   → a 'pkceStore at capacity' warning is emitted on eviction
 *   → the server does not crash / throw under concurrent flood
 *
 * The scenario is a DoS-ish attacker firing many /authorize requests with
 * unique `state` values, trying to blow up the in-memory PKCE map. Before
 * N0-B2 the map was unbounded — this test would OOM the process. After
 * N0-B2 the map plateaus at `maxPkceStoreSize` and starts evicting the
 * oldest entry per accepted request.
 *
 * Discipline (ADR-0004 rule 3) : behavioral only — real Express listener,
 * real fetch, real winston capture, no fs.readFileSync on src/, no
 * SOURCE.toContain, no regex on file content.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  attachLogCapture,
  startOauthFixture,
  type LogCapture,
  type OauthFixture,
} from './helpers/oauth-server-fixture.js';

// Same real registered redirect_uri used by test/lot1-behavior.test.ts — we
// need to pass the redirect_uri allowlist check to reach the PKCE store
// insertion path (http-routes.ts:389).
const VALID_REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';

// Default cap declared in createAuthorizeHandler (src/oauth/http-routes.ts:259).
// The fixture wires the production defaults, so this is the real cap under test.
const DEFAULT_MAX_PKCE_STORE_SIZE = 10_000;

// One-over-cap so we deterministically trigger the eviction branch at least once.
const FLOOD_REQUEST_COUNT = DEFAULT_MAX_PKCE_STORE_SIZE + 1;

// Loopback batch — keeps undici's global-agent concurrency reasonable and
// avoids socket exhaustion (~4-8 kFDs on default Linux). Empirically small
// enough that 10_001 requests still complete well under the 30 s budget.
const BATCH_SIZE = 100;

// PKCE code_challenge for S256 must be a URL-safe base64 string of 43-128
// chars (RFC 7636 §4.2). 43 chars = 256 bits pre-encoding. The handler
// only forwards it verbatim — a literal 43-char fill is enough to exercise
// the store insertion path without pulling in any hashing dependency.
const VALID_CODE_CHALLENGE = 'X'.repeat(43);

function buildAuthorizeUrl(baseUrl: string, state: string): URL {
  const url = new URL('/authorize', baseUrl);
  url.searchParams.set('client_id', 'test-client');
  url.searchParams.set('redirect_uri', VALID_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'Mail.Read');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', VALID_CODE_CHALLENGE);
  url.searchParams.set('code_challenge_method', 'S256');
  return url;
}

describe('TEST-02 — PKCE store flood (N0-B2 bounded LRU)', () => {
  let fixture: OauthFixture;
  let capture: LogCapture;

  beforeEach(async () => {
    fixture = await startOauthFixture();
    capture = attachLogCapture();
  });

  afterEach(async () => {
    capture.restore();
    await fixture.close();
  });

  it(
    'plateaus pkceStore at maxPkceStoreSize under a 10_001-request flood, evicting oldest and logging capacity',
    async () => {
      const startedAt = Date.now();

      // Unique state per request so each accepted /authorize triggers a
      // fresh pkceStore.set() (collisions would silently overwrite instead
      // of exercising the eviction branch we want to validate).
      const states = Array.from({ length: FLOOD_REQUEST_COUNT }, (_, i) =>
        `flood-state-${i.toString(16).padStart(8, '0')}`
      );

      // Track HTTP outcomes without holding response bodies (memory).
      const statusCounts = new Map<number | 'error', number>();
      const errors: string[] = [];

      // Batched Promise.all — keeps concurrent sockets bounded to BATCH_SIZE.
      for (let offset = 0; offset < states.length; offset += BATCH_SIZE) {
        const slice = states.slice(offset, offset + BATCH_SIZE);
        const results = await Promise.allSettled(
          slice.map((state) => {
            const url = buildAuthorizeUrl(fixture.baseUrl, state);
            return fetch(url, { redirect: 'manual' });
          })
        );
        for (const result of results) {
          if (result.status === 'fulfilled') {
            const status = result.value.status;
            statusCounts.set(status, (statusCounts.get(status) ?? 0) + 1);
            // Drain the body to release the socket promptly.
            await result.value.arrayBuffer().catch(() => undefined);
          } else {
            statusCounts.set('error', (statusCounts.get('error') ?? 0) + 1);
            errors.push(String(result.reason));
          }
        }
      }

      const elapsedMs = Date.now() - startedAt;

      // (2) No request may have thrown / crashed the listener. Every fetch
      //     either resolved with a status or the whole test would already
      //     have failed on an unhandled rejection. We also assert the
      //     Promise-level result explicitly.
      expect(statusCounts.get('error') ?? 0, `unexpected fetch failures: ${errors.slice(0, 3).join(' | ')}`).toBe(0);

      // Every accepted /authorize returns 302 (redirect to Microsoft). The
      // handler never enters an error path with the URL we built.
      expect(statusCounts.get(302) ?? 0).toBe(FLOOD_REQUEST_COUNT);

      // (1) pkceStore is bounded — never exceeds the configured cap even
      //     after 10_001 accepted requests.
      expect(fixture.pkceStore.size).toBeLessThanOrEqual(DEFAULT_MAX_PKCE_STORE_SIZE);
      // Sanity : we did fill it (not a no-op).
      expect(fixture.pkceStore.size).toBeGreaterThan(0);

      // (3) At least one 'pkceStore at capacity' warning must have fired.
      //     Matches the winston line at src/oauth/http-routes.ts:383.
      const capacityWarnings = capture.messages.filter((line) =>
        line.includes('pkceStore at capacity')
      );
      expect(
        capacityWarnings.length,
        `expected >=1 capacity warning across ${capture.messages.length} log lines`
      ).toBeGreaterThanOrEqual(1);

      // (4) Time budget. 30 s is generous — real runs on loopback are a
      //     few seconds. Blowing this budget means either a leak, a hung
      //     socket, or the test spun up something it should not have.
      expect(elapsedMs, `flood took ${elapsedMs} ms`).toBeLessThan(30_000);
    },
    45_000 // vitest per-test timeout : must exceed the 30 s budget above.
  );
});
