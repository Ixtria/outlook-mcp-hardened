/**
 * Behavioral tests for the full winston pipeline (OBS-03 + OBS-05 + OBS-07).
 *
 * These tests attach a Winston Stream transport to the shared logger
 * singleton (via `attachLogCapture()` from the Workflow-1 fixture) and
 * assert on the STRING that is actually handed to a transport — i.e. the
 * exact byte-sequence that would land in `mcp-server.log`. This closes the
 * gap left by `test/log-redactor.test.ts`, which only exercises the pure
 * `redactSensitive()` helper : that test cannot detect a regression where
 * the redactor is fine but the winston format chain routes around it
 * (splat args, meta objects, error stacks — the historical leak vectors
 * of B1 + SEC-01 + OBS-07).
 *
 * Discipline (ADR-0004 rule 3) : NO grep on source, NO `fs.readFileSync`
 * on `logger.ts`. All assertions are on observable log output.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import logger from '../src/logger.js';
import { attachLogCapture, type LogCapture } from './helpers/oauth-server-fixture.js';
import { resetAuditSaltCache } from '../src/security/audit-salt.js';

// Realistic MSAL / OAuth token shapes (also used by the SEC-01 regression
// suite). Kept out of any real credential — these are byte-shape twins so
// the regex is exercised, nothing more.
const REFRESH_TOKEN_M = 'M.C_TOKEN.example.blob.DEADBEEF1234567890abcdef';
const REFRESH_TOKEN_1A = '1.AAAAAxxxxx.CAFEBABE.example.blob.tokenmaterial';
const REFRESH_TOKEN_AQAB = 'AQABIQabcdef1234567890examplerefreshtokenblob';
const ACCESS_TOKEN_JWT =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZUBleGFtcGxlLmNvbSJ9.SFLKvL9pE-XeF3vJ8Kp0nQabc123';
const RECIPIENT_EMAIL = 'target-recipient@example.com';

/** Assert helper : the concatenated capture contains ZERO occurrences of a secret. */
function expectNoLeak(capture: LogCapture, needle: string): void {
  const joined = capture.messages.join('\n');
  expect(joined, `secret leaked into log output: ${needle}`).not.toContain(needle);
}

describe('winston pipeline — OBS-03 + OBS-05 + OBS-07 behavioral', () => {
  let capture: LogCapture;

  beforeEach(() => {
    process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = '00112233445566778899aabbccddeeff';
    resetAuditSaltCache();
    capture = attachLogCapture();
  });

  afterEach(() => {
    capture.restore();
    delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    resetAuditSaltCache();
  });

  describe('OBS-05 — output format is JSON with static process metadata', () => {
    it('emits a parseable JSON line per log call', () => {
      logger.info('pipeline check', { anyExtra: 'noSecret' });
      expect(capture.messages).toHaveLength(1);
      // The line MUST parse as JSON — no printf leftover.
      expect(() => JSON.parse(capture.messages[0]!)).not.toThrow();
    });

    it('every line carries service / hostname / pid defaultMeta', () => {
      logger.info('meta check');
      const record = JSON.parse(capture.messages[0]!);
      expect(record.service).toBe('outlook-mcp');
      expect(record.pid).toBe(process.pid);
      expect(typeof record.hostname).toBe('string');
      expect(record.hostname.length).toBeGreaterThan(0);
    });

    it('timestamp is ISO 8601 UTC (Z suffix)', () => {
      logger.info('timestamp check');
      const record = JSON.parse(capture.messages[0]!);
      // e.g. "2026-08-02T14:03:19.482Z"
      expect(record.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/);
    });

    it('level is preserved on the JSON record', () => {
      logger.warn('level check');
      const record = JSON.parse(capture.messages[0]!);
      expect(record.level).toBe('warn');
    });
  });

  describe('OBS-03 — deep-meta recursive redaction', () => {
    it('redacts a JWT-shaped token nested inside a meta object', () => {
      logger.info('graph call', {
        request: {
          headers: { Authorization: `Bearer ${ACCESS_TOKEN_JWT}` },
          nested: { deeper: { accessToken: ACCESS_TOKEN_JWT } },
        },
      });
      expectNoLeak(capture, ACCESS_TOKEN_JWT);
    });

    it('redacts an email nested inside a meta object', () => {
      logger.info('send-mail params', {
        params: {
          toRecipients: [{ emailAddress: { address: RECIPIENT_EMAIL } }],
          subject: 'Q4 report',
        },
      });
      expectNoLeak(capture, RECIPIENT_EMAIL);
      // The (non-PII) subject stays for debuggability.
      expect(capture.messages.join('\n')).toContain('Q4 report');
    });

    it('redacts an Azure MSAL refresh-token (M.*) inside a nested meta', () => {
      logger.info('token cache mutation', {
        cache: { entries: [{ refresh_token: REFRESH_TOKEN_M }] },
      });
      expectNoLeak(capture, REFRESH_TOKEN_M);
      expectNoLeak(capture, 'M.C_TOKEN');
    });

    it('redacts refresh-token variants 1.A* and AQAB* nested in meta', () => {
      logger.info('token variant A', { rt: REFRESH_TOKEN_1A });
      logger.info('token variant B', { rt: REFRESH_TOKEN_AQAB });
      expectNoLeak(capture, REFRESH_TOKEN_1A);
      expectNoLeak(capture, REFRESH_TOKEN_AQAB);
    });

    it('keys are not touched — safe keys like "accessToken" or "email" remain visible', () => {
      // We redact VALUES, not KEYS — an operator reading the log still sees
      // WHICH field carried the secret (helpful for triage). The value is
      // the only thing that must not leak.
      logger.info('key preservation', {
        payload: { accessToken: ACCESS_TOKEN_JWT, email: RECIPIENT_EMAIL },
      });
      const joined = capture.messages.join('\n');
      expect(joined).toContain('accessToken');
      expect(joined).toContain('email');
      expect(joined).not.toContain(ACCESS_TOKEN_JWT);
      expect(joined).not.toContain(RECIPIENT_EMAIL);
    });

    it('handles a cycle in the meta without throwing', () => {
      const meta: { self?: unknown; token: string } = { token: ACCESS_TOKEN_JWT };
      meta.self = meta;
      expect(() => logger.info('cyclic meta', { meta })).not.toThrow();
      expectNoLeak(capture, ACCESS_TOKEN_JWT);
    });
  });

  describe('OBS-07 — logger.error(msg, err) splat still redacts', () => {
    it('redacts a refresh-token embedded in an Error message', () => {
      logger.error('token refresh failed', new Error(`refresh: ${REFRESH_TOKEN_M}`));
      expectNoLeak(capture, REFRESH_TOKEN_M);
      expectNoLeak(capture, 'M.C_TOKEN');
    });

    it('redacts a JWT embedded in an Error stack', () => {
      // Fabricate a stack that carries the JWT — real MSAL stacks routinely
      // include the token in the "at request(..., 'Bearer …')" frame.
      const err = new Error('graph call failed');
      err.stack = `Error: graph call failed\n    at Object.<anonymous> (Bearer ${ACCESS_TOKEN_JWT})`;
      logger.error('outbound call failure', err);
      expectNoLeak(capture, ACCESS_TOKEN_JWT);
    });

    it('surface the Error content in the JSON output (not swallowed by splat)', () => {
      logger.error('operation label', new Error('inner reason'));
      const record = JSON.parse(capture.messages[0]!);
      // The message is either the concatenation (label + inner) or contains
      // the inner reason ; either way the diagnostic content must be there.
      const joined = `${record.message ?? ''} ${record.stack ?? ''}`;
      expect(joined).toContain('inner reason');
    });

    it('redacts an email inside the message argument itself', () => {
      logger.info(`sending to ${RECIPIENT_EMAIL} now`);
      expectNoLeak(capture, RECIPIENT_EMAIL);
    });

    it('redacts a JSON-dumped payload containing a JWT (regression B1)', () => {
      // graph-tools.ts historically logged `params: ${JSON.stringify(params)}`
      // — that's a single string argument, and B1's original scope.
      const params = {
        headers: { Authorization: `Bearer ${ACCESS_TOKEN_JWT}` },
        toRecipients: [{ emailAddress: { address: RECIPIENT_EMAIL } }],
      };
      logger.info(`Tool send-mail params: ${JSON.stringify(params)}`);
      expectNoLeak(capture, ACCESS_TOKEN_JWT);
      expectNoLeak(capture, RECIPIENT_EMAIL);
    });
  });
});
