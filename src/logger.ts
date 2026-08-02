import winston from 'winston';
import path from 'path';
import { homedir, hostname } from 'node:os';
import fs from 'fs';
import { redactSensitiveDeep } from './security/log-redactor.js';
import { getRequestId } from './request-context.js';

/**
 * Resolve the logs directory location, in priority order :
 *
 *   1. `OUTLOOK_MCP_LOGS_DIR` env var — explicit operator override
 *   2. `XDG_STATE_HOME/outlook-mcp/logs/` — XDG Base Dir spec
 *   3. `~/.local/state/outlook-mcp/logs/` — XDG default fallback
 *
 * Resolves N0 cross-review OBSERVATION O3 (2026-05-10) : previously the
 * logs directory was `path.join(__dirname, '..', 'logs')` which lands under
 * the module installation path. Under `npm install -g`, that's typically
 * `/usr/lib/node_modules/...` (root-owned) and `mkdirSync` would fail at
 * runtime. Under `npx`, it lands in the cache dir, which can collide
 * between invocations of the same binary.
 *
 * XDG Base Directory Specification gives us a stable, per-user, writeable
 * location regardless of how the package was installed.
 */
function resolveLogsDir(): string {
  if (process.env.OUTLOOK_MCP_LOGS_DIR) return process.env.OUTLOOK_MCP_LOGS_DIR;
  const stateHome = process.env.XDG_STATE_HOME || path.join(homedir(), '.local', 'state');
  return path.join(stateHome, 'outlook-mcp', 'logs');
}

const logsDir = resolveLogsDir();

if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true, mode: 0o700 });
}

// Winston stores the splat args (extra `logger.info(msg, a, b)` positional
// args) under this well-known Symbol. Kept as a module-level constant so we
// don't recompute the interned symbol on every log line.
const SPLAT = Symbol.for('splat');

/**
 * Custom winston format that scrubs PII / secrets from log messages BEFORE
 * they reach any transport. Resolves N0 BLOCKER B1 (2026-06-02) : prior to
 * this format, `logger.info(`params: ${JSON.stringify(params)}`)` in
 * graph-tools.ts shipped recipient emails, mail bodies, and JWT-shaped
 * tokens verbatim to mcp-server.log — defeating the audit-logger's salted
 * HMAC pseudonymity (same XDG directory, attacker-acquires-files threat).
 *
 * OBS-03 + OBS-07 extension (2026-08-02) :
 *   - Recurse into EVERY own enumerable property of `info` (not just
 *     `info.message`) so meta objects, error stacks, and deeply nested
 *     structures are covered.
 *   - Unwrap Error instances that ended up in the splat symbol
 *     (`logger.error('X', err)`) into `info.message` + `info.stack` before
 *     redaction, so the `winston.format.json()` transport — which only
 *     serialises own enumerable string keys, NOT the splat symbol — can
 *     still surface the error content in output while ensuring that
 *     content has passed through the redactor.
 *
 * The redactor runs at format-time (before transport.write), so EVERY
 * file/console output is sanitized regardless of which logger.info call
 * site forgot to scrub manually.
 */
const piiRedactFormat = winston.format((info) => {
  // Step 1 — unwrap Error(s) from the splat symbol into `info` fields so
  // the JSON transport (which ignores splat) still emits the diagnostic
  // content. Winston's built-in `format.errors({ stack: true })` only
  // triggers when the Error is `info.message` itself ; the very common
  // `logger.error('label', err)` case (where message='label' and err lives
  // in splat) slips past it.
  const record = info as unknown as Record<string | symbol, unknown>;
  const splat = record[SPLAT];
  if (Array.isArray(splat)) {
    for (const item of splat) {
      if (item instanceof Error) {
        if (typeof record.stack !== 'string' || record.stack.length === 0) {
          record.stack = item.stack;
        }
        if (typeof info.message === 'string' && item.message) {
          info.message = `${info.message}: ${item.message}`;
        }
      }
    }
    // Deep-redact the splat contents anyway. Even though the json transport
    // doesn't emit splat, a future transport (or a debug print) might.
    record[SPLAT] = splat.map((v) => redactSensitiveDeep(v));
  }

  // Step 2 — deep-redact every own enumerable string key. Keys stay
  // untouched ; only string values (and strings found inside nested
  // objects / arrays / Error instances) are rewritten.
  for (const key of Object.keys(info)) {
    record[key] = redactSensitiveDeep(record[key]);
  }
  return info;
});

/**
 * OBS-04 (2026-08-02) : inject the current HTTP request's correlation id
 * into every emission. Reading from AsyncLocalStorage at format-time means
 * call sites do NOT need to thread the id through winston meta explicitly
 * — every `logger.info(...)` fired inside a `requestContext.run(...)` scope
 * gains a `request_id` field automatically, joining audit lines to winston
 * lines for the same request.
 *
 * When there is no active request scope (stdio mode, boot-time logs,
 * background timers) the field is simply omitted.
 *
 * An explicit `request_id` already present on the info object wins — a
 * future call site that has better context (e.g. an outbound Graph retry
 * where we already know the id) can override the ambient value.
 */
const requestIdFormat = winston.format((info) => {
  if (typeof (info as { request_id?: unknown }).request_id !== 'string') {
    const id = getRequestId();
    if (id) {
      (info as { request_id?: string }).request_id = id;
    }
  }
  return info;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  // OBS-05 (2026-08-02) : static process metadata attached to every
  // emission. Useful when logs from multiple hosts / restarts land in a
  // shared aggregator — pid disambiguates concurrent runs, hostname
  // disambiguates hosts, service disambiguates the emitter. Set on the
  // logger (not per-transport) so both file and console inherit.
  defaultMeta: {
    service: 'outlook-mcp',
    hostname: hostname(),
    pid: process.pid,
  },
  format: winston.format.combine(
    // OBS-07 : `format.errors({ stack: true })` handles the case where
    // `info.message` itself is an Error (some call sites do
    // `logger.error(err)`). The splat-Error case is handled in
    // piiRedactFormat above.
    winston.format.errors({ stack: true }),
    // OBS-05 : no format arg → winston uses `new Date().toISOString()`
    // which is RFC 3339 / ISO 8601 UTC with the trailing `Z`. Explicitly
    // NOT localised — cross-host correlation requires a single timezone.
    winston.format.timestamp(),
    // OBS-04 : ambient request id BEFORE redaction so downstream redactor
    // can see (and if needed, sanitize) the field like any other meta.
    requestIdFormat(),
    piiRedactFormat(),
    // OBS-05 : structured JSON output instead of `printf`. Log
    // aggregators (Loki, ELK, Datadog…) parse JSON natively ; ad-hoc
    // printf lines require brittle regex parsers on ingest.
    winston.format.json()
  ),
  transports: [
    // HARDENED (OBS-01 fix, 2026-08-02) : File transports MUST have rotation
    // caps, otherwise mcp-server.log grows unbounded and fills the disk.
    // Audit stratégique MAINT-03 : winston.transports.File sans maxsize +
    // maxFiles + tailable = disque plein garanti à moyen terme (usage prod
    // perso Jimmy). Choix : 10 MB × 5 fichiers = 50 MB cap (raisonnable),
    // tailable pour que le fichier "actif" reste toujours mcp-server.log.
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),
    new winston.transports.File({
      filename: path.join(logsDir, 'mcp-server.log'),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),
  ],
});

export const enableConsoleLogging = (): void => {
  logger.add(
    new winston.transports.Console({
      // Console keeps the human-readable simple format — the interactive
      // dev use-case wants a colourised one-liner, not JSON. The
      // logger-level piiRedactFormat has already scrubbed the payload
      // before this transport-level format runs.
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
      silent: process.env.SILENT === 'true' || process.env.SILENT === '1',
    })
  );
};

/** Resolved logs directory (exported for diagnostics + tests). */
export { logsDir };

export default logger;
