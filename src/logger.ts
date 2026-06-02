import winston from 'winston';
import path from 'path';
import { homedir } from 'node:os';
import fs from 'fs';
import { redactSensitive } from './security/log-redactor.js';

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

/**
 * Custom winston format that scrubs PII / secrets from log messages BEFORE
 * they reach any transport. Resolves N0 BLOCKER B1 (2026-06-02) : prior to
 * this format, `logger.info(`params: ${JSON.stringify(params)}`)` in
 * graph-tools.ts shipped recipient emails, mail bodies, and JWT-shaped
 * tokens verbatim to mcp-server.log — defeating the audit-logger's salted
 * HMAC pseudonymity (same XDG directory, attacker-acquires-files threat).
 *
 * The redactor runs at format-time (before transport.write), so EVERY
 * file/console output is sanitized regardless of which logger.info call
 * site forgot to scrub manually.
 */
const piiRedactFormat = winston.format((info) => {
  if (typeof info.message === 'string') {
    info.message = redactSensitive(info.message);
  }
  return info;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    piiRedactFormat(),
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss',
    }),
    winston.format.printf(({ level, message, timestamp }) => {
      return `${timestamp} ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
    }),
    new winston.transports.File({
      filename: path.join(logsDir, 'mcp-server.log'),
    }),
  ],
});

export const enableConsoleLogging = (): void => {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
      silent: process.env.SILENT === 'true' || process.env.SILENT === '1',
    })
  );
};

/** Resolved logs directory (exported for diagnostics + tests). */
export { logsDir };

export default logger;
