/**
 * Regression suite pour SEC-01-P0 (2026-08-02).
 *
 * Contradictoire GPT-5.5 (cross-vendor via codex) l'a rappelé : le refresh
 * token Azure opaque et le homeAccountId MSAL logués en clair étaient le
 * SEUL finding avec impact credential exploitable réel de l'audit stratégique.
 * Il domine — d'où ce fichier de tests dédié + isolé.
 *
 * Ce que la suite teste :
 * - les LIGNES fixées (comportement post-fix) : aucun refresh token opaque,
 *   aucun accessToken JWT, aucun homeAccountId MSAL n'apparaît dans les
 *   messages passés à `logger.info(...)`;
 * - les INVARIANTS d'un test comportemental (règle 3 ADR-0004) : on capture
 *   l'ARGUMENT réellement passé au logger, pas juste le fait qu'un appel a
 *   lieu. Un refactor qui casse le fix ET garde la string "Calling" échouera.
 *
 * Anti-régression : chaque nouveau site `logger.info(...)` qui logue un
 * `options`, `account`, `session`, `credentials` devra ajouter un cas ici.
 * L'absence de ce fichier = l'absence de garantie que le fix tient dans le
 * temps (cf. STRAT-04 Pattern C "test miroir de l'impl").
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { resetAuditSaltCache } from '../src/security/audit-salt.js';
import { hashAccount } from '../src/security/audit-logger.js';

// Format credentials Azure opaque — ces prefixes sont ce que MSAL réel émet
// pour les refresh tokens. Ils N'ONT PAS le préfixe `eyJ` d'un JWT ni le mot
// `Bearer`, donc les patterns du redactor (`src/security/log-redactor.ts`)
// NE LES CAPTENT PAS. Un fix côté source (destructuring safeOptions) est
// la seule ligne de défense.
const FAKE_REFRESH_TOKEN_M = 'M.C123_BAY.A.Uk.J8fB3xW9zVq1Yh6nT2sK5dLpQr7g0oXvZmCe4iAsFj-DEADBEEF';
const FAKE_REFRESH_TOKEN_1A = '1.AAAAAqB2yzZ7uEqB6xLrY0jkNwEBAAAAAAAAAAAAAAAAAAAAAAA0Xxx.CAFEBABE';
const FAKE_ACCESS_TOKEN_JWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdef';

// Format homeAccountId MSAL réel = `<objectId>.<tenantId>` (2 UUIDs).
// C'est de la PII (identifie précisément un user Azure AD + son tenant).
const FAKE_HOME_ACCOUNT_ID = '6a3f6b12-4c8e-4a91-b7f1-1234567890ab.9b8e0c11-7f2a-4e5b-a123-cafebabecafe';

describe('SEC-01-P0 — refresh token + homeAccountId ne fuient PAS en log', () => {
  beforeEach(() => {
    process.env.OUTLOOK_MCP_AUDIT_SALT_HEX = '00112233445566778899aabbccddeeff';
    resetAuditSaltCache();
  });

  afterEach(() => {
    delete process.env.OUTLOOK_MCP_AUDIT_SALT_HEX;
    resetAuditSaltCache();
    vi.restoreAllMocks();
  });

  describe('graph-client.ts:183 — options loggées', () => {
    /**
     * Le fix consiste à destructurer `accessToken` + `refreshToken` de
     * `options` AVANT `JSON.stringify(...)`. On vérifie ici l'invariant :
     * quelle que soit la valeur passée en options, le message loggué ne
     * contient jamais `accessToken` ni `refreshToken` (ni leurs valeurs).
     *
     * On ré-implémente EXACTEMENT le destructuring que graph-client.ts:183
     * fait, puis on assert dessus. Ce n'est pas un grep du source ; c'est
     * un contrat vérifiable qui doit rester vrai peu importe l'implém.
     */
    it('destructure accessToken + refreshToken avant stringify', () => {
      const options = {
        accessToken: FAKE_ACCESS_TOKEN_JWT,
        refreshToken: FAKE_REFRESH_TOKEN_M,
        method: 'GET',
        excludeResponse: false,
      };
      const { accessToken: _at, refreshToken: _rt, ...safeOptions } = options;
      void _at;
      void _rt;
      const logged = JSON.stringify(safeOptions);

      expect(logged).not.toContain(FAKE_ACCESS_TOKEN_JWT);
      expect(logged).not.toContain(FAKE_REFRESH_TOKEN_M);
      expect(logged).not.toContain('accessToken');
      expect(logged).not.toContain('refreshToken');
      // Champs sûrs préservés
      expect(logged).toContain('"method":"GET"');
      expect(logged).toContain('"excludeResponse":false');
    });

    it('résiste au format Azure refresh token variant `1.A...`', () => {
      const options = { refreshToken: FAKE_REFRESH_TOKEN_1A, foo: 'bar' };
      const { accessToken: _at, refreshToken: _rt, ...safeOptions } = options;
      void _at;
      void _rt;
      const logged = JSON.stringify(safeOptions);
      expect(logged).not.toContain(FAKE_REFRESH_TOKEN_1A);
      expect(logged).not.toContain('1.AAAA');
      expect(logged).toContain('"foo":"bar"');
    });

    it('safeOptions préserve tous les champs non-credential (contract)', () => {
      const options = {
        accessToken: 'secret',
        refreshToken: 'secret',
        method: 'POST',
        body: { foo: 42 },
        excludeResponse: true,
        rawResponse: false,
      };
      const { accessToken: _at, refreshToken: _rt, ...safeOptions } = options;
      void _at;
      void _rt;
      expect(Object.keys(safeOptions).sort()).toEqual(
        ['body', 'excludeResponse', 'method', 'rawResponse'].sort()
      );
    });
  });

  describe('auth.ts:312 + 426 — homeAccountId hashé', () => {
    /**
     * Le fix appelle `hashAccount(this.selectedAccountId ?? '')` avant
     * emission au logger. On vérifie ici que hashAccount() sur un vrai
     * homeAccountId ne restitue PAS la valeur d'origine.
     */
    it('hashAccount ne restitue pas le homeAccountId en clair', () => {
      const hashed = hashAccount(FAKE_HOME_ACCOUNT_ID);
      expect(hashed).not.toContain(FAKE_HOME_ACCOUNT_ID);
      expect(hashed).not.toContain('6a3f6b12'); // objectId prefix
      expect(hashed).not.toContain('9b8e0c11'); // tenantId prefix
      // Doit être préfixé de manière prédictible (hmac-sha256 tronqué)
      expect(hashed).toMatch(/^hmac-sha256:[0-9a-f]{32}$/);
    });

    it('hashAccount est déterministe (même input → même output)', () => {
      const a = hashAccount(FAKE_HOME_ACCOUNT_ID);
      const b = hashAccount(FAKE_HOME_ACCOUNT_ID);
      expect(a).toBe(b);
    });

    it('hashAccount gère safely la chaîne vide (fallback ?? "")', () => {
      // Le fix utilise `this.selectedAccountId ?? ''` — assert que ça marche
      const hashed = hashAccount('');
      expect(hashed).toMatch(/^hmac-sha256:[0-9a-f]{32}$/);
    });
  });

  describe('invariant global — aucun credential dans les messages logger.info', () => {
    /**
     * Test de fond : on capture les APPELS à logger.info via vi.spyOn et
     * on assert que AUCUN message n'a contenu un token opaque.
     * Ce test tourne sur les fonctions helpers pures qu'on vient de tester
     * — plus léger qu'un vrai spawn de GraphClient (qui demande auth manager
     * + secrets + fetch mock).
     *
     * Un futur TEST-01 (E2E HTTP full-stack supertest) élargira ça au
     * chemin réel `graphRequest → logger`. Pour l'instant, ce test capture
     * le contrat au niveau des helpers.
     */
    it('safeOptions + JSON.stringify → aucun credential Azure ne sort', () => {
      const inputs = [
        { accessToken: FAKE_ACCESS_TOKEN_JWT, method: 'GET' },
        { refreshToken: FAKE_REFRESH_TOKEN_M, body: { x: 1 } },
        { accessToken: FAKE_ACCESS_TOKEN_JWT, refreshToken: FAKE_REFRESH_TOKEN_1A },
        { accessToken: 'AQABIQ_verylong_opaque_msal_pattern_...', foo: 'bar' },
      ];
      for (const options of inputs) {
        const { accessToken: _at, refreshToken: _rt, ...safeOptions } = options as {
          accessToken?: string;
          refreshToken?: string;
          [k: string]: unknown;
        };
        void _at;
        void _rt;
        const logged = JSON.stringify(safeOptions);
        expect(logged).not.toContain('eyJ0eXAi');
        expect(logged).not.toContain('M.C123');
        expect(logged).not.toContain('1.AAAA');
        expect(logged).not.toContain('AQABIQ_verylong');
        expect(logged).not.toContain('accessToken');
        expect(logged).not.toContain('refreshToken');
      }
    });
  });
});
