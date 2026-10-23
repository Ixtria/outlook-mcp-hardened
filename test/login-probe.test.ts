/**
 * #35 — `--login` reported 'Graph API access failed: 403' after a successful
 * login: testLogin() probed /v1.0/me, which needs User.Read, a scope this
 * server never requests. The probe must stay within the requested scopes.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AccountInfo } from '@azure/msal-node';

import AuthManager from '../src/auth.js';

const ACCOUNT = {
  homeAccountId: 'home-id',
  environment: 'login.microsoftonline.com',
  tenantId: 'tenant',
  localAccountId: 'local-id',
  username: 'jimmy@example.com',
  name: 'Jimmy',
} as AccountInfo;

function makeManager(scopes: string[]): AuthManager {
  const manager = new AuthManager(
    { auth: { clientId: '00000000-0000-0000-0000-000000000000' } },
    scopes,
  );
  vi.spyOn(manager, 'getToken').mockResolvedValue('fake-access-token');
  vi.spyOn(manager, 'getCurrentAccount').mockResolvedValue(ACCOUNT);
  return manager;
}

function stubGraph(handler: (url: string) => Response): string[] {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL) => {
      const url = String(input);
      calls.push(url);
      return handler(url);
    }),
  );
  return calls;
}

describe('testLogin probe (#35)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('succeeds without User.Read: never calls /v1.0/me when mail scopes are granted', async () => {
    // Graph answers 403 on /me (no User.Read), 200 on mailbox resources.
    const calls = stubGraph((url) =>
      new URL(url).pathname === '/v1.0/me'
        ? new Response('Forbidden', { status: 403 })
        : new Response('{"id":"x"}', { status: 200 }),
    );

    const result = await makeManager([
      'Mail.Read',
      'Calendars.Read',
    ]).testLogin();

    expect(result).toEqual({
      success: true,
      message: 'Login successful',
      userData: {
        displayName: 'Jimmy',
        userPrincipalName: 'jimmy@example.com',
      },
    });
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0]!).pathname).toBe('/v1.0/me/mailFolders/inbox');
  });

  it('probes calendars when only calendar scopes are requested', async () => {
    const calls = stubGraph(
      () => new Response('{"value":[]}', { status: 200 }),
    );

    const result = await makeManager(['Calendars.ReadWrite']).testLogin();

    expect(result.success).toBe(true);
    expect(new URL(calls[0]!).pathname).toBe('/v1.0/me/calendars');
  });

  it('skips the Graph check instead of failing when no readable scope is requested', async () => {
    // --enabled-tools '^send-mail$' --enable-send requests Mail.Send only:
    // probing the inbox would 403 exactly like /me did.
    const calls = stubGraph(() => new Response('Forbidden', { status: 403 }));

    const result = await makeManager(['Mail.Send']).testLogin();

    expect(result.success).toBe(true);
    expect(result.message).toContain('not checked');
    expect(calls).toHaveLength(0);
  });

  it('probes mailbox settings when they are the only readable scope', async () => {
    const calls = stubGraph(() => new Response('{}', { status: 200 }));

    const result = await makeManager(['MailboxSettings.Read', 'Mail.Send']).testLogin();

    expect(result.success).toBe(true);
    expect(new URL(calls[0]!).pathname).toBe('/v1.0/me/mailboxSettings/timeZone');
  });

  it('reports the account that just logged in, not the previously selected one', async () => {
    const SECOND = { ...ACCOUNT, homeAccountId: 'second', username: 'second@example.com', name: 'Second' };
    const manager = new AuthManager(
      { auth: { clientId: '00000000-0000-0000-0000-000000000000' } },
      ['Mail.Read']
    );
    // ACCOUNT is already selected; the device-code login authenticates SECOND.
    (manager as unknown as { selectedAccountId: string }).selectedAccountId = ACCOUNT.homeAccountId;
    vi.spyOn(manager, 'getCurrentAccount').mockResolvedValue(ACCOUNT);
    vi.spyOn(manager, 'saveTokenCache').mockResolvedValue();
    const msalApp = (manager as unknown as { msalApp: { acquireTokenByDeviceCode: unknown } })
      .msalApp;
    vi.spyOn(msalApp as never, 'acquireTokenByDeviceCode').mockResolvedValue({
      accessToken: 'second-token',
      account: SECOND,
      expiresOn: new Date(Date.now() + 3600_000),
      scopes: ['Mail.Read'],
    } as never);
    stubGraph(() => new Response('{"id":"x"}', { status: 200 }));

    await manager.acquireTokenByDeviceCode(() => {});
    const result = await manager.testLogin();

    expect(result.userData).toEqual({
      displayName: 'Second',
      userPrincipalName: 'second@example.com',
    });
  });

  it('still reports a real Graph failure on the probed resource', async () => {
    stubGraph(() => new Response('Unauthorized', { status: 401 }));

    const result = await makeManager(['Mail.Read']).testLogin();

    expect(result).toEqual({
      success: false,
      message: 'Login successful but Graph API access failed: 401',
    });
  });
});
