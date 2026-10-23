import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { sessionKey } from '../app/session.ts';
import { Login } from './Login.tsx';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('sign-in', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends password and code together and keeps the session', async () => {
    const calls: { url: string; body: unknown }[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string, init?: RequestInit) => {
        calls.push({
          url,
          body:
            typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
        });
        if (url === '/api/whoami') {
          return Promise.resolve(
            json({
              score: null,
              class: null,
              reasons: [],
              request_id: null,
              ip_prefix: null,
            }),
          );
        }
        return Promise.resolve(
          json({
            user: { name: 'ops', role: 'operator' },
            csrf: 'token',
            expires_at: 1,
          }),
        );
      }),
    );
    const client = new QueryClient();
    render(
      <QueryClientProvider client={client}>
        <Login />
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Username'), 'ops');
    await user.type(screen.getByLabelText('Password'), 'right-password');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(
      screen.getByRole('heading', { name: 'Two-factor check' }),
    ).toBeInTheDocument();
    await user.type(screen.getByLabelText('Code'), '12a3456');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    expect(calls.find((call) => call.url === '/api/session')?.body).toEqual({
      username: 'ops',
      password: 'right-password',
      totp: '123456',
    });
    expect(client.getQueryData(sessionKey)).toMatchObject({
      user: { name: 'ops' },
    });
  });

  it('says what went wrong without telling which part', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) =>
        Promise.resolve(
          url === '/api/whoami'
            ? json({
                score: null,
                class: null,
                reasons: [],
                request_id: null,
                ip_prefix: null,
              })
            : json({ error: 'wrong user name, password or code' }, 401),
        ),
      ),
    );
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Login />
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Enter your user name and password.',
    );
    await user.type(screen.getByLabelText('Username'), 'ops');
    await user.type(screen.getByLabelText('Password'), 'x');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    // The sixth digit submits by itself.
    await user.type(screen.getByLabelText('Code'), '000000');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The user name, password or code is wrong.',
    );
  });

  it('tells a slow server from a slow network', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) =>
        Promise.resolve(
          url === '/api/whoami'
            ? json({
                score: 15,
                class: 'human',
                reasons: ['relayed_connection'],
                request_id: null,
                ip_prefix: null,
                passkeys: false,
              })
            : json({ server_ms: 1, loop_ms: 240, gateway_ms: null }),
        ),
      ),
    );
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Login />
      </QueryClientProvider>,
    );
    const check = screen.getByRole('region', { name: 'Connection check' });
    expect(check).toHaveTextContent('Checking your connection');
    expect(
      await within(check).findByText(
        'The server is slow, not your connection.',
        {},
        { timeout: 3000 },
      ),
    ).toBeInTheDocument();
    expect(check).toHaveTextContent('admin API does not answer');
    expect(check).toHaveTextContent('ran 240 ms late');
    expect(check).toHaveTextContent('Answered6 of 6');
    expect(check).toHaveTextContent('connection relayed');
  });
});
