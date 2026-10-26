import { createServer, type Server } from 'node:http';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTraefikClient, ruleMatchesHost } from './traefik.ts';

describe('ruleMatchesHost', () => {
  it('reads Host, HostSNI and HostRegexp', () => {
    expect(
      ruleMatchesHost('Host(`shop.example.com`)', 'Shop.Example.com'),
    ).toBe(true);
    expect(
      ruleMatchesHost(
        'Host(`a.example.com`, `b.example.com`) && PathPrefix(`/api`)',
        'b.example.com',
      ),
    ).toBe(true);
    expect(ruleMatchesHost('Host(`a.example.com`)', 'b.example.com')).toBe(
      false,
    );
    expect(
      ruleMatchesHost('HostSNI(`grpc.example.com`)', 'grpc.example.com'),
    ).toBe(true);
    expect(ruleMatchesHost('HostSNI(`*`)', 'anything.example.com')).toBe(true);
    expect(
      ruleMatchesHost('HostRegexp(`^.+\\.example\\.com$`)', 'x.example.com'),
    ).toBe(true);
    expect(ruleMatchesHost('HostRegexp(`(`)', 'x.example.com')).toBe(false);
    expect(ruleMatchesHost('PathPrefix(`/`)', 'x.example.com')).toBe(false);
  });
});

describe('createTraefikClient', () => {
  let server: Server;
  let base = '';

  beforeAll(async () => {
    server = createServer((request, response) => {
      const url = new URL(request.url ?? '/', 'http://x');
      const page = Number(url.searchParams.get('page'));
      const send = (body: unknown, next?: number) => {
        response.writeHead(200, {
          'content-type': 'application/json',
          ...(next ? { 'x-next-page': String(next) } : {}),
        });
        response.end(JSON.stringify(body));
      };
      switch (url.pathname) {
        case '/api/http/routers':
          // Two pages: the client follows X-Next-Page.
          if (page === 1) {
            send(
              [
                {
                  name: 'shop@docker',
                  rule: 'Host(`shop.example.com`)',
                  service: 'shop',
                  provider: 'docker',
                  status: 'enabled',
                  entryPoints: ['websecure'],
                  tls: { options: 'default' },
                },
              ],
              2,
            );
          } else {
            send([
              {
                name: 'other@file',
                rule: 'Host(`other.example.com`)',
                service: 'other@file',
                provider: 'file',
                status: 'enabled',
              },
            ]);
          }
          return;
        case '/api/tcp/routers':
          send([
            {
              name: 'grpc@docker',
              rule: 'HostSNI(`shop.example.com`)',
              service: 'grpc',
              provider: 'docker',
              status: 'enabled',
              tls: { passthrough: true },
            },
          ]);
          return;
        case '/api/http/services':
          send([
            {
              name: 'shop@docker',
              status: 'enabled',
              loadBalancer: { servers: [{ url: 'http://10.0.0.5:80' }] },
              serverStatus: { 'http://10.0.0.5:80': 'UP' },
            },
          ]);
          return;
        case '/api/tcp/services':
          send([
            {
              name: 'grpc@docker',
              status: 'enabled',
              loadBalancer: { servers: [{ address: '10.0.0.6:50051' }] },
            },
          ]);
          return;
        default:
          response.writeHead(404).end();
      }
    });
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('');
    base = `http://127.0.0.1:${address.port}`;
  });

  afterAll(() => {
    server.close();
  });

  it('matches routers of the host across pages and protocols', async () => {
    const routes = await createTraefikClient(base).routes('shop.example.com');
    expect(routes).toEqual([
      expect.objectContaining({
        protocol: 'http',
        name: 'shop@docker',
        service: 'shop@docker',
        tls_options: 'default',
        servers: [{ target: 'http://10.0.0.5:80', status: 'UP' }],
      }),
      expect.objectContaining({
        protocol: 'tcp',
        name: 'grpc@docker',
        passthrough: true,
        servers: [{ target: '10.0.0.6:50051', status: null }],
      }),
    ]);
    expect(
      (await createTraefikClient(base).routes('other.example.com'))[0]?.service,
    ).toBe('other@file');
  });

  it('fails when the API is not there', async () => {
    await expect(
      createTraefikClient(`${base}/nope/`).routes('shop.example.com'),
    ).rejects.toThrow(/HTTP 404/);
  });
});
