import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AdminError, createAdminClient } from './admin.ts';
import { parsePrometheus } from './metrics.ts';

describe('parsePrometheus', () => {
  it('reads samples and sums labelled series', () => {
    const samples = parsePrometheus(
      [
        '# HELP x y',
        '# TYPE bot_shield_proxied_requests_total counter',
        'bot_shield_proxied_requests_total{source="upstream"} 10',
        'bot_shield_proxied_requests_total{source="local"} 5',
        'bot_shield_nats_connected 1',
        'garbage line',
        'bad_value{a="b"} NaNx',
      ].join('\n'),
    );
    expect(samples.get('bot_shield_proxied_requests_total')).toBe(15);
    expect(
      samples.get('bot_shield_proxied_requests_total{source="local"}'),
    ).toBe(5);
    expect(samples.get('bot_shield_nats_connected')).toBe(1);
    expect(samples.has('garbage')).toBe(false);
  });
});

describe('admin client', () => {
  let dir: string;
  let socket: string;
  let server: Server;
  let handler: (method: string, url: string, body: string) => [number, unknown];

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'lg-admin-'));
    socket = join(dir, 'admin.sock');
    server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk: Buffer) => (body += chunk.toString()));
      req.on('end', () => {
        const [status, json] = handler(req.method ?? '', req.url ?? '', body);
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(typeof json === 'string' ? json : JSON.stringify(json));
      });
    });
    await new Promise<void>((resolve) => server.listen(socket, resolve));
  });

  afterEach(async () => {
    await new Promise<void>((resolve) =>
      server.close(() => {
        resolve();
      }),
    );
    rmSync(dir, { recursive: true, force: true });
  });

  it('drops the full address from decisions', async () => {
    handler = (method, url) => {
      expect(method).toBe('GET');
      expect(url).toBe('/decisions/a-1-2');
      return [
        200,
        {
          request_id: 'a-1-2',
          time_ms: 1,
          host: 'shop.test',
          method: 'GET',
          path_group: '/',
          ip: '203.0.113.77',
          ip_prefix: '203.0.113.0/24',
          ip_hash: 'abcd',
          user_agent: 'x',
          ja4: 'j',
          h2_fp: '',
          header_fp: '',
          mode: 'shadow',
          score: 80,
          class: 'bot',
          reasons: ['r'],
          action: 'allow',
          would_action: 'block',
          status: 200,
          local: false,
          duration_ms: 3,
        },
      ];
    };
    const decision = await createAdminClient(socket).decision('a-1-2');
    expect(decision).not.toBeNull();
    expect(decision).not.toHaveProperty('ip');
    expect(decision?.ip_prefix).toBe('203.0.113.0/24');
    expect(JSON.stringify(decision)).not.toContain('203.0.113.77');
  });

  it('returns null for unknown decisions and throws gateway errors', async () => {
    handler = (_method, url) =>
      url.startsWith('/decisions')
        ? [404, { error: 'unknown request id' }]
        : [422, { error: 'col 3: unknown name', column: 3 }];
    const client = createAdminClient(socket);
    expect(await client.decision('x')).toBeNull();
    const error = await client.testRule('a b', []).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AdminError);
    expect((error as AdminError).status).toBe(422);
    expect((error as AdminError).column).toBe(3);
  });

  it('rejects responses that do not match the schema', async () => {
    handler = () => [200, { version: 1 }];
    await expect(createAdminClient(socket).status()).rejects.toMatchObject({
      status: 502,
    });
    handler = () => [200, 'not json'];
    await expect(createAdminClient(socket).status()).rejects.toMatchObject({
      status: 502,
    });
  });

  it('sends JSON bodies and encodes path segments', async () => {
    const seen: string[] = [];
    handler = (method, url, body) => {
      seen.push(`${method} ${url} ${body}`);
      return [200, { removed: 'x' }];
    };
    const client = createAdminClient(socket);
    await client.setMode('shop.test', 'enforce');
    expect(await client.clearMode('*.a/b')).toBe(true);
    expect(seen).toEqual([
      'POST /policy {"host":"shop.test","mode":"enforce"}',
      'DELETE /policy/*.a%2Fb ',
    ]);
  });

  it('reports an unreachable socket as 503', async () => {
    const client = createAdminClient(join(dir, 'missing.sock'));
    await expect(client.status()).rejects.toMatchObject({ status: 503 });
  });
});
