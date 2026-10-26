// Contract of the admin API: the real gateway binary behind a fake Traefik,
// every call of createAdminClient against it, so each response goes
// through the schema the console relies on. Skipped without a built
// gateway (see env.ts).

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { request } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  type AdminApi,
  AdminError,
  createAdminClient,
  type RuleSampleEvent,
} from '../gateway/admin.ts';
import {
  type Child,
  findGateway,
  findOpenssl,
  freePort,
  makeCert,
  prerequisite,
  startChild,
  waitFor,
} from './env.ts';

const found = findGateway();
const openssl = findOpenssl();
const setup =
  typeof found !== 'string' && openssl !== undefined
    ? { ...found, openssl }
    : undefined;
const ready = prerequisite(
  'Gateway',
  typeof found === 'string'
    ? found
    : openssl === undefined
      ? 'openssl not found'
      : undefined,
);

const HOST = 'a.test';
const CHROME_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

const portOpen = (port: number) =>
  new Promise<boolean>((done) => {
    const socket = connect(port, '127.0.0.1');
    socket.once('connect', () => {
      socket.destroy();
      done(true);
    });
    socket.once('error', () => done(false));
  });

describe.skipIf(!ready)('gateway admin API contract', () => {
  let dir: string;
  let upstream: Child;
  let gateway: Child;
  let asnServer: Server;
  let admin: AdminApi;
  let httpsPort: number;
  let ca: string;

  // A request through the gateway; the fake Traefik echoes what it got.
  function get(path: string): Promise<{ status: number; body: string }> {
    return new Promise((done, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port: httpsPort,
          servername: HOST,
          ca,
          path,
          headers: { host: HOST, 'user-agent': CHROME_UA, accept: '*/*' },
          agent: false,
        },
        (res) => {
          let body = '';
          res.on('data', (chunk: Buffer) => (body += chunk.toString()));
          res.on('end', () => done({ status: res.statusCode ?? 0, body }));
        },
      );
      req.on('error', reject);
      req.end();
    });
  }

  beforeAll(async () => {
    if (setup === undefined) throw new Error('unreachable');
    dir = mkdtempSync(join(tmpdir(), 'lg-contract-'));
    const gw = makeCert(setup.openssl, dir, 'gw', [HOST]);
    const up = makeCert(setup.openssl, dir, 'upstream', [HOST]);
    ca = readFileSync(gw.cert, 'utf8');
    const acme = join(dir, 'acme.json');
    writeFileSync(
      acme,
      JSON.stringify({
        le: {
          Account: {},
          Certificates: [
            {
              domain: { main: HOST },
              certificate: readFileSync(gw.cert).toString('base64'),
              key: readFileSync(gw.key).toString('base64'),
              Store: 'default',
            },
          ],
        },
      }),
    );

    const [tlsPort, plainPort, metricsPort] = [
      await freePort(),
      await freePort(),
      await freePort(),
    ];
    httpsPort = await freePort();
    upstream = startChild(setup.upstream, [
      String(tlsPort),
      String(plainPort),
      up.cert,
      up.key,
    ]);
    await waitFor('fake upstream', () => portOpen(tlsPort));

    // ASN database download (iptoasn format).
    asnServer = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/tab-separated-values' });
      res.end(
        '1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n' +
          '127.0.0.0\t127.255.255.255\t64500\tZZ\tContract-ISP Example\n',
      );
    });
    await new Promise<void>((done) =>
      asnServer.listen(0, '127.0.0.1', () => done()),
    );
    const asnAddress = asnServer.address();
    if (asnAddress === null || typeof asnAddress === 'string') {
      throw new Error('ASN server has no port');
    }

    const socket = join(dir, 'admin.sock');
    const config = join(dir, 'bot-shield.yaml');
    writeFileSync(
      config,
      `listen:
  https: 127.0.0.1:${httpsPort}
  http: ""
workers: 1
traefik:
  acme_json: ${acme}
  acme_reload_interval: 200ms
  upstream_https: 127.0.0.1:${tlsPort}
  upstream_http: 127.0.0.1:${plainPort}
mode: shadow
policy:
  hosts:
    www.${HOST}: enforce
rules:
  - name: admin
    when: 'path ~ "/admin*"'
    action: block
rate_limits:
  - name: limited-path
    paths: ["/limited*"]
    key: [ip, host]
    rate: 3/m
crawlers:
  ip_ranges: false
asn:
  url: http://127.0.0.1:${asnAddress.port}/ip2asn.tsv
events:
  ip_salt: contract-salt
admin:
  socket: ${socket}
  state_file: ${join(dir, 'lists.json')}
  modes_file: ${join(dir, 'modes.json')}
  settings_file: ${join(dir, 'settings.yaml')}
  decisions: 100
metrics:
  listen: 127.0.0.1:${metricsPort}
log_level: info
`,
    );
    gateway = startChild(setup.binary, ['--config', config]);
    try {
      await waitFor('gateway /health', async () => {
        const response = await fetch(`http://127.0.0.1:${metricsPort}/health`);
        return response.ok;
      });
    } catch (error) {
      throw new Error(`${String(error)}\ngateway log:\n${gateway.output()}`);
    }
    admin = createAdminClient(socket);
  }, 60_000);

  afterAll(async () => {
    await gateway?.stop();
    await upstream?.stop();
    await new Promise((done) => asnServer?.close(done) ?? done(undefined));
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('status', async () => {
    const status = await admin.status();
    expect(status.mode).toBe('shadow');
    expect(status.workers).toBe(1);
    expect(status.certificates).toBeGreaterThan(0);
    expect(status.config_hash).toMatch(/^[0-9a-f]{12}$/);
    expect(status.worker_beats).toHaveLength(1);
    expect(status.worker_beats[0]?.age_ms).toBeLessThan(5000);
  });

  it('config', async () => {
    const config = await admin.config();
    expect(config.rules.map((rule) => rule.name)).toContain('admin');
    expect(config.rate_limits.map((limit) => limit.name)).toContain(
      'limited-path',
    );
    expect(config.crawlers.catalog.length).toBeGreaterThan(0);
  });

  it('policy overview and per host', async () => {
    const overview = await admin.policyOverview();
    expect(overview.default).toBe('shadow');
    expect(overview.policy_hosts).toContainEqual({
      host: `www.${HOST}`,
      mode: 'enforce',
    });
    const policy = await admin.policy(`www.${HOST}`);
    expect(policy).toMatchObject({
      mode: 'enforce',
      mode_source: 'policy.hosts',
      certificate: false,
    });
    expect(await admin.policy(HOST)).toMatchObject({
      mode: 'shadow',
      mode_source: 'mode',
      route: 'terminate',
      certificate: true,
    });
  });

  it('console host modes', async () => {
    await admin.setMode(HOST, 'off');
    expect(await admin.policy(HOST)).toMatchObject({
      mode: 'off',
      mode_source: 'console',
    });
    expect((await admin.policyOverview()).console).toContainEqual({
      host: HOST,
      mode: 'off',
    });
    expect(await admin.clearMode(HOST)).toBe(true);
    expect(await admin.clearMode(HOST)).toBe(false);
    expect((await admin.policy(HOST)).mode_source).toBe('mode');
  });

  it('lists', async () => {
    const full = await admin.addList({
      kind: 'ip',
      value: '192.0.2.0/24',
      action: 'block',
      host: HOST,
      ttl: '5m',
      comment: 'contract',
    });
    expect(full).toMatchObject({ host: HOST, comment: 'contract' });
    expect(full.expires_at).toBeGreaterThan(full.created_at);
    // Without host and comment (the gateway leaves them out of its JSON).
    const bare = await admin.addList({
      kind: 'ja4',
      value: 't13d1516h2_8daaf6152771_02713d6af862',
      action: 'allow',
    });
    expect(bare).toMatchObject({ host: '', comment: '' });
    // Extended in place, then made permanent.
    const extended = await admin.updateList(full.id, {
      ttl: '2h',
      comment: 'longer',
    });
    expect(extended).toMatchObject({ id: full.id, comment: 'longer' });
    expect(extended?.expires_at).toBeGreaterThan(full.expires_at);
    expect((await admin.updateList(full.id, { ttl: null }))?.expires_at).toBe(
      0,
    );
    expect(await admin.updateList(999_999, { ttl: '1h' })).toBeNull();
    const asn = await admin.addList({
      kind: 'asn',
      value: 'AS64500',
      action: 'block',
    });
    expect(asn.value).toBe('64500');
    expect(await admin.removeList(asn.id)).toBe(true);
    const entries = await admin.lists();
    expect(entries.map((entry) => entry.id)).toEqual(
      expect.arrayContaining([full.id, bare.id]),
    );
    expect(await admin.removeList(full.id)).toBe(true);
    expect(await admin.removeList(bare.id)).toBe(true);
    expect(await admin.removeList(bare.id)).toBe(false);
    expect(await admin.lists()).toEqual([]);
  });

  it('decisions of proxied requests', async () => {
    const response = await get('/contract/page?x=1');
    expect(response.status).toBe(200);
    const echoed = JSON.parse(response.body) as {
      headers: Record<string, string>;
    };
    const requestId = echoed.headers['x-bot-request-id'];
    expect(requestId).toBeTruthy();
    const decision = await admin.decision(requestId ?? '');
    expect(decision).toMatchObject({
      request_id: requestId,
      host: HOST,
      method: 'GET',
      mode: 'shadow',
      user_agent: CHROME_UA,
      status: 200,
      local: false,
    });
    expect(decision?.ip_prefix).toBe('127.0.0.0/24');
    expect(decision?.ip_hash).toMatch(/\S/);
    expect(decision).not.toHaveProperty('ip');
    expect(await admin.decision('no-such-request')).toBeNull();
  });

  it('attack mode', async () => {
    await admin.enableAttack(HOST, '5m');
    await admin.enableAttack(`www.${HOST}`);
    const state = await admin.attack();
    const timed = state.entries.find((entry) => entry.host === HOST);
    expect(timed?.until).toBeGreaterThan(timed?.since ?? 0);
    expect(
      state.entries.find((entry) => entry.host === `www.${HOST}`)?.until,
    ).toBeUndefined();
    expect(await admin.disableAttack(HOST)).toBe(true);
    expect(await admin.disableAttack(`www.${HOST}`)).toBe(true);
    expect(await admin.disableAttack(HOST)).toBe(false);
    expect((await admin.attack()).entries).toEqual([]);
  });

  it('rule tests: compile and errors', async () => {
    const result = await admin.testRule('path ~ "/admin*" and score >= 50', []);
    expect(result).toEqual({
      references: expect.arrayContaining(['path', 'score']),
      evaluated: 0,
      matched: [],
    });
    const error = await admin
      .testRule('path ~ ', [])
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AdminError);
    expect((error as AdminError).status).toBe(422);
    expect((error as AdminError).column).toBeGreaterThan(0);
  });

  // The console sends up to 200 sampled events: a body of many kilobytes.
  it('rule tests on samples', async () => {
    const sample: RuleSampleEvent = {
      host: HOST,
      method: 'GET',
      path: '/admin/panel',
      http_version: 'HTTP/2',
      sni: HOST,
      ja4: 't13d1516h2_8daaf6152771_02713d6af862',
      h2_fp: '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
      pseudo_order: 'masp',
      header_fp: 'abc123',
      tcp_fp: '',
      user_agent: CHROME_UA,
      score: 80,
      class: 'bot',
      reasons: ['ua_mismatch'],
      asn: 64500,
      signed_agent: '',
      ip_prefix: '192.0.2.0/24',
      tcp_rtt_us: 1200,
      handshake_us: null,
    };
    const result = await admin.testRule('path ~ "/admin*" and score >= 50', [
      sample,
      { ...sample, path: '/' },
      { ...sample, score: 10 },
    ]);
    expect(result.evaluated).toBe(3);
    expect(result.matched).toEqual([0]);
  });

  it('AS numbers', async () => {
    let asns: Awaited<ReturnType<AdminApi['asns']>> = [];
    await waitFor('ASN database', async () => {
      asns = await admin.asns([64500, 13335, 65535]);
      return asns.length > 0;
    });
    expect(asns).toContainEqual(
      expect.objectContaining({ asn: 64500, org: 'Contract-ISP Example' }),
    );
    expect(asns.map((info) => info.asn)).not.toContain(65535);
  });

  it('reload', async () => {
    const result = await admin.reload();
    expect(result.summary).toMatch(/\S/);
    // The files did not change: nothing to report, the same hash.
    expect(result.changes).toEqual([]);
    expect(result.config_hash).toBe((await admin.status()).config_hash);
  });

  it('settings: read, validate, apply, history, rollback', async () => {
    const before = await admin.settings();
    expect(before.editable).toBe(true);
    const threshold = before.keys.find(
      (key) => key.path === 'policy.thresholds.suspicious',
    );
    expect(threshold).toMatchObject({ secret: false, apply: 'live' });
    const salt = before.keys.find((key) => key.path === 'events.ip_salt');
    expect(salt).toEqual(
      expect.objectContaining({ secret: true, set: true, source: 'file' }),
    );
    expect(salt).not.toHaveProperty('value');
    const value =
      threshold && !threshold.secret ? Number(threshold.value) + 1 : 31;

    const change = {
      base_revision: before.revision,
      set: { 'policy.thresholds.suspicious': value, 'events.ip_salt': 'new' },
      reset: [],
    };
    const preview = await admin.validateSettings(change);
    expect(preview.changes.map((entry) => entry.path).sort()).toEqual([
      'events.ip_salt',
      'policy.thresholds.suspicious',
    ]);
    expect((await admin.settings()).revision).toBe(before.revision);

    const applied = await admin.applySettings(change);
    expect(applied.revision).not.toBe(before.revision);
    expect(
      applied.changes.find((entry) => entry.path === 'events.ip_salt'),
    ).toMatchObject({ secret: true, set_after: true, value_changed: true });
    expect(
      applied.changes.find(
        (entry) => entry.path === 'policy.thresholds.suspicious',
      ),
    ).toMatchObject({ secret: false, after: value, source_after: 'console' });
    expect((await admin.config()).policy.suspicious_threshold).toBe(value);

    const history = await admin.settingsHistory();
    expect(history.revision).toBe(applied.revision);
    const previous = history.versions[0];
    expect(previous).toBeDefined();

    const rolled = await admin.rollbackSettings(
      previous?.revision ?? '',
      applied.revision,
    );
    expect(rolled.changes.length).toBeGreaterThan(0);
    const after = await admin.settings();
    expect(
      after.keys.find((key) => key.path === 'policy.thresholds.suspicious'),
    ).toMatchObject({ source: threshold?.source });

    // Refusals name the key.
    const stale = await admin
      .applySettings({ ...change, base_revision: before.revision })
      .catch((caught: unknown) => caught);
    expect(stale).toBeInstanceOf(AdminError);
    expect((stale as AdminError).status).toBe(409);
    const refused = await admin
      .validateSettings({
        base_revision: after.revision,
        set: { 'traefik.acme_json': '/elsewhere' },
        reset: [],
      })
      .catch((caught: unknown) => caught);
    expect(refused).toBeInstanceOf(AdminError);
    expect((refused as AdminError).path).toBe('traefik.acme_json');
  });
});
