// Contract of the analytics queries: deploy/clickhouse/schema.sql (without
// the NATS tables and their views) on a real ClickHouse, fixture events,
// then every query of sql.ts through createAnalytics and
// createClickHouseRun as the console runs them, as a readonly = 2 user.
//
// ClickHouse: CLICKHOUSE_URL (user "default" without a password, e.g. a CI
// service), else a clickhouse/clickhouse-server container started here.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { type ClickHouseClient, createClient } from '@clickhouse/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { requestFilterSchema } from '../../shared/api.ts';
import { type Analytics, createAnalytics } from '../analytics/analytics.ts';
import { createClickHouseRun } from '../analytics/clickhouse.ts';
import { prerequisite, REPO, waitFor } from './env.ts';

const IMAGE =
  process.env['CLICKHOUSE_IMAGE'] ?? 'clickhouse/clickhouse-server:25.8';
const GIVEN_URL = process.env['CLICKHOUSE_URL'];
const DATABASE = 'bot_shield';

function dockerMissing(): string | undefined {
  if (GIVEN_URL !== undefined) return undefined;
  try {
    execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 10_000 });
    return undefined;
  } catch {
    return 'no CLICKHOUSE_URL and Docker is not available';
  }
}

const ready = prerequisite('ClickHouse', dockerMissing());

// schema.sql statements, without comments and without what needs NATS.
export function schemaStatements(sql: string): string[] {
  return sql
    .replace(/--.*$/gm, '')
    .split(';')
    .map((statement) => statement.trim())
    .filter((statement) => statement !== '')
    .filter((statement) => !/NATS|_queue\b/.test(statement));
}

const MINUTE = 60_000;
const NOW = Date.now();

// A bot_shield.req row; `ago` in ms before NOW.
function event(index: number, ago: number, fields: Record<string, unknown>) {
  const ts = NOW - ago;
  return {
    ts: new Date(ts).toISOString().replace('T', ' ').replace('Z', ''),
    instance: 'contract',
    conn_id: index,
    seq: 1,
    ip_prefix: '203.0.113.0/24',
    ip_hash: 'aaaa1111',
    http_version: 'h2',
    method: 'GET',
    host: 'a.test',
    path_group: '/',
    header_fp: 'hf-chrome',
    header_names: ['user-agent', 'accept'],
    pseudo_order: 'masp',
    has_cookie: false,
    has_referer: false,
    sni: 'a.test',
    ja4: 'JA4_CHROME',
    tcp_fp: 'tcp-mac',
    ja4t: '',
    ja4h: 'ge20nn',
    h2_fp: 'h2-chrome',
    user_agent: 'Chrome',
    accept: '*/*',
    accept_language: 'en',
    accept_encoding: 'gzip',
    sec_ch_ua: '"Chromium";v="141"',
    sec_ch_ua_mobile: '?0',
    sec_ch_ua_platform: '"macOS"',
    sec_fetch_site: 'none',
    sec_fetch_mode: 'navigate',
    sec_fetch_dest: 'document',
    sec_fetch_user: '?1',
    status: 200,
    duration_ms: 12,
    response_bytes: 1024,
    local: false,
    score: 10,
    class: 'human',
    reasons: [],
    action: 'allow',
    would_action: 'allow',
    rate_limit: '',
    request_id: `contract-${index}-1`,
    watermark: '',
    features: [0.5, 1],
    model_score: null,
    client_fp: '',
    signed_agent: '',
    asn: 64500,
    tcp_rtt_us: null,
    handshake_us: null,
    alpn: 'h2',
    session: '',
    crawler_check: [],
    ...fields,
    _ts: ts,
  };
}

const EVENTS = [
  event(1, 1 * MINUTE, {
    reasons: ['token_valid'],
    session: 'feedfacecafebeef',
    model_score: 0.25,
    tcp_rtt_us: 1500,
    handshake_us: 2000,
  }),
  event(2, 2 * MINUTE, {
    ip_prefix: '198.51.100.0/24',
    ip_hash: 'bbbb2222',
    asn: 13335,
    ja4: 'JA4_CURL',
    user_agent: 'curl/8.0',
    class: 'bot',
    score: 90,
    reasons: ['rule:admin', 'ua_mismatch'],
    action: 'block',
    would_action: 'block',
    status: 403,
    local: true,
    path_group: '/admin/*',
  }),
  event(3, 3 * MINUTE, {
    ip_hash: 'cccc3333',
    asn: 15169,
    class: 'verified_bot',
    score: 0,
    reasons: ['verified_crawler:googlebot'],
  }),
  // Shadow host: would have been blocked.
  event(4, 4 * MINUTE, {
    ip_prefix: '198.51.100.0/24',
    ip_hash: 'dddd4444',
    asn: 13335,
    class: 'bot',
    score: 85,
    reasons: ['fake_crawler:googlebot', 'list:7'],
    crawler_check: [
      'claim:googlebot',
      'ranges:outside',
      'rdns:outside_domains',
      'result:fake',
    ],
    would_action: 'block',
  }),
  event(5, 5 * MINUTE, {
    host: 'b.test',
    sni: 'b.test',
    ip_hash: 'eeee5555',
    asn: 13335,
    class: 'suspicious',
    score: 55,
    reasons: ['headless'],
    action: 'challenge',
    would_action: 'challenge',
  }),
  event(6, 6 * MINUTE, {
    host: 'b.test',
    sni: 'b.test',
    ip_hash: 'eeee5555',
    asn: 13335,
    class: 'suspicious',
    score: 55,
    action: 'rate_limit',
    would_action: 'rate_limit',
    rate_limit: 'limited-path',
    status: 429,
  }),
  // A client that passed a challenge, blocked in enforce mode.
  event(7, 7 * MINUTE, {
    score: 75,
    reasons: ['ua_mismatch', 'token_valid'],
    would_action: 'block',
  }),
  // Outside 24 hours, inside 7 days.
  event(8, 2 * 24 * 60 * MINUTE, {}),
];
const LAST_HOUR = 7;

const sum = (values: number[]) => values.reduce((a, b) => a + b, 0);

describe.skipIf(!ready)('ClickHouse analytics contract', () => {
  let container: string | undefined;
  let dir: string;
  let root: ClickHouseClient;
  let close: () => Promise<void>;
  let analytics: Analytics;

  beforeAll(async () => {
    let url = GIVEN_URL;
    if (url === undefined) {
      container = execFileSync(
        'docker',
        [
          'run',
          '-d',
          '--rm',
          '-e',
          'CLICKHOUSE_SKIP_USER_SETUP=1',
          // The container's own address is unreachable from macOS.
          '-p',
          '127.0.0.1::8123',
          IMAGE,
        ],
        { encoding: 'utf8', timeout: 170_000 },
      ).trim();
      const published = execFileSync(
        'docker',
        ['port', container, '8123/tcp'],
        { encoding: 'utf8' },
      )
        .trim()
        .split('\n')[0];
      url = `http://${published}`;
    }
    await waitFor(
      `ClickHouse at ${url}`,
      async () => (await fetch(`${url}/ping`)).ok,
      60_000,
    );

    root = createClient({ url, username: 'default', password: '' });
    const schema = readFileSync(
      join(REPO, 'deploy', 'clickhouse', 'schema.sql'),
      'utf8',
    );
    await root.command({ query: `DROP DATABASE IF EXISTS ${DATABASE}` });
    for (const statement of schemaStatements(schema)) {
      await root.command({ query: statement });
    }
    await root.insert({
      table: `${DATABASE}.req`,
      values: EVENTS.map(({ _ts, ...row }) => row),
      format: 'JSONEachRow',
    });
    await root.insert({
      table: `${DATABASE}.conn`,
      values: [
        {
          ts: EVENTS[0]?.ts,
          instance: 'contract',
          conn_id: 1,
          listener: 'https',
          ip_prefix: '203.0.113.0/24',
          ip_hash: 'aaaa1111',
          route: 'terminate',
          reason: 'closed',
          duration_ms: 100,
          bytes_in: 1000,
          bytes_out: 5000,
          requests: 1,
          sni: 'a.test',
          tls_version: '1.3',
          alpn_offered: 'h2,http/1.1',
          alpn: 'h2',
          ja4: 'JA4_CHROME',
          ja4_r: '',
          tcp_fp: 'tcp-mac',
          ja4t: '',
          h2_fp: 'h2-chrome',
          quic_fp: '',
          asn: 64500,
        },
      ],
      format: 'JSONEachRow',
    });

    // The console's user, as in deploy/console.yaml.
    dir = mkdtempSync(join(tmpdir(), 'lg-contract-ch-'));
    const passwordFile = join(dir, 'password');
    writeFileSync(passwordFile, 'contract-password\n');
    await root.command({ query: 'DROP USER IF EXISTS contract_console' });
    await root.command({
      query:
        "CREATE USER contract_console IDENTIFIED BY 'contract-password' SETTINGS readonly = 2",
    });
    await root.command({
      query: `GRANT SELECT ON ${DATABASE}.* TO contract_console`,
    });
    const clickhouse = createClickHouseRun({
      url,
      user: 'contract_console',
      password_file: passwordFile,
    });
    close = clickhouse.close;
    analytics = createAnalytics(DATABASE, clickhouse.run);
  }, 180_000);

  afterAll(async () => {
    await close?.();
    await root?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
    if (container !== undefined) {
      execFileSync('docker', ['rm', '-f', container], { stdio: 'ignore' });
    }
  });

  it('schema: materialized views over req work', async () => {
    const result = await root.query({
      query: `SELECT
  (SELECT sum(requests) FROM ${DATABASE}.fp_hourly) AS fp,
  (SELECT sum(requests) FROM ${DATABASE}.cluster_daily) AS clusters`,
      format: 'JSONEachRow',
    });
    const [row] = await result.json<{ fp: string; clusters: string }>();
    expect(Number(row?.fp)).toBe(EVENTS.length);
    expect(Number(row?.clusters)).toBeGreaterThan(0);
    const candidates = await root.query({
      query: `SELECT count() AS n FROM ${DATABASE}.cluster_candidates(days = 7, min_requests = 1, min_anomaly = 0.1)`,
      format: 'JSONEachRow',
    });
    expect(await candidates.json()).toHaveLength(1);
  });

  it('verdictSeries', async () => {
    const step = 60;
    const hour = await analytics.verdictSeries('1h', NOW);
    const total = (key: 'allowed' | 'challenged' | 'blocked' | 'would_block') =>
      Math.round(sum(hour.map((point) => point[key])) * step);
    // A rate-limit refusal (429) counts as blocked, like block and decoy.
    expect(total('blocked')).toBe(2);
    expect(total('challenged')).toBe(1);
    expect(total('allowed')).toBe(4);
    expect(total('would_block')).toBe(2);
    const week = await analytics.verdictSeries('7d', NOW);
    expect(week.length).toBeGreaterThan(0);
  });

  it('topHosts with sparklines', async () => {
    const hosts = await analytics.topHosts('1h', 5, NOW);
    expect(hosts.map((host) => [host.host, host.requests])).toEqual([
      ['a.test', 5],
      ['b.test', 2],
    ]);
    expect(hosts[0]).toMatchObject({ blocked: 1, would_block: 2 });
    expect(Math.round(sum(hosts[0]?.spark ?? []) * 60)).toBe(5);
  });

  it('blockedReasons, topAsns, crawlerCounts', async () => {
    const reasons = await analytics.blockedReasons('1h');
    expect(reasons[0]).toEqual({ reason: 'ua_mismatch', requests: 2 });
    expect(reasons).toContainEqual({ reason: 'rule:admin', requests: 1 });
    expect(await analytics.topAsns('1h')).toEqual([
      { asn: 13335, requests: 4, blocked: 2, challenged: 1 },
      { asn: 64500, requests: 2, blocked: 0, challenged: 0 },
      { asn: 15169, requests: 1, blocked: 0, challenged: 0 },
    ]);
    expect(await analytics.crawlerCounts(3600)).toEqual([
      { id: 'googlebot', verified: 1, fake: 1 },
    ]);
  });

  it('lag', async () => {
    const lag = await analytics.lag();
    expect(lag).toBeGreaterThan(30);
    expect(lag).toBeLessThan(600);
  });

  it('requests: rows, total and facets', async () => {
    const page = await analytics.requests(
      requestFilterSchema.parse({ range: '1h' }),
    );
    expect(page.total).toBe(LAST_HOUR);
    expect(page.rows.map((row) => row.request_id)).toEqual(
      EVENTS.slice(0, LAST_HOUR).map((row) => row.request_id),
    );
    expect(page.rows[0]?.ts).toBe(EVENTS[0]?._ts);
    expect(page.facets.host).toEqual([
      { value: 'a.test', requests: 5 },
      { value: 'b.test', requests: 2 },
    ]);
    expect(page.facets.action).toContainEqual({
      value: 'rate_limit',
      requests: 1,
    });
  });

  it('requests: every filter at once', async () => {
    const filter = requestFilterSchema.parse({
      range: '1h',
      host: 'a.test,b.test',
      action: 'block,allow',
      class: 'bot',
      reason: 'rule:admin',
      asn: '13335',
      ja4: 'JA4_C',
      ip_prefix: '198.51.100.0/24',
      ip_hash: 'bbbb',
      path: '/admin',
      min_score: '50',
      max_score: '100',
      before: String(NOW),
      limit: '10',
    });
    const page = await analytics.requests(filter);
    expect(page.rows.map((row) => row.request_id)).toEqual([
      EVENTS[1]?.request_id,
    ]);
    expect(page.total).toBe(1);
    // A facet leaves its own dimension out.
    expect(page.facets.class).toEqual([{ value: 'bot', requests: 1 }]);
    const older = await analytics.requests(
      requestFilterSchema.parse({
        range: '1h',
        before: String(EVENTS[2]?._ts),
      }),
    );
    expect(older.rows[0]?.request_id).toBe(EVENTS[3]?.request_id);
  });

  it('request detail', async () => {
    const first = EVENTS[0];
    const blocked = EVENTS[1];
    if (!first || !blocked) throw new Error('fixture');
    expect(await analytics.request(first.request_id, first._ts)).toMatchObject({
      ts: first._ts,
      host: 'a.test',
      header_names: ['user-agent', 'accept'],
      local: false,
      tcp_rtt_us: 1500,
      handshake_us: 2000,
      alpn: 'h2',
      session: 'feedfacecafebeef',
      crawler_check: [],
    });
    const fake = EVENTS[3];
    if (!fake) throw new Error('fixture');
    expect(
      (await analytics.request(fake.request_id, fake._ts))?.crawler_check,
    ).toEqual([
      'claim:googlebot',
      'ranges:outside',
      'rdns:outside_domains',
      'result:fake',
    ]);
    expect(
      (await analytics.request(first.request_id, first._ts))?.model_score,
    ).toBeCloseTo(0.25);
    expect(
      await analytics.request(blocked.request_id, blocked._ts),
    ).toMatchObject({
      local: true,
      status: 403,
      model_score: null,
      tcp_rtt_us: null,
    });
    expect(await analytics.request('missing', NOW)).toBeNull();
  });

  it('challenge history', async () => {
    const challenged = EVENTS[4];
    if (!challenged) throw new Error('fixture');
    expect(
      await analytics.challengeHistory('eeee5555', challenged._ts),
    ).toEqual([
      expect.objectContaining({
        request_id: challenged.request_id,
        step: 'challenge',
        host: 'b.test',
      }),
    ]);
    expect(await analytics.challengeHistory('nobody', challenged._ts)).toEqual(
      [],
    );
  });

  it('fingerprints', async () => {
    const all = await analytics.fingerprints('ja4', undefined, NOW);
    expect(all.rows.map((row) => [row.value, row.requests])).toEqual([
      ['JA4_CHROME', 6],
      ['JA4_CURL', 1],
    ]);
    expect(sum(all.rows[0]?.hourly ?? [])).toBe(6);
    expect(all.rows[0]?.hourly).toHaveLength(24);
    expect(all.kinds).toContainEqual({ kind: 'ja4', distinct: 2 });
    const curl = await analytics.fingerprints('ja4', 'curl', NOW);
    expect(curl.rows).toHaveLength(1);
    expect(curl.rows[0]).toMatchObject({
      value: 'JA4_CURL',
      blocked: 1,
      median_score: 90,
      ua_sample: 'curl/8.0',
    });
    for (const kind of ['h2_fp', 'header_fp', 'tcp_fp'] as const) {
      const rows = (await analytics.fingerprints(kind, undefined, NOW)).rows;
      expect(sum(rows.map((row) => row.requests))).toBe(LAST_HOUR);
    }
  });

  it('reasonCounts, refusedByLimit, ruleSamples', async () => {
    expect(await analytics.reasonCounts('rule:', 3600)).toEqual(
      new Map([['admin', 1]]),
    );
    expect(await analytics.reasonCounts('list:', 3600)).toEqual(
      new Map([['7', 1]]),
    );
    expect(await analytics.refusedByLimit(3600)).toEqual(
      new Map([['limited-path', 1]]),
    );
    const samples = await analytics.ruleSamples(3600, 200);
    expect(samples.total).toBe(LAST_HOUR);
    expect(samples.samples).toHaveLength(LAST_HOUR);
    expect(samples.samples).toContainEqual(
      expect.objectContaining({
        path: '/admin/*',
        reasons: ['rule:admin', 'ua_mismatch'],
        tcp_rtt_us: null,
      }),
    );
  });

  it('consumers, hostStats, busiestHost', async () => {
    const consumers = await analytics.consumers(3600, 'ip_prefix');
    expect(consumers).toContainEqual({
      key: '198.51.100.0/24',
      ip_prefix: '198.51.100.0/24',
      ip_hash_count: 2,
      host: 'a.test',
      rps: 2 / 3600,
      refused: 0,
    });
    expect(
      consumers.find((row) => row.ip_prefix === '203.0.113.0/24')?.refused,
    ).toBe(1);
    // By clearance session: only the client that had one.
    expect(await analytics.consumers(3600, 'session')).toEqual([
      expect.objectContaining({ key: 'feedfacecafebeef', ip_hash_count: 1 }),
    ]);
    expect(
      (await analytics.consumers(3600, 'ip_hash')).map((row) => row.key),
    ).toContain('eeee5555');
    expect(await analytics.hostStats(3600)).toEqual([
      {
        host: 'a.test',
        requests: 5,
        blocked: 1,
        challenged: 0,
        allowed: 4,
        would_block: 2,
      },
      {
        host: 'b.test',
        requests: 2,
        blocked: 1,
        challenged: 1,
        allowed: 0,
        would_block: 0,
      },
    ]);
    expect(await analytics.busiestHost(3600)).toEqual({
      host: 'a.test',
      rps: 5 / 3600,
    });
  });

  it('impostors and attackImpact', async () => {
    expect(await analytics.impostors(3600)).toEqual([
      {
        crawler: 'googlebot',
        ip_prefix: '198.51.100.0/24',
        asn: 13335,
        requests: 1,
        action: 'allow',
        last_seen: EVENTS[3]?._ts,
      },
    ]);
    expect(await analytics.attackImpact(3600)).toEqual({
      requests: LAST_HOUR,
      token: 2,
      verified_or_listed: 2,
    });
  });

  it('readiness', async () => {
    const readiness = await analytics.readiness('a.test', 86_400);
    expect(readiness).toMatchObject({
      requests: 5,
      clients: 4,
      block: {
        requests: 3,
        clients: 3,
        legit_requests: 1,
        legit_clients: 1,
      },
      challenge: { requests: 0, clients: 0 },
    });
    expect(readiness.reasons[0]).toEqual({
      reason: 'ua_mismatch',
      requests: 2,
      clients: 2,
      legit_clients: 1,
    });
    expect(readiness.suspects).toEqual([
      {
        ip_hash: 'aaaa1111',
        ip_prefix: '203.0.113.0/24',
        asn: 64500,
        user_agent: 'Chrome',
        requests: 1,
        reasons: expect.arrayContaining(['ua_mismatch', 'token_valid']),
        evidence: ['passed_challenge', 'classed_human'],
        last_seen: EVENTS[6]?._ts,
      },
    ]);
  });

  it('search', async () => {
    expect(await analytics.search('host', 'A.')).toEqual([
      { value: 'a.test', requests: 5 },
    ]);
    expect(await analytics.search('ja4', 'JA4_')).toHaveLength(2);
    expect(await analytics.search('ip_prefix', '198.')).toEqual([
      { value: '198.51.100.0/24', requests: 2, asn: 13335 },
    ]);
    expect(await analytics.search('ip_hash', 'bbbb')).toEqual([
      { value: 'bbbb2222', requests: 1, asn: 13335 },
    ]);
  });

  // Last: its rows are two days old, outside every window above.
  it('libraryCandidates', async () => {
    const chrome =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
    const iphone =
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1';
    const rows = [
      ...[1, 2, 3].map((n) => ({
        ua: chrome,
        hash: `c${n}`,
        ja4: 't13d1516h2_8daaf6152771_02713d6af862',
        token: true,
      })),
      // Not passed the challenge: ignored.
      {
        ua: chrome,
        hash: 'c9',
        ja4: 't13d1516h2_ffffffffffff_x',
        token: false,
      },
      ...[1, 2].map((n) => ({
        ua: iphone,
        hash: `i${n}`,
        ja4: 't13d2014h2_a09f3c656075_y',
        token: true,
      })),
      // curl that somehow holds a token: no engine.
      {
        ua: 'curl/8.0',
        hash: 'k1',
        ja4: 't13d0000h1_000000000000_z',
        token: true,
      },
    ];
    await root.insert({
      table: `${DATABASE}.req`,
      values: rows.map((row, i) => {
        const { _ts, ...base } = event(900 + i, 2 * 24 * 60 * MINUTE, {
          host: 'lib.test',
          ip_hash: row.hash,
          user_agent: row.ua,
          ja4: row.ja4,
          pseudo_order: 'm,a,s,p',
          reasons: row.token ? ['token_valid'] : [],
        });
        return base;
      }),
      format: 'JSONEachRow',
    });
    const stacks = await analytics.libraryCandidates(7 * 86_400, 2);
    expect(
      stacks.map(({ first_seen, last_seen, ua_sample, ...s }) => s),
    ).toEqual([
      {
        engine: 'chromium',
        ciphers: '8daaf6152771',
        pseudo_order: 'm,a,s,p',
        clients: 3,
        requests: 3,
      },
      {
        engine: 'webkit',
        ciphers: 'a09f3c656075',
        pseudo_order: 'm,a,s,p',
        clients: 2,
        requests: 2,
      },
    ]);
    expect(await analytics.libraryCandidates(86_400, 2)).toEqual([]);
  });
});
