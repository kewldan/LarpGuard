// Analytics from ClickHouse: runs the queries in sql.ts and shapes rows
// for the routes. `run` is injected so the shaping is testable without a
// database.

import { z } from 'zod';

import {
  type FingerprintKind,
  type RequestFilterParsed,
  type RequestRow,
  requestDetailSchema,
  requestRowSchema,
  type VerdictPoint,
} from '../../shared/api.ts';
import {
  RANGE_SECONDS,
  RANGE_STEP_SECONDS,
  type Range,
} from '../../shared/domain.ts';
import { type Query, Sql } from './sql.ts';

export type Run = <T>(query: Query, row: z.ZodType<T>) => Promise<T[]>;

const num = z.coerce.number();

const toneRow = z.object({
  blocked: num,
  challenged: num,
  allowed: num,
  would_block: num,
});
const seriesRow = toneRow.extend({ t: num });
const hostRow = toneRow.extend({ host: z.string(), requests: num });
const countRow = z.object({ value: z.string(), requests: num });
const nameCountRow = z.object({ name: z.string(), requests: num });

export type DetailRow = z.infer<typeof requestDetailSchema>['row'];

const detailRow = requestDetailSchema.shape.row.extend({
  ts: num,
  asn: num,
  score: num,
  status: num,
  duration_ms: num,
  model_score: z.coerce.number().nullable(),
  local: z.coerce.boolean(),
});
const rowSchema = requestRowSchema.extend({
  ts: num,
  asn: num,
  score: num,
  status: num,
});

export interface HostCounts {
  host: string;
  requests: number;
  allowed: number;
  challenged: number;
  blocked: number;
  would_block: number;
}

export interface SampleEvent {
  ts: number;
  host: string;
  method: string;
  path: string;
  http_version: string;
  sni: string;
  ja4: string;
  h2_fp: string;
  pseudo_order: string;
  header_fp: string;
  tcp_fp: string;
  user_agent: string;
  score: number;
  class: string;
  reasons: string[];
  asn: number;
  signed_agent: string;
  ip_prefix: string;
  action: string;
  would_action: string;
  tcp_rtt_us: number | null;
  handshake_us: number | null;
}

const sampleRow = z.object({
  ts: num,
  host: z.string(),
  method: z.string(),
  path: z.string(),
  http_version: z.string(),
  sni: z.string(),
  ja4: z.string(),
  h2_fp: z.string(),
  pseudo_order: z.string(),
  header_fp: z.string(),
  tcp_fp: z.string(),
  user_agent: z.string(),
  score: num,
  class: z.string(),
  reasons: z.array(z.string()),
  asn: num,
  signed_agent: z.string(),
  ip_prefix: z.string(),
  action: z.string(),
  would_action: z.string(),
  tcp_rtt_us: z.coerce.number().nullable(),
  handshake_us: z.coerce.number().nullable(),
});

export interface FingerprintStats {
  value: string;
  requests: number;
  clients: number;
  hourly: number[];
  allowed: number;
  challenged: number;
  blocked: number;
  median_score: number;
  first_seen: number;
  last_seen: number;
  ua_sample: string;
}

export interface Analytics {
  verdictSeries(range: Range, now: number): Promise<VerdictPoint[]>;
  topHosts(
    range: Range,
    limit: number,
    now: number,
  ): Promise<(HostCounts & { spark: number[] })[]>;
  blockedReasons(range: Range): Promise<{ reason: string; requests: number }[]>;
  topAsns(
    range: Range,
  ): Promise<
    { asn: number; requests: number; blocked: number; challenged: number }[]
  >;
  crawlerCounts(
    seconds: number,
  ): Promise<{ id: string; verified: number; fake: number }[]>;
  lag(): Promise<number | null>;
  requests(filter: RequestFilterParsed): Promise<{
    rows: RequestRow[];
    total: number;
    facets: Record<
      'action' | 'class' | 'host',
      { value: string; requests: number }[]
    >;
  }>;
  request(requestId: string, ts: number): Promise<DetailRow | null>;
  fingerprints(
    kind: FingerprintKind,
    q: string | undefined,
    now: number,
  ): Promise<{
    rows: FingerprintStats[];
    kinds: { kind: FingerprintKind; distinct: number }[];
  }>;
  reasonCounts(prefix: string, seconds: number): Promise<Map<string, number>>;
  ruleSamples(
    seconds: number,
    target: number,
  ): Promise<{
    total: number;
    samples: SampleEvent[];
  }>;
  refusedByLimit(seconds: number): Promise<Map<string, number>>;
  consumers(seconds: number): Promise<
    {
      ip_prefix: string;
      ip_hash_count: number;
      host: string;
      rps: number;
      refused: number;
    }[]
  >;
  hostStats(seconds: number): Promise<HostCounts[]>;
  impostors(seconds: number): Promise<
    {
      crawler: string;
      ip_prefix: string;
      asn: number;
      requests: number;
      action: string;
      last_seen: number;
    }[]
  >;
  busiestHost(seconds: number): Promise<{ host: string; rps: number } | null>;
  attackImpact(seconds: number): Promise<{
    requests: number;
    token: number;
    verified_or_listed: number;
  }>;
  search(
    kind: 'host' | 'ja4' | 'ip_prefix' | 'ip_hash',
    q: string,
  ): Promise<{ value: string; requests: number; asn?: number }[]>;
}

// Bucket starts covering `range` up to `now`, `step` apart, oldest first.
export function bucketStarts(range: Range, now: number): number[] {
  const stepMs = RANGE_STEP_SECONDS[range] * 1000;
  const last = Math.floor(now / stepMs) * stepMs;
  const first =
    Math.floor((now - RANGE_SECONDS[range] * 1000) / stepMs) * stepMs + stepMs;
  const starts: number[] = [];
  for (let t = first; t <= last; t += stepMs) starts.push(t);
  return starts;
}

// Counts per bucket to requests per second, with empty buckets as zero.
export function fillSeries(
  rows: z.infer<typeof seriesRow>[],
  range: Range,
  now: number,
): VerdictPoint[] {
  const step = RANGE_STEP_SECONDS[range];
  const byStart = new Map(rows.map((row) => [row.t, row]));
  return bucketStarts(range, now).map((t) => {
    const row = byStart.get(t);
    return {
      t,
      allowed: (row?.allowed ?? 0) / step,
      challenged: (row?.challenged ?? 0) / step,
      blocked: (row?.blocked ?? 0) / step,
      would_block: (row?.would_block ?? 0) / step,
    };
  });
}

export function createAnalytics(database: string, run: Run): Analytics {
  const sql = new Sql(database);

  const nameCounts = async (query: Query) =>
    new Map(
      (await run(query, nameCountRow)).map((row) => [row.name, row.requests]),
    );

  return {
    async verdictSeries(range, now) {
      const rows = await run(
        sql.verdictSeries(range, RANGE_STEP_SECONDS[range]),
        seriesRow,
      );
      return fillSeries(rows, range, now);
    },

    async topHosts(range, limit, now) {
      const hosts = await run(sql.topHosts(range, limit), hostRow);
      if (hosts.length === 0) return [];
      const step = RANGE_STEP_SECONDS[range];
      const series = await run(
        sql.hostSeries(
          range,
          step,
          hosts.map((host) => host.host),
        ),
        z.object({ host: z.string(), t: num, requests: num }),
      );
      const starts = bucketStarts(range, now);
      return hosts.map((host) => {
        const points = new Map(
          series
            .filter((row) => row.host === host.host)
            .map((row) => [row.t, row.requests / step]),
        );
        return { ...host, spark: starts.map((t) => points.get(t) ?? 0) };
      });
    },

    blockedReasons: (range) =>
      run(
        sql.blockedReasons(range, 8),
        z.object({ reason: z.string(), requests: num }),
      ),

    topAsns: (range) =>
      run(
        sql.topAsns(range, 6),
        z.object({ asn: num, requests: num, blocked: num, challenged: num }),
      ),

    crawlerCounts: (seconds) =>
      run(
        sql.crawlerCounts(seconds, 50),
        z.object({ id: z.string(), verified: num, fake: num }),
      ),

    async lag() {
      const [row] = await run(
        sql.lag(),
        z.object({ lag_s: z.coerce.number().nullable() }),
      );
      return row?.lag_s ?? null;
    },

    async requests(filter) {
      const [rows, count, action, botClass, host] = await Promise.all([
        run(sql.requestRows(filter), rowSchema),
        run(sql.requestCount(filter), z.object({ total: num })),
        run(sql.requestFacet(filter, 'action'), countRow),
        run(sql.requestFacet(filter, 'class'), countRow),
        run(sql.requestFacet(filter, 'host'), countRow),
      ]);
      return {
        rows,
        total: count[0]?.total ?? 0,
        facets: { action, class: botClass, host },
      };
    },

    async request(requestId, ts) {
      const [row] = await run(sql.requestDetail(requestId, ts), detailRow);
      return row ?? null;
    },

    async fingerprints(kind, q, now) {
      const statsRow = toneRow.extend({
        value: z.string(),
        requests: num,
        clients: num,
        median_score: num,
        first_seen: num,
        last_seen: num,
        ua_sample: z.string(),
      });
      const [rows, kinds] = await Promise.all([
        run(sql.fingerprints(kind, q), statsRow),
        run(
          sql.fingerprintKinds(),
          z.object({ ja4: num, h2_fp: num, header_fp: num, tcp_fp: num }),
        ),
      ]);
      const hourly =
        rows.length === 0
          ? []
          : await run(
              sql.fingerprintHourly(
                kind,
                rows.map((row) => row.value),
              ),
              z.object({ value: z.string(), t: num, requests: num }),
            );
      const hourMs = 3_600_000;
      const lastHour = Math.floor(now / hourMs) * hourMs;
      const hours = Array.from(
        { length: 24 },
        (_, i) => lastHour - (23 - i) * hourMs,
      );
      const counts = kinds[0];
      return {
        rows: rows.map((row) => {
          const points = new Map(
            hourly
              .filter((point) => point.value === row.value)
              .map((point) => [point.t, point.requests]),
          );
          return { ...row, hourly: hours.map((t) => points.get(t) ?? 0) };
        }),
        kinds: (['ja4', 'h2_fp', 'header_fp', 'tcp_fp'] as const).map(
          (name) => ({ kind: name, distinct: counts?.[name] ?? 0 }),
        ),
      };
    },

    reasonCounts: (prefix, seconds) =>
      nameCounts(sql.reasonCounts(prefix, seconds)),

    async ruleSamples(seconds, target) {
      const [count] = await run(
        sql.totalSince(seconds),
        z.object({ total: num }),
      );
      const total = count?.total ?? 0;
      if (total === 0) return { total, samples: [] };
      const modulo = Math.max(1, Math.floor(total / target));
      const samples = await run(
        sql.ruleSamples(seconds, modulo, target),
        sampleRow,
      );
      return { total, samples };
    },

    refusedByLimit: (seconds) => nameCounts(sql.refusedByLimit(seconds)),

    consumers: (seconds) =>
      run(
        sql.consumers(seconds, 10),
        z.object({
          ip_prefix: z.string(),
          ip_hash_count: num,
          host: z.string(),
          rps: num,
          refused: num,
        }),
      ),

    hostStats: (seconds) => run(sql.hostStats(seconds), hostRow),

    impostors: (seconds) =>
      run(
        sql.impostors(seconds, 20),
        z.object({
          crawler: z.string(),
          ip_prefix: z.string(),
          asn: num,
          requests: num,
          action: z.string(),
          last_seen: num,
        }),
      ),

    async busiestHost(seconds) {
      const [row] = await run(
        sql.busiestHost(seconds),
        z.object({ host: z.string(), rps: num }),
      );
      return row ?? null;
    },

    async attackImpact(seconds) {
      const [row] = await run(
        sql.attackImpact(seconds),
        z.object({ requests: num, token: num, verified_or_listed: num }),
      );
      return row ?? { requests: 0, token: 0, verified_or_listed: 0 };
    },

    async search(kind, q) {
      if (kind === 'host') {
        return (
          await run(
            sql.hostsLike(q, 5),
            z.object({ host: z.string(), requests: num }),
          )
        ).map((row) => ({ value: row.host, requests: row.requests }));
      }
      if (kind === 'ja4') return run(sql.ja4Like(q, 5), countRow);
      return run(sql.ipLike(kind, q, 5), countRow.extend({ asn: num }));
    },
  };
}
