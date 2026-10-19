// GET /api/overview?range=: KPIs, verdicts over time, top hosts, reasons,
// ASNs and crawlers.

import type { Hono } from 'hono';
import { z } from 'zod';

import { overviewSchema, rangeSchema } from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { parseOr400, send } from '../http.ts';
import { RANGE_SECONDS, RANGE_STEP_SECONDS } from '../../shared/domain.ts';
import { analytics, asnNames } from './common.ts';

export function registerOverview(app: Hono<AppEnv>): void {
  app.get('/api/overview', async (c) => {
    const deps = c.get('deps');
    const { range } = parseOr400(
      z.object({ range: rangeSchema.default('1h') }),
      c.req.query(),
    );
    const data = analytics(deps);
    const now = deps.now();
    const [series, hosts, reasons, asns, crawlers] = await Promise.all([
      data.verdictSeries(range, now),
      data.topHosts(range, 6, now),
      data.blockedReasons(range),
      data.topAsns(range),
      data.crawlerCounts(RANGE_SECONDS[range]),
    ]);
    const [names, modes] = await Promise.all([
      asnNames(
        deps,
        asns.map((row) => row.asn),
      ),
      Promise.all(
        hosts.map((host) =>
          deps.admin.policy(host.host).then(
            (policy) => ({ mode: policy.mode, source: policy.mode_source }),
            () => null,
          ),
        ),
      ),
    ]);
    const step = RANGE_STEP_SECONDS[range];
    const sum = (key: 'allowed' | 'challenged' | 'blocked' | 'would_block') =>
      Math.round(series.reduce((total, point) => total + point[key] * step, 0));
    const totals = {
      allowed: sum('allowed'),
      challenged: sum('challenged'),
      blocked: sum('blocked'),
      would_block: sum('would_block'),
    };
    return send(c, overviewSchema, {
      range,
      step_s: step,
      series,
      totals: {
        requests: totals.allowed + totals.challenged + totals.blocked,
        ...totals,
      },
      hosts: hosts.map((host, i) => ({
        host: host.host,
        requests: host.requests,
        blocked: host.blocked,
        would_block: host.would_block,
        spark: host.spark,
        mode: modes[i] ?? null,
      })),
      reasons,
      asns: asns.map((row) => ({ ...row, info: names.get(row.asn) ?? null })),
      crawlers: crawlers.slice(0, 6),
    });
  });
}
