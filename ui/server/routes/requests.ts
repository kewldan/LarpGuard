// GET /api/requests: the explorer (filters in the query string).
// GET /api/requests/:id?ts=: one request with its context.

import type { Hono } from 'hono';
import { z } from 'zod';

import {
  requestDetailSchema,
  requestFilterSchema,
  requestPageSchema,
} from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { fail, parseOr400, send } from '../http.ts';
import { analytics, asnNames } from './common.ts';

export function registerRequests(app: Hono<AppEnv>): void {
  app.get('/api/requests', async (c) => {
    const deps = c.get('deps');
    const filter = parseOr400(requestFilterSchema, c.req.query());
    const page = await analytics(deps).requests(filter);
    const names = await asnNames(
      deps,
      page.rows.map((row) => row.asn),
    );
    return send(c, requestPageSchema, { ...page, asns: [...names.values()] });
  });

  app.get('/api/requests/:id', async (c) => {
    const deps = c.get('deps');
    const id = c.req.param('id');
    const { ts } = parseOr400(
      z.object({ ts: z.coerce.number().int().positive() }),
      c.req.query(),
    );
    if (!/^[\w.-]{1,128}$/.test(id)) fail(400, 'invalid request id');
    const row = await analytics(deps).request(id, ts);
    if (!row) return fail(404, 'request not found (events are kept 14 days)');
    const [names, policy, decision] = await Promise.all([
      asnNames(deps, [row.asn]),
      deps.admin.policy(row.host).catch(() => null),
      deps.admin.decision(id).catch(() => null),
    ]);
    return send(c, requestDetailSchema, {
      row,
      asn: names.get(row.asn) ?? null,
      mode: policy && { mode: policy.mode, source: policy.mode_source },
      decision_available: decision !== null,
    });
  });
}
