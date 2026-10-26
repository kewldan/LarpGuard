// GET /api/limits?by=: rate limits in effect, refusals and the busiest
// clients by network, address hash or clearance session.

import type { Hono } from 'hono';

import { z } from 'zod';

import { consumerKeySchema, limitsSchema } from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { parseOr400, send } from '../http.ts';

export function registerLimits(app: Hono<AppEnv>): void {
  app.get('/api/limits', async (c) => {
    const deps = c.get('deps');
    const { by } = parseOr400(
      z.object({ by: consumerKeySchema.default('ip_prefix') }),
      c.req.query(),
    );
    const [config, refused, consumers, settings] = await Promise.all([
      deps.admin.config(),
      deps.analytics
        ? deps.analytics.refusedByLimit(3600).catch(() => null)
        : Promise.resolve(null),
      deps.analytics
        ? deps.analytics.consumers(60, by).catch(() => [])
        : Promise.resolve([]),
      deps.admin.settings().catch(() => null),
    ]);
    const key = settings?.keys.find((item) => item.path === 'rate_limits');
    return send(c, limitsSchema, {
      limits: config.rate_limits.map((limit) => ({
        ...limit,
        refused_1h: refused?.get(limit.name) ?? 0,
      })),
      throttle: config.throttle,
      consumers_by: by,
      consumers,
      source: key?.source ?? 'file',
      editable: settings?.editable ?? false,
      revision: settings?.revision ?? null,
    });
  });
}
