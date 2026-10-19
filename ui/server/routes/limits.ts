// GET /api/limits: rate limits in effect, refusals and the busiest clients.

import type { Hono } from 'hono';

import { limitsSchema } from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { send } from '../http.ts';

export function registerLimits(app: Hono<AppEnv>): void {
  app.get('/api/limits', async (c) => {
    const deps = c.get('deps');
    const [config, refused, consumers] = await Promise.all([
      deps.admin.config(),
      deps.analytics
        ? deps.analytics.refusedByLimit(3600).catch(() => null)
        : Promise.resolve(null),
      deps.analytics
        ? deps.analytics.consumers(60).catch(() => [])
        : Promise.resolve([]),
    ]);
    return send(c, limitsSchema, {
      limits: config.rate_limits.map((limit) => ({
        ...limit,
        refused_1h: refused?.get(limit.name) ?? 0,
      })),
      throttle: config.throttle,
      consumers,
    });
  });
}
