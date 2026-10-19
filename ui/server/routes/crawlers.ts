// GET /api/crawlers: the crawler catalog and how verification went.

import type { Hono } from 'hono';

import { crawlersSchema } from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { send } from '../http.ts';

export function registerCrawlers(app: Hono<AppEnv>): void {
  app.get('/api/crawlers', async (c) => {
    const deps = c.get('deps');
    const day = 86_400;
    const [config, counts, agents, impostors] = await Promise.all([
      deps.admin.config(),
      deps.analytics
        ? deps.analytics.crawlerCounts(day).catch(() => [])
        : Promise.resolve([]),
      deps.analytics
        ? deps.analytics.reasonCounts('signed_agent:', day).catch(() => null)
        : Promise.resolve(null),
      deps.analytics
        ? deps.analytics.impostors(day).catch(() => [])
        : Promise.resolve([]),
    ]);
    const byId = new Map(counts.map((row) => [row.id, row]));
    return send(c, crawlersSchema, {
      verify: config.crawlers.verify,
      ip_ranges: config.crawlers.ip_ranges,
      ai_action: config.crawlers.ai_action,
      web_bot_auth: config.web_bot_auth,
      crawlers: config.crawlers.catalog
        .map((crawler) => ({
          ...crawler,
          verified: byId.get(crawler.id)?.verified ?? 0,
          fake: byId.get(crawler.id)?.fake ?? 0,
        }))
        .sort((a, b) => b.verified + b.fake - (a.verified + a.fake)),
      signed_agents: [...(agents ?? new Map<string, number>())].map(
        ([agent, requests]) => ({ agent, requests }),
      ),
      impostors,
    });
  });
}
