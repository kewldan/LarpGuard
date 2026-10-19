// Every /api route behind a session.

import type { Hono } from 'hono';

import type { AppEnv } from '../deps.ts';
import { registerAttack } from './attack.ts';
import { registerAudit } from './audit.ts';
import { registerCrawlers } from './crawlers.ts';
import { registerFingerprints } from './fingerprints.ts';
import { registerHosts } from './hosts.ts';
import { registerLimits } from './limits.ts';
import { registerLists } from './lists.ts';
import { registerOverview } from './overview.ts';
import { registerRequests } from './requests.ts';
import { registerRules } from './rules.ts';
import { registerSearch } from './search.ts';
import { registerStatus } from './status.ts';

export function registerRoutes(app: Hono<AppEnv>): void {
  registerStatus(app);
  registerOverview(app);
  registerRequests(app);
  registerFingerprints(app);
  registerRules(app);
  registerLists(app);
  registerLimits(app);
  registerHosts(app);
  registerCrawlers(app);
  registerAttack(app);
  registerAudit(app);
  registerSearch(app);
}
