// GET /api/hosts: every known host with its mode, route and traffic.
// POST /api/hosts/mode, DELETE /api/hosts/mode/:host: console host modes.

import type { Hono } from 'hono';

import { hostsSchema, setModeSchema, type HostRow } from '../../shared/api.ts';
import type { HostMode } from '../../shared/domain.ts';
import type { AppEnv, Deps } from '../deps.ts';
import { fail, jsonBody, parseOr400, send } from '../http.ts';
import { requireRole } from '../roles.ts';
import { actor } from './common.ts';

const MAX_HOSTS = 200;

async function consoleMode(deps: Deps, host: string): Promise<HostMode | null> {
  const overview = await deps.admin.policyOverview();
  return overview.console.find((entry) => entry.host === host)?.mode ?? null;
}

export async function applyMode(
  deps: Deps,
  host: string,
  mode: HostMode | null,
): Promise<void> {
  if (mode === null) await deps.admin.clearMode(host);
  else await deps.admin.setMode(host, mode);
}

export function registerHosts(app: Hono<AppEnv>): void {
  app.get('/api/hosts', async (c) => {
    const deps = c.get('deps');
    const [overview, stats] = await Promise.all([
      deps.admin.policyOverview(),
      deps.analytics
        ? deps.analytics.hostStats(3600).catch(() => [])
        : Promise.resolve([]),
    ]);
    const names = new Set<string>(stats.map((row) => row.host));
    for (const entry of [
      ...overview.console,
      ...overview.policy_hosts,
      ...overview.labels,
    ]) {
      // Wildcards apply to hosts; only concrete names are rows.
      if (!entry.host.startsWith('*.')) names.add(entry.host);
    }
    const byHost = new Map(stats.map((row) => [row.host, row]));
    const hosts = [...names].slice(0, MAX_HOSTS);
    const policies = await Promise.all(
      hosts.map((host) => deps.admin.policy(host).catch(() => null)),
    );
    const rows: HostRow[] = [];
    hosts.forEach((host, i) => {
      const policy = policies[i];
      if (!policy) return;
      const stat = byHost.get(host);
      rows.push({
        host,
        mode: policy.mode,
        source: policy.mode_source,
        route: policy.route,
        certificate: policy.certificate,
        rate_limits: policy.rate_limits,
        requests: stat?.requests ?? 0,
        rps: (stat?.requests ?? 0) / 3600,
        blocked: stat?.blocked ?? 0,
        would_block: stat?.would_block ?? 0,
        challenged: stat?.challenged ?? 0,
      });
    });
    rows.sort(
      (a, b) => b.requests - a.requests || a.host.localeCompare(b.host),
    );
    return send(c, hostsSchema, {
      default_mode: overview.default,
      hosts: rows,
    });
  });

  app.post('/api/hosts/mode', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const { host, mode } = parseOr400(setModeSchema, await jsonBody(c));
    const name = host.toLowerCase().replace(/\.$/, '');
    const before = await consoleMode(deps, name);
    const previous = await deps.admin.policy(name).catch(() => null);
    await deps.admin.setMode(name, mode);
    deps.audit.append({
      kind: 'mode',
      actor: actor(c),
      what: `${name} switched ${previous?.mode ?? '?'} → ${mode}`,
      before: { host: name, mode: before },
      after: { host: name, mode },
      facts: [
        ['Source', 'console override'],
        ...(previous
          ? ([['Was', `${previous.mode} (${previous.mode_source})`]] as [
              string,
              string,
            ][])
          : []),
      ],
    });
    return c.body(null, 204);
  });

  app.delete('/api/hosts/mode/:host', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const host = c.req.param('host').toLowerCase();
    const before = await consoleMode(deps, host);
    if (before === null || !(await deps.admin.clearMode(host))) {
      return fail(404, 'no console mode for this host');
    }
    const now = await deps.admin.policy(host).catch(() => null);
    deps.audit.append({
      kind: 'mode',
      actor: actor(c),
      what: `${host}: console override removed (${before} → ${now?.mode ?? '?'})`,
      before: { host, mode: before },
      after: { host, mode: null },
      facts: now ? [['Now', `${now.mode} (${now.mode_source})`]] : [],
    });
    return c.body(null, 204);
  });
}
