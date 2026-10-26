// GET /api/attack, POST /api/attack, DELETE /api/attack/:host: the
// gateway's under-attack mode (challenge everyone without a token).

import type { Hono } from 'hono';

import { attackSchema, enableAttackSchema } from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { fail, jsonBody, parseOr400, send } from '../http.ts';
import { requireRole } from '../roles.ts';
import { actor } from './common.ts';

export function registerAttack(app: Hono<AppEnv>): void {
  app.get('/api/attack', async (c) => {
    const deps = c.get('deps');
    const [state, config, gateway, busiest, impact] = await Promise.all([
      deps.admin.attack(),
      deps.admin.config(),
      deps.metrics.read().catch(() => null),
      deps.analytics
        ? deps.analytics.busiestHost(60).catch(() => null)
        : Promise.resolve(null),
      deps.analytics
        ? deps.analytics.attackImpact(300).catch(() => null)
        : Promise.resolve(null),
    ]);
    return send(c, attackSchema, {
      entries: state.entries,
      history: state.history,
      auto_rps: state.auto_rps,
      auto_rps_total: state.auto_rps_total,
      auto_duration_ms: config.attack.auto_duration_ms,
      persistent: config.attack.persistent,
      rps: gateway?.rps ?? null,
      busiest,
      auto_activations:
        gateway?.metrics?.get('bot_shield_attack_auto_activations_total') ??
        null,
      impact: impact && {
        ...impact,
        rest: Math.max(
          0,
          impact.requests - impact.token - impact.verified_or_listed,
        ),
      },
    });
  });

  app.post('/api/attack', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const { host, ttl } = parseOr400(enableAttackSchema, await jsonBody(c));
    const before = (await deps.admin.attack()).entries.find(
      (entry) => entry.host === host,
    );
    await deps.admin.enableAttack(host, ttl);
    const after = (await deps.admin.attack()).entries.find(
      (entry) => entry.host === host.toLowerCase(),
    );
    deps.audit.append({
      kind: 'attack',
      actor: actor(c),
      what: `Attack mode ${before ? 'extended' : 'on'} for ${host === '*' ? 'all hosts' : host}${ttl ? ` (${ttl})` : ''}`,
      ...(before ? { before } : {}),
      ...(after ? { after } : {}),
      facts: [['Duration', ttl ?? 'until switched off']],
    });
    return c.body(null, 204);
  });

  app.delete('/api/attack/:host', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const host = c.req.param('host');
    const before = (await deps.admin.attack()).entries.find(
      (entry) => entry.host === host,
    );
    if (!(await deps.admin.disableAttack(host))) {
      return fail(404, 'host is not under attack');
    }
    deps.audit.append({
      kind: 'attack',
      actor: actor(c),
      what: `Attack mode off for ${host === '*' ? 'all hosts' : host}`,
      ...(before ? { before } : {}),
      facts: before
        ? [['Was on since', new Date(before.since * 1000).toISOString()]]
        : [],
    });
    return c.body(null, 204);
  });
}
