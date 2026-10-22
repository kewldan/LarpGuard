// GET /api/status: gateway status and the health of every data source.
// GET /api/config: the gateway's verdict set in effect.

import type { Hono } from 'hono';

import {
  gatewayConfigSchema,
  type SourceState,
  statusSchema,
} from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { send } from '../http.ts';

function lagState(lag: number | null): SourceState {
  if (lag === null) return 'degraded';
  if (lag <= 60) return 'ok';
  return lag <= 600 ? 'degraded' : 'down';
}

export function registerStatus(app: Hono<AppEnv>): void {
  app.get('/api/status', async (c) => {
    const deps = c.get('deps');
    const [status, config, gateway, lag] = await Promise.allSettled([
      deps.admin.status(),
      deps.admin.config(),
      deps.metrics.read(),
      deps.analytics ? deps.analytics.lag() : Promise.resolve(null),
    ]);
    const admin = status.status === 'fulfilled' ? status.value : null;
    const health = gateway.status === 'fulfilled' ? gateway.value : null;
    const samples = health?.metrics ?? null;
    const xdpAttached = samples?.get('bot_shield_xdp_attached') === 1;
    const xdpDrops = ['blocked', 'syn_rate', 'invalid', 'fragment'].reduce(
      (sum, result) =>
        sum +
        (samples?.get(`bot_shield_xdp_packets_total{result="${result}"}`) ?? 0),
      0,
    );
    const lagSeconds = lag.status === 'fulfilled' ? lag.value : null;
    return send(c, statusSchema, {
      gateway: admin && {
        version: admin.version,
        uptime_s: admin.uptime_s,
        mode: admin.mode,
        generation: admin.verdicts_generation,
        built_at_ms:
          config.status === 'fulfilled' ? config.value.built_at_ms : 0,
        workers: admin.workers,
        connections_active: admin.connections_active,
        nats_connected: admin.nats_connected,
        events_dropped: admin.events_dropped,
        list_entries: admin.list_entries,
        attack_entries: admin.attack_entries,
      },
      health: {
        admin: admin ? 'ok' : 'down',
        workers:
          health?.healthy === true
            ? 'ok'
            : health?.healthy === false
              ? 'degraded'
              : 'down',
        events:
          deps.analytics === null
            ? 'off'
            : admin?.nats_connected
              ? 'ok'
              : 'down',
        clickhouse:
          deps.analytics === null
            ? 'off'
            : lag.status === 'rejected'
              ? 'down'
              : lagState(lagSeconds),
        clickhouse_lag_s: lagSeconds,
        xdp: samples === null ? 'down' : xdpAttached ? 'ok' : 'off',
      },
      metrics: samples && {
        rps: health?.rps ?? null,
        xdp_blocked: xdpAttached ? xdpDrops : null,
        attack_auto_activations:
          samples.get('bot_shield_attack_auto_activations_total') ?? 0,
      },
    });
  });

  app.get('/api/config', async (c) =>
    send(c, gatewayConfigSchema, await c.get('deps').admin.config()),
  );
}
