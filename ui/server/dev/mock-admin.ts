// An in-memory gateway for development and browser tests: the admin API's
// behaviour (lists, attack mode, console modes, rule tests) without a
// gateway process.

import type { GatewayConfig, ListEntry } from '../../shared/api.ts';
import type { HostMode } from '../../shared/domain.ts';
import {
  AdminError,
  type AdminApi,
  type HostPolicy,
} from '../gateway/admin.ts';
import { compileRule, RuleError } from './mini-rules.ts';
import { MOCK_CONFIG } from './mock-config.ts';
import { MOCK_ASNS, MOCK_HOSTS } from './mock-data.ts';

export const MOCK_SHADOW_HOSTS = new Set([
  'shop.example.com',
  'docs.example.com',
]);

export function createMockAdmin(now: () => number): AdminApi {
  const config: GatewayConfig = {
    ...MOCK_CONFIG,
    built_at_ms: now() - 12 * 60_000,
  };
  const policyHosts = new Map<string, HostMode>(
    MOCK_HOSTS.map(({ host }) => [
      host,
      MOCK_SHADOW_HOSTS.has(host) ? 'shadow' : 'enforce',
    ]),
  );
  const consoleModes = new Map<string, HostMode>();
  const lists: ListEntry[] = [];
  let nextId = 1;
  const attack = new Map<
    string,
    { host: string; source: string; since: number; until?: number }
  >();
  const seconds = () => Math.floor(now() / 1000);
  const sweep = () => {
    for (const [host, entry] of attack) {
      if (entry.until !== undefined && entry.until <= seconds())
        attack.delete(host);
    }
    for (let i = lists.length - 1; i >= 0; i -= 1) {
      const entry = lists[i];
      if (entry && entry.expires_at !== 0 && entry.expires_at <= seconds())
        lists.splice(i, 1);
    }
  };
  const ttlSeconds = (ttl: string | undefined) => {
    if (!ttl) return 0;
    const match = /^(\d+)(ms|s|m|h)$/.exec(ttl);
    if (!match) throw new AdminError(400, 'bad ttl');
    const unit = { ms: 0.001, s: 1, m: 60, h: 3600 }[
      match[2] as 'ms' | 's' | 'm' | 'h'
    ];
    return Math.ceil(Number(match[1]) * unit);
  };
  const policy = (host: string): HostPolicy => {
    const name = host.toLowerCase();
    const fromConsole = consoleModes.get(name);
    const configured = policyHosts.get(name);
    return {
      host: name,
      mode: fromConsole ?? configured ?? 'shadow',
      mode_source: fromConsole
        ? 'console'
        : configured
          ? 'policy.hosts'
          : 'mode',
      route: 'terminate',
      certificate: true,
      rate_limits: config.rate_limits
        .filter(
          (limit) => limit.hosts.length === 0 || limit.hosts.includes(name),
        )
        .map((limit) => limit.name),
    };
  };
  return {
    status: () =>
      Promise.resolve({
        version: '0.9.3-dev',
        uptime_s: 86_400 * 3,
        mode: 'shadow',
        verdicts_generation: config.generation,
        workers: 16,
        certificates: 6,
        label_hosts: 0,
        connections_active: 1840,
        rate_limit_keys: 920,
        list_entries: lists.length,
        attack_entries: attack.size,
        nats_connected: true,
        events_published: 1_000_000,
        events_dropped: 0,
      }),
    config: () => Promise.resolve(config),
    policy: (host) => Promise.resolve(policy(host)),
    policyOverview: () =>
      Promise.resolve({
        default: 'shadow',
        console: [...consoleModes].map(([host, mode]) => ({ host, mode })),
        policy_hosts: [...policyHosts].map(([host, mode]) => ({ host, mode })),
        labels: [],
        passthrough_hosts: [],
      }),
    setMode: (host, mode) => {
      consoleModes.set(host.toLowerCase(), mode);
      config.generation += 1;
      return Promise.resolve();
    },
    clearMode: (host) => {
      const removed = consoleModes.delete(host.toLowerCase());
      if (removed) config.generation += 1;
      return Promise.resolve(removed);
    },
    lists: () => {
      sweep();
      return Promise.resolve([...lists]);
    },
    addList: (entry) => {
      const ttl = ttlSeconds(entry.ttl);
      const stored: ListEntry = {
        id: nextId,
        kind: entry.kind,
        value:
          entry.kind === 'ip' && !entry.value.includes('/')
            ? `${entry.value}/${entry.value.includes(':') ? 128 : 32}`
            : entry.value,
        action: entry.action,
        host: entry.host ?? '',
        created_at: seconds(),
        expires_at: ttl === 0 ? 0 : seconds() + ttl,
        comment: entry.comment ?? '',
      };
      nextId += 1;
      lists.push(stored);
      return Promise.resolve(stored);
    },
    removeList: (id) => {
      const index = lists.findIndex((entry) => entry.id === id);
      if (index >= 0) lists.splice(index, 1);
      return Promise.resolve(index >= 0);
    },
    decision: () => Promise.resolve(null),
    attack: () => {
      sweep();
      return Promise.resolve({
        entries: [...attack.values()],
        auto_rps: config.attack.auto_rps,
      });
    },
    enableAttack: (host, ttl) => {
      const name = host.toLowerCase();
      const duration = ttlSeconds(ttl);
      attack.set(name, {
        host: name,
        source: 'admin',
        since: seconds(),
        ...(duration === 0 ? {} : { until: seconds() + duration }),
      });
      return Promise.resolve();
    },
    disableAttack: (host) => Promise.resolve(attack.delete(host.toLowerCase())),
    testRule: (when, samples) => {
      try {
        const rule = compileRule(when);
        const matched: number[] = [];
        samples.forEach((sample, i) => {
          if (rule.matches(sample)) matched.push(i);
        });
        return Promise.resolve({
          references: rule.references,
          evaluated: samples.length,
          matched,
        });
      } catch (error) {
        if (error instanceof RuleError) {
          return Promise.reject(
            new AdminError(422, error.message, error.column),
          );
        }
        throw error;
      }
    },
    asns: (numbers) =>
      Promise.resolve(MOCK_ASNS.filter((info) => numbers.includes(info.asn))),
    reload: () => {
      config.generation += 1;
      config.built_at_ms = now();
      return Promise.resolve(
        `generation ${config.generation}: 5 rules, 3 limits (mock)`,
      );
    },
  };
}
