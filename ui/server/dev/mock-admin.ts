// An in-memory gateway for development and browser tests: the admin API's
// behaviour (lists, attack mode, console modes, rule tests, settings)
// without a gateway process.

import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import type {
  AttackEntry,
  AttackRecord,
  GatewayConfig,
  ListEntry,
  SettingsDiff,
} from '../../shared/api.ts';
import type { Action, HostMode } from '../../shared/domain.ts';
import {
  type AdminApi,
  AdminError,
  type HostPolicy,
} from '../gateway/admin.ts';
import { compileRule, RuleError } from './mini-rules.ts';
import { MOCK_CONFIG } from './mock-config.ts';
import { MOCK_ASNS, MOCK_HOSTS, type MockEvent } from './mock-data.ts';
import { createMockSettings } from './mock-settings.ts';

export const MOCK_CONFIG_HASH = '7a1e2f04c9b3';

export const MOCK_SHADOW_HOSTS = new Set([
  'shop.example.com',
  'docs.example.com',
]);

// `recent`: the requests the gateway would hold for live rule tests.
export function createMockAdmin(
  now: () => number,
  recent: () => readonly MockEvent[] = () => [],
): AdminApi {
  // An audit key of its own, as the gateway's admin.audit_key_file.
  const auditKeys = generateKeyPairSync('ed25519');
  const rawPublic = auditKeys.publicKey
    .export({ format: 'der', type: 'spki' })
    .subarray(12);
  const auditKey = {
    key_id: createHash('sha256').update(rawPublic).digest('hex').slice(0, 16),
    public_key: rawPublic.toString('base64url'),
  };
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
  const settings = createMockSettings(now);
  // Live settings reach the verdict set, as in the gateway.
  const applied = (diff: SettingsDiff): SettingsDiff => {
    const value = settings.value;
    config.policy = {
      ...config.policy,
      enforce: value('mode') === 'enforce',
      suspicious_threshold: value('policy.thresholds.suspicious') as number,
      bot_threshold: value('policy.thresholds.bot') as number,
      suspicious_action: value('policy.actions.suspicious') as Action,
      bot_action: value('policy.actions.bot') as Action,
      verified_bot_action: value('policy.actions.verified_bot') as Action,
      block_status: value('policy.block_status') as number,
    };
    config.rules = (
      value('rules') as (Omit<GatewayConfig['rules'][number], 'disabled'> & {
        disabled?: boolean;
      })[]
    ).map((rule) => ({ ...rule, disabled: rule.disabled ?? false }));
    config.honeypot_paths = value('honeypot.paths') as string[];
    type LimitValue = {
      name: string;
      hosts?: string[];
      paths?: string[];
      methods?: string[];
      classes?: string[];
      key?: string[];
      rate: string;
      burst?: number;
      statuses?: number[];
      mode?: 'local' | 'synced' | 'strict';
    };
    const parsed = (text: string) => {
      const [count, unit] = text.split('/');
      const period = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[
        (unit ?? 's') as 's' | 'm' | 'h' | 'd'
      ];
      return { count: Number(count), period_ms: period };
    };
    config.rate_limits = (value('rate_limits') as LimitValue[]).map(
      (limit) => ({
        name: limit.name,
        hosts: limit.hosts ?? [],
        paths: limit.paths ?? [],
        methods: limit.methods ?? [],
        classes: limit.classes ?? [],
        key: limit.key ?? [],
        ...parsed(limit.rate),
        burst: limit.burst ?? 1,
        statuses: limit.statuses ?? [],
        mode: limit.mode ?? 'local',
      }),
    );
    const throttle = value('throttle') as Omit<LimitValue, 'name'> | null;
    config.throttle = throttle
      ? {
          name: 'throttle',
          hosts: [],
          paths: [],
          methods: [],
          classes: [],
          key: throttle.key ?? [],
          ...parsed(throttle.rate),
          burst: throttle.burst ?? 1,
          statuses: [],
          mode: 'local',
        }
      : null;
    const ai = value('crawlers.ai');
    config.crawlers = {
      ...config.crawlers,
      ai_action: ai === 'default' ? null : (ai as Action),
    };
    config.generation += 1;
    config.built_at_ms = now();
    return diff;
  };
  const lists: ListEntry[] = [];
  let nextId = 1;
  const attack = new Map<string, AttackEntry>();
  const seconds = () => Math.floor(now() / 1000);
  // The gateway's record of activations, newest first. One automatic trip
  // earlier today (the mock metrics count one).
  const attackHistory: AttackRecord[] = [
    {
      host: 'api.example.com',
      source: 'auto',
      since: seconds() - 5 * 3600,
      until: seconds() - 5 * 3600 + 600,
      ended: seconds() - 5 * 3600 + 600,
      signature: { kind: 'asn', value: '14061' },
      threshold: config.attack.auto_rps,
    },
  ];
  const endRecord = (host: string, at: number) => {
    for (const record of attackHistory) {
      if (record.host === host && record.ended === undefined) record.ended = at;
    }
  };
  const sweep = () => {
    for (const [host, entry] of attack) {
      if (entry.until !== undefined && entry.until <= seconds()) {
        endRecord(host, entry.until);
        attack.delete(host);
      }
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
        config_hash: MOCK_CONFIG_HASH,
        workers: 16,
        // Every loop beats twice a second; all on the current set.
        worker_beats: Array.from({ length: 16 }, (_, i) => ({
          age_ms: 40 + ((i * 97) % 420),
          generation: config.generation,
          acked: true,
        })),
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
      // Copies, as the gateway's JSON would be: a later change in place
      // must not show up in what a caller read before.
      return Promise.resolve(lists.map((entry) => ({ ...entry })));
    },
    addList: (entry) => {
      const ttl = ttlSeconds(entry.ttl);
      const stored: ListEntry = {
        id: nextId,
        kind: entry.kind,
        value:
          entry.kind === 'ip' && !entry.value.includes('/')
            ? `${entry.value}/${entry.value.includes(':') ? 128 : 32}`
            : entry.kind === 'asn'
              ? entry.value.replace(/^as/i, '')
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
    updateList: (id, patch) => {
      sweep();
      const entry = lists.find((item) => item.id === id);
      if (!entry) return Promise.resolve(null);
      if (patch.ttl !== undefined) {
        entry.expires_at =
          patch.ttl === null ? 0 : seconds() + ttlSeconds(patch.ttl);
      }
      if (patch.comment !== undefined) entry.comment = patch.comment;
      return Promise.resolve({ ...entry });
    },
    decision: () => Promise.resolve(null),
    attack: () => {
      sweep();
      return Promise.resolve({
        entries: [...attack.values()],
        history: attackHistory.map((record) => ({ ...record })),
        auto_rps: config.attack.auto_rps,
        auto_rps_total: config.attack.auto_rps_total,
      });
    },
    enableAttack: (host, ttl) => {
      sweep();
      const name = host.toLowerCase();
      const duration = ttlSeconds(ttl);
      const entry: AttackEntry = {
        host: name,
        source: 'admin',
        since: seconds(),
        ...(duration === 0 ? {} : { until: seconds() + duration }),
      };
      const open = attackHistory.find(
        (record) => record.host === name && record.ended === undefined,
      );
      if (attack.has(name) && open) {
        if (entry.until === undefined) delete open.until;
        else open.until = entry.until;
      } else {
        attackHistory.unshift({ ...entry });
        attackHistory.splice(200);
      }
      attack.set(name, entry);
      return Promise.resolve();
    },
    disableAttack: (host) => {
      const name = host.toLowerCase();
      if (!attack.delete(name)) return Promise.resolve(false);
      endRecord(name, seconds());
      return Promise.resolve(true);
    },
    testRuleLive: (when) => {
      try {
        const rule = compileRule(when);
        const samples = recent();
        const matches = samples
          .filter((sample) => rule.matches(sample))
          .reverse()
          .slice(0, 1000);
        return Promise.resolve({
          references: rule.references,
          evaluated: samples.length,
          window_ms:
            samples.length === 0 ? 0 : now() - (samples[0]?.ts ?? now()),
          matched_count: samples.filter((sample) => rule.matches(sample))
            .length,
          matches: matches.map((sample) => ({
            time_ms: sample.ts,
            request_id: sample.request_id,
            host: sample.host,
            method: sample.method,
            path_group: sample.path_group,
            ip_prefix: sample.ip_prefix,
            ip_hash: sample.ip_hash,
            class: sample.class,
            score: sample.score,
            asn: sample.asn,
            action: sample.action,
            would_action: sample.would_action,
          })),
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
    settings: () => Promise.resolve(settings.view()),
    validateSettings: (change) =>
      Promise.resolve().then(() => settings.validate(change)),
    applySettings: (change) =>
      Promise.resolve().then(() => applied(settings.apply(change))),
    settingsHistory: () => Promise.resolve(settings.history()),
    rollbackSettings: (revision, base) =>
      Promise.resolve().then(() => applied(settings.rollback(revision, base))),
    auditKey: () => Promise.resolve(auditKey),
    signAudit: (hash) =>
      Promise.resolve(
        /^[0-9a-f]{64}$/.test(hash)
          ? {
              signature: sign(
                null,
                Buffer.from(`larpguard-audit-v1\n${hash}`),
                auditKeys.privateKey,
              ).toString('base64url'),
              key_id: auditKey.key_id,
            }
          : null,
      ),
    reload: () => {
      config.generation += 1;
      config.built_at_ms = now();
      return Promise.resolve({
        reloaded: true as const,
        summary: `generation ${config.generation}: 5 rules, 3 limits (mock)`,
        // The mock has no files: a reload changes nothing.
        changes: [],
        config_hash: MOCK_CONFIG_HASH,
      });
    },
  };
}
