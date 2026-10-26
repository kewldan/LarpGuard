// Snippets of the gateway's YAML for changes the console cannot make itself
// (the configuration file is the source of truth).

import type { Candidates, GatewayConfig, Limit } from '../../shared/api.ts';
import type { Action } from '../../shared/domain.ts';

export interface RuleDraft {
  name: string;
  when: string;
  action: Action | 'score';
  score: number;
  disabled?: boolean;
}

// A rule as the gateway's settings take it (the `rules` key).
export function ruleSpec(draft: RuleDraft): {
  name: string;
  when: string;
  action: string;
  score?: number;
  disabled?: boolean;
} {
  return {
    name: draft.name,
    when: draft.when,
    action: draft.action,
    ...(draft.action === 'score' ? { score: draft.score } : {}),
    ...(draft.disabled ? { disabled: true } : {}),
  };
}

export function perSecond(limit: Pick<Limit, 'count' | 'period_ms'>): number {
  return limit.period_ms > 0 ? (limit.count * 1000) / limit.period_ms : 0;
}

// "30/m" as the gateway writes a rate (FormatRate).
export function formatRate(count: number, periodMs: number): string {
  if (periodMs === 86_400_000) return `${count}/d`;
  if (periodMs === 3_600_000) return `${count}/h`;
  if (periodMs === 60_000) return `${count}/m`;
  return `${count}/s`;
}

// A what-if rate in requests per second as a rate setting.
export function rateOf(rps: number): string {
  return rps >= 1 ? `${Math.round(rps)}/s` : `${Math.round(rps * 60)}/m`;
}

// A limit as the gateway's settings take it (the `rate_limits` key);
// `rate` and `burst` replace its own when given.
export function limitSpec(
  limit: Limit,
  change?: { rate: string; burst: number },
): Record<string, string | number | string[] | number[]> {
  return {
    name: limit.name,
    hosts: limit.hosts,
    paths: limit.paths,
    methods: limit.methods,
    classes: limit.classes,
    key: limit.key,
    rate: change?.rate ?? formatRate(limit.count, limit.period_ms),
    burst: change?.burst ?? limit.burst,
    ...(limit.statuses.length > 0 ? { statuses: limit.statuses } : {}),
    ...(limit.mode !== 'local' ? { mode: limit.mode } : {}),
  };
}

export function limitYaml(limit: Limit, rps: number, burst: number): string {
  const lines = [`  - name: ${limit.name}`];
  if (limit.hosts.length) lines.push(`    hosts: [${limit.hosts.join(', ')}]`);
  if (limit.paths.length)
    lines.push(`    paths: [${limit.paths.map((p) => `"${p}"`).join(', ')}]`);
  if (limit.methods.length)
    lines.push(`    methods: [${limit.methods.join(', ')}]`);
  if (limit.classes.length)
    lines.push(`    classes: [${limit.classes.join(', ')}]`);
  lines.push(
    `    key: [${limit.key.map((k) => (k.includes(':') ? `"${k}"` : k)).join(', ')}]`,
  );
  if (limit.statuses.length)
    lines.push(`    statuses: [${limit.statuses.join(', ')}]`);
  lines.push(
    `    rate: ${rps >= 1 ? `${Math.round(rps)}/s` : `${Math.round(rps * 60)}/m`}`,
  );
  lines.push(`    burst: ${burst}`);
  if (limit.mode !== 'local') lines.push(`    mode: ${limit.mode}`);
  return `rate_limits:\n${lines.join('\n')}`;
}

export function ruleYaml(draft: RuleDraft): string {
  const lines = [
    `  - name: ${draft.name}`,
    `    when: '${draft.when.replace(/\s*\n\s*/g, ' ').replace(/'/g, "''")}'`,
    `    action: ${draft.action}`,
  ];
  if (draft.action === 'score') lines.push(`    score: ${draft.score}`);
  if (draft.disabled) lines.push('    disabled: true');
  return `rules:\n${lines.join('\n')}`;
}

// The engine's profile with the candidate's values added.
export function candidateYaml(
  candidate: Candidates['candidates'][number],
  browsers: GatewayConfig['library']['browsers'],
): string {
  const profile = browsers.find((b) => b.id === candidate.profile);
  const ciphers = [...(profile?.ja4_ciphers ?? [])];
  if (candidate.new_ciphers) ciphers.push(candidate.ciphers);
  const orders = [...(profile?.h2_pseudo_orders ?? [])];
  if (candidate.new_pseudo_order) orders.push(candidate.pseudo_order);
  const lines = [
    'browsers:',
    `  - id: ${candidate.profile ?? candidate.engine}`,
    `    engines: [${(profile?.engines ?? [candidate.engine]).join(', ')}]`,
    `    ja4_ciphers: [${ciphers.join(', ')}]`,
  ];
  if (orders.length) {
    lines.push(
      `    h2_pseudo_orders: [${orders.map((o) => `"${o}"`).join(', ')}]`,
    );
  }
  return lines.join('\n');
}
