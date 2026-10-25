// Snippets of the gateway's YAML for changes the console cannot make itself
// (the configuration file is the source of truth).

import type { Candidates, GatewayConfig, Limit } from '../../shared/api.ts';
import type { Action } from '../../shared/domain.ts';

export interface RuleDraft {
  name: string;
  when: string;
  action: Action | 'score';
  score: number;
}

export function perSecond(limit: Pick<Limit, 'count' | 'period_ms'>): number {
  return limit.period_ms > 0 ? (limit.count * 1000) / limit.period_ms : 0;
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
  return `rate_limits:\n${lines.join('\n')}`;
}

export function ruleYaml(draft: RuleDraft): string {
  const lines = [
    `  - name: ${draft.name}`,
    `    when: '${draft.when.replace(/\s*\n\s*/g, ' ').replace(/'/g, "''")}'`,
    `    action: ${draft.action}`,
  ];
  if (draft.action === 'score') lines.push(`    score: ${draft.score}`);
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
