// Weights of the reasons in a verdict, from the gateway's configuration:
// library signals, automation signatures, score rules and the clearance
// token. Reasons without a weight (lists, crawlers, allow/block rules)
// return null.

import type { GatewayConfig } from '../../shared/api.ts';
import { reasonBase } from '../../shared/domain.ts';

export function reasonWeight(
  reason: string,
  config: GatewayConfig | undefined,
): number | null {
  if (!config) return null;
  const base = reasonBase(reason);
  const rest = reason.slice(base.length + 1);
  if (base === 'known_automation') {
    return config.library.automation.find((s) => s.id === rest)?.weight ?? null;
  }
  if (base === 'rule') {
    const rule = config.rules.find((r) => r.name === rest);
    return rule?.action === 'score' ? (rule.score ?? 0) : null;
  }
  if (base === 'token_valid') return -config.challenge.token_credit;
  return config.library.weights[base] ?? null;
}

export function thresholdsOf(config: GatewayConfig | undefined): {
  challenge: number;
  block: number;
} {
  return config
    ? {
        challenge: config.policy.suspicious_threshold,
        block: config.policy.bot_threshold,
      }
    : { challenge: 30, block: 70 };
}

// Blocking weights (25 and up) are orange, smaller ones amber, negative
// ones (trust) blue.
export function weightColor(weight: number): string {
  if (weight < 0) return 'var(--color-verified)';
  return weight >= 25
    ? 'var(--color-blocked-text)'
    : 'var(--color-challenged-text)';
}
