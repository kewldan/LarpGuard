// Gateway vocabulary shared by the BFF and the SPA: actions, classes, host
// modes and time ranges, as the gateway names them (src/score/policy.h,
// src/score/scorer.h).

export const ACTIONS = [
  'allow',
  'challenge',
  'captcha',
  'throttle',
  'tarpit',
  'decoy',
  'block',
] as const;
export type Action = (typeof ACTIONS)[number];

export function isAction(value: string): value is Action {
  return (ACTIONS as readonly string[]).includes(value);
}

// What a request's event records as its action: the actions above, and
// rate_limit for a request a limit refused (429). Not a policy action.
export const OUTCOMES = [...ACTIONS, 'rate_limit'] as const;
export type Outcome = (typeof OUTCOMES)[number];

export function isOutcome(value: string): value is Outcome {
  return (OUTCOMES as readonly string[]).includes(value);
}

// Seven actions fold into three tones ("03 Actions, classes, modes"); a
// rate-limit refusal counts as blocked.
export type ActionTone = 'allowed' | 'challenged' | 'blocked';
export type ActionStyle = 'soft' | 'outline' | 'filled';

export const ACTION_LOOK: Record<
  Outcome,
  { tone: ActionTone; style: ActionStyle }
> = {
  allow: { tone: 'allowed', style: 'soft' },
  challenge: { tone: 'challenged', style: 'soft' },
  captcha: { tone: 'challenged', style: 'soft' },
  throttle: { tone: 'challenged', style: 'outline' },
  tarpit: { tone: 'challenged', style: 'outline' },
  decoy: { tone: 'blocked', style: 'outline' },
  block: { tone: 'blocked', style: 'filled' },
  rate_limit: { tone: 'blocked', style: 'outline' },
};

// Actions counted as "blocked" and "challenged" in charts and KPIs: the
// same split as the tones.
export const BLOCKING_ACTIONS: readonly Outcome[] = [
  'block',
  'decoy',
  'rate_limit',
];
export const CHALLENGING_ACTIONS: readonly Action[] = [
  'challenge',
  'captcha',
  'throttle',
  'tarpit',
];

export const BOT_CLASSES = [
  'human',
  'suspicious',
  'bot',
  'verified_bot',
] as const;
export type BotClass = (typeof BOT_CLASSES)[number];

export const HOST_MODES = ['shadow', 'enforce', 'off'] as const;
export type HostMode = (typeof HOST_MODES)[number];

export const MODE_SOURCES = [
  'console',
  'policy.hosts',
  'labels',
  'mode',
] as const;
export type ModeSource = (typeof MODE_SOURCES)[number];

// Time ranges of the analytics screens; raw events live 14 days.
export const RANGES = ['15m', '1h', '6h', '24h', '7d'] as const;
export type Range = (typeof RANGES)[number];

export const RANGE_SECONDS: Record<Range, number> = {
  '15m': 15 * 60,
  '1h': 60 * 60,
  '6h': 6 * 60 * 60,
  '24h': 24 * 60 * 60,
  '7d': 7 * 24 * 60 * 60,
};

// Chart buckets per range: 60 points, a round step.
export const RANGE_STEP_SECONDS: Record<Range, number> = {
  '15m': 15,
  '1h': 60,
  '6h': 6 * 60,
  '24h': 24 * 60,
  '7d': 168 * 60,
};

export const LIST_KINDS = ['ip', 'ja4', 'header_fp'] as const;
export type ListKind = (typeof LIST_KINDS)[number];

export const ROLES = ['viewer', 'operator'] as const;
export type Role = (typeof ROLES)[number];

// Reason codes with a parameter: "rule:<name>", "list:<id>",
// "verified_crawler:<id>", "fake_crawler:<id>", "signed_agent:<host>",
// "known_automation:<id>".
export function reasonBase(reason: string): string {
  const colon = reason.indexOf(':');
  return colon < 0 ? reason : reason.slice(0, colon);
}
