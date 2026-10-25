// The explorer's query bar: filters as text, "host:shop.example.com
// action:block,challenge score>=40 asn:64496". Unknown words are errors,
// so a typo never silently widens the result.

import {
  BOT_CLASSES,
  type BotClass,
  OUTCOMES,
  type Outcome,
} from '../../shared/domain.ts';

export interface FilterFields {
  host?: string;
  action?: Outcome[];
  class?: BotClass[];
  reason?: string;
  asn?: number;
  ja4?: string;
  ip_prefix?: string;
  ip_hash?: string;
  path?: string;
  min_score?: number;
}

const KEYS = [
  'host',
  'action',
  'class',
  'reason',
  'asn',
  'ja4',
  'ip',
  'h',
  'path',
] as const;

export function filterToText(filter: FilterFields): string {
  const parts: string[] = [];
  if (filter.host) parts.push(`host:${filter.host}`);
  if (filter.action?.length) parts.push(`action:${filter.action.join(',')}`);
  if (filter.class?.length) parts.push(`class:${filter.class.join(',')}`);
  if (filter.reason) parts.push(`reason:${filter.reason}`);
  if (filter.asn !== undefined) parts.push(`asn:${filter.asn}`);
  if (filter.ja4) parts.push(`ja4:${filter.ja4}`);
  if (filter.ip_prefix) parts.push(`ip:${filter.ip_prefix}`);
  if (filter.ip_hash) parts.push(`h:${filter.ip_hash}`);
  if (filter.path) parts.push(`path:${filter.path}`);
  if (filter.min_score !== undefined) parts.push(`score>=${filter.min_score}`);
  return parts.join(' ');
}

export type ParseResult =
  | { ok: true; filter: FilterFields }
  | { ok: false; error: string };

export function parseFilterText(text: string): ParseResult {
  const filter: FilterFields = {};
  for (const word of text.trim().split(/\s+/).filter(Boolean)) {
    const score = /^score>=?(\d{1,3})$/.exec(word);
    if (score) {
      const value = Number(score[1]) + (word.includes('>=') ? 0 : 1);
      if (value > 100) return { ok: false, error: 'score goes up to 100' };
      filter.min_score = value;
      continue;
    }
    const colon = word.indexOf(':');
    const key = word.slice(0, colon) as (typeof KEYS)[number];
    const value = word.slice(colon + 1);
    if (colon <= 0 || !KEYS.includes(key) || value === '') {
      return {
        ok: false,
        error: `"${word}": use ${KEYS.map((k) => `${k}:`).join(' ')} or score>=N`,
      };
    }
    switch (key) {
      case 'host':
        filter.host = value.toLowerCase();
        break;
      case 'action': {
        const actions = value.split(',');
        const bad = actions.find(
          (a) => !(OUTCOMES as readonly string[]).includes(a),
        );
        if (bad) return { ok: false, error: `unknown action "${bad}"` };
        filter.action = actions as Outcome[];
        break;
      }
      case 'class': {
        const classes = value.split(',');
        const bad = classes.find(
          (c) => !(BOT_CLASSES as readonly string[]).includes(c),
        );
        if (bad) return { ok: false, error: `unknown class "${bad}"` };
        filter.class = classes as BotClass[];
        break;
      }
      case 'reason':
        filter.reason = value;
        break;
      case 'asn': {
        const asn = Number(value.replace(/^as/i, ''));
        if (!Number.isInteger(asn) || asn <= 0)
          return { ok: false, error: `bad AS number "${value}"` };
        filter.asn = asn;
        break;
      }
      case 'ja4':
        filter.ja4 = value;
        break;
      case 'ip':
        filter.ip_prefix = value;
        break;
      case 'h':
        if (!/^[0-9a-f]{1,32}$/.test(value))
          return { ok: false, error: 'h: takes hex' };
        filter.ip_hash = value;
        break;
      case 'path':
        filter.path = value;
        break;
    }
  }
  return { ok: true, filter };
}
