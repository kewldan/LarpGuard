// The settings screen's logic: sections in the order of the YAML, values to
// and from what the fields show, and a draft of changes into the request
// the gateway checks.

import type {
  SettingKey,
  SettingsChange,
  SettingType,
  SettingValue,
} from '../../shared/api.ts';

export interface Section {
  id: string;
  name: string;
  // Keys: "x." takes every key under x, else the exact key.
  keys: string[];
  // YAML sections whose comments describe this one.
  help: string[];
}

export const SECTIONS: Section[] = [
  {
    id: 'listen',
    name: 'Listeners & TLS',
    keys: ['listen.', 'workers', 'passthrough_hosts', 'non_tls', 'no_sni'],
    help: ['listen', 'passthrough_hosts'],
  },
  { id: 'traefik', name: 'Traefik', keys: ['traefik.'], help: ['traefik'] },
  {
    id: 'connections',
    name: 'Timeouts & connections',
    keys: [
      'timeouts.',
      'max_connections',
      'max_requests_per_connection',
      'connection_limits.',
    ],
    help: ['timeouts', 'connection_limits'],
  },
  {
    id: 'policy',
    name: 'Policy & modes',
    keys: ['mode', 'policy.'],
    help: ['mode'],
  },
  { id: 'rules', name: 'Rules', keys: ['rules'], help: ['rules'] },
  {
    id: 'limits',
    name: 'Rate limits',
    keys: ['rate_limits', 'throttle'],
    help: ['rate_limits'],
  },
  {
    id: 'challenge',
    name: 'JS challenge',
    keys: ['challenge.'],
    help: ['challenge'],
  },
  { id: 'captcha', name: 'CAPTCHA', keys: ['captcha.'], help: ['captcha'] },
  {
    id: 'crawlers',
    name: 'Crawlers & Web Bot Auth',
    keys: ['crawlers.', 'web_bot_auth.'],
    help: ['crawlers', 'web_bot_auth'],
  },
  {
    id: 'signals',
    name: 'Behaviour, honeypot & model',
    keys: ['behavior.', 'honeypot.', 'model.'],
    help: ['behavior', 'honeypot', 'model'],
  },
  {
    id: 'actions',
    name: 'Tarpit & decoy',
    keys: ['tarpit.', 'decoy.'],
    help: ['tarpit', 'decoy'],
  },
  {
    id: 'asn',
    name: 'ASN & downloads',
    keys: ['asn.', 'data_dir', 'ca_file'],
    help: ['asn', 'data_dir'],
  },
  { id: 'http3', name: 'HTTP/3', keys: ['http3.'], help: ['http3'] },
  { id: 'xdp', name: 'XDP', keys: ['xdp.'], help: ['xdp'] },
  { id: 'attack', name: 'Attack mode', keys: ['attack.'], help: ['attack'] },
  { id: 'events', name: 'Events', keys: ['events.'], help: ['events'] },
  {
    id: 'admin',
    name: 'Admin, Docker & logs',
    keys: [
      'admin.',
      'docker.',
      'fingerprints.',
      'metrics.',
      'log_level',
      'whoami',
    ],
    help: ['admin', 'docker'],
  },
];

// Keys the gateway reports that no section names (a newer gateway).
export const OTHER: Section = {
  id: 'other',
  name: 'Other',
  keys: [],
  help: [],
};

export function sectionOf(path: string): Section {
  return (
    SECTIONS.find((section) =>
      section.keys.some((key) =>
        key.endsWith('.') ? path.startsWith(key) : path === key,
      ),
    ) ?? OTHER
  );
}

export function findSection(id: string | undefined): Section | undefined {
  return [...SECTIONS, OTHER].find((section) => section.id === id);
}

// The key's name inside its section ("round_timeout" for
// captcha.round_timeout, "difficulty.bot" for challenge.difficulty.bot).
export function shortName(path: string): string {
  const dot = path.indexOf('.');
  return dot < 0 ? path : path.slice(dot + 1);
}

// Types edited as text (the rest are switches and choices).
export function isText(type: SettingType): boolean {
  return type !== 'bool' && type !== 'enum';
}

export function isMultiline(type: SettingType): boolean {
  return (
    type === 'strings' ||
    type === 'host_modes' ||
    type === 'rules' ||
    type === 'rate_limits' ||
    type === 'throttle'
  );
}

// What a field shows for a value.
export function toText(type: SettingType, value: SettingValue): string {
  switch (type) {
    case 'strings':
      return Array.isArray(value) ? value.join('\n') : '';
    case 'host_modes':
      return value && typeof value === 'object' && !Array.isArray(value)
        ? Object.entries(value)
            .map(([host, mode]) => `${host}: ${String(mode)}`)
            .join('\n')
        : '';
    case 'rules':
    case 'rate_limits':
    case 'throttle':
      return value === null ? '' : JSON.stringify(value, null, 2);
    default:
      return value === null ? '' : String(value);
  }
}

export type Parsed = { value: SettingValue } | { error: string };

// A field's text back to a value; the gateway checks the rest.
export function fromText(type: SettingType, text: string): Parsed {
  switch (type) {
    case 'int':
      return /^-?\d+$/.test(text.trim())
        ? { value: Number(text.trim()) }
        : { error: 'expected an integer' };
    case 'number': {
      const value = Number(text.trim());
      return text.trim() !== '' && Number.isFinite(value)
        ? { value }
        : { error: 'expected a number' };
    }
    case 'strings':
      return {
        value: text
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean),
      };
    case 'host_modes': {
      const modes: Record<string, string> = {};
      for (const line of text.split('\n')) {
        if (line.trim() === '') continue;
        const match = /^\s*(\S+)\s*:\s*(\S+)\s*$/.exec(line);
        if (!match?.[1] || !match[2])
          return { error: `expected host: mode, not "${line.trim()}"` };
        modes[match[1]] = match[2];
      }
      return { value: modes };
    }
    case 'rules':
    case 'rate_limits':
    case 'throttle': {
      if (text.trim() === '') {
        return { value: type === 'throttle' ? null : [] };
      }
      try {
        return { value: JSON.parse(text) as SettingValue };
      } catch (error) {
        return {
          error: `not JSON: ${error instanceof Error ? error.message : 'invalid'}`,
        };
      }
    }
    default:
      return { value: text };
  }
}

// One change in the draft: a new value (a secret's new text; "" clears
// it), or back to the main file.
export type DraftEntry =
  | { kind: 'set'; value: SettingValue; text?: string; error?: string }
  | { kind: 'reset' };

export type Draft = ReadonlyMap<string, DraftEntry>;

// The change for the gateway, or the first field that does not parse.
export function toChange(
  draft: Draft,
  revision: string,
): { change: SettingsChange } | { path: string; error: string } {
  const set: Record<string, SettingValue> = {};
  const reset: string[] = [];
  for (const [path, entry] of draft) {
    if (entry.kind === 'reset') {
      reset.push(path);
    } else if (entry.error !== undefined) {
      return { path, error: entry.error };
    } else {
      set[path] = entry.value;
    }
  }
  return { change: { base_revision: revision, set, reset } };
}

export function sameValue(a: SettingValue, b: SettingValue): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

// Puts `value` in the draft, or takes the key out when it is the value in
// effect already.
export function withValue(
  draft: Draft,
  key: SettingKey,
  value: SettingValue,
  text?: string,
  error?: string,
): Map<string, DraftEntry> {
  const next = new Map(draft);
  const unchanged =
    !key.secret && error === undefined && sameValue(value, key.value);
  if (unchanged) next.delete(key.path);
  else
    next.set(key.path, {
      kind: 'set',
      value,
      ...(text === undefined ? {} : { text }),
      ...(error === undefined ? {} : { error }),
    });
  return next;
}

export function withReset(draft: Draft, path: string): Map<string, DraftEntry> {
  const next = new Map(draft);
  next.set(path, { kind: 'reset' });
  return next;
}

export function without(draft: Draft, path: string): Map<string, DraftEntry> {
  const next = new Map(draft);
  next.delete(path);
  return next;
}

// A short form of a value for diffs and hints.
export function preview(value: SettingValue, max = 48): string {
  const text =
    typeof value === 'string'
      ? value === ''
        ? '""'
        : value
      : JSON.stringify(value);
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// Keys and sections matching a ⌘K query.
export function matchKeys(keys: readonly SettingKey[], needle: string) {
  const q = needle.trim().toLowerCase();
  if (q.length < 2) return [];
  return keys.filter((key) => key.path.toLowerCase().includes(q));
}
