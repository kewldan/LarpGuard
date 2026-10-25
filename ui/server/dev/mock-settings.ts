// The development gateway's settings (GET /settings and friends): the
// registry of src/config/settings.cc as data, a main file that matches
// MOCK_CONFIG, and a console layer with history, checked roughly the way
// the gateway checks it. Development and tests only.

import type {
  SettingApply,
  SettingChange,
  SettingSource,
  Settings,
  SettingsDiff,
  SettingsHistory,
  SettingType,
  SettingValue,
} from '../../shared/api.ts';
import { AdminError, type GatewaySettingsChange } from '../gateway/admin.ts';
import { MOCK_CONFIG } from './mock-config.ts';

interface MockKey {
  path: string;
  type: SettingType;
  apply: SettingApply;
  default: SettingValue;
  options?: string[];
  secret?: boolean;
}

const ACTIONS = [
  'allow',
  'challenge',
  'captcha',
  'block',
  'tarpit',
  'decoy',
  'throttle',
];

function key(
  path: string,
  type: SettingType,
  apply: SettingApply,
  value: SettingValue,
  options?: string[],
): MockKey {
  return { path, type, apply, default: value, ...(options ? { options } : {}) };
}

const secret = (path: string): MockKey => ({
  path,
  type: 'string',
  apply: 'restart',
  default: '',
  secret: true,
});

export const MOCK_KEYS: MockKey[] = [
  key('listen.https', 'endpoint', 'yaml', '0.0.0.0:443'),
  key('listen.http', 'endpoint', 'yaml', '0.0.0.0:80'),
  key('workers', 'int', 'restart', 0),
  key('traefik.acme_json', 'string', 'yaml', '/traefik/acme.json'),
  key('traefik.acme_reload_interval', 'duration', 'restart', '2s'),
  key('traefik.upstream_https', 'endpoint', 'yaml', '127.0.0.1:8443'),
  key('traefik.upstream_http', 'endpoint', 'yaml', '127.0.0.1:8080'),
  key('traefik.proxy_protocol', 'bool', 'restart', true),
  key('traefik.pool_size', 'int', 'restart', 4),
  key('traefik.tls_verify', 'bool', 'restart', false),
  key('passthrough_hosts', 'strings', 'restart', []),
  key('non_tls', 'enum', 'restart', 'reject', ['reject', 'passthrough']),
  key('no_sni', 'enum', 'restart', 'reject', ['reject', 'passthrough']),
  key('timeouts.client_hello', 'duration', 'restart', '5s'),
  key('timeouts.tls_handshake', 'duration', 'restart', '10s'),
  key('timeouts.request_headers', 'duration', 'restart', '10s'),
  key('timeouts.upstream_connect', 'duration', 'restart', '5s'),
  key('timeouts.idle', 'duration', 'restart', '5m'),
  key('timeouts.drain', 'duration', 'restart', '30s'),
  key('timeouts.upstream_idle', 'duration', 'restart', '90s'),
  key('max_connections', 'int', 'restart', 100000),
  key('max_requests_per_connection', 'int', 'restart', 1000),
  key('events.nats', 'endpoint', 'yaml', ''),
  key('events.subject_prefix', 'string', 'restart', 'botshield.events'),
  secret('events.token'),
  key('events.user', 'string', 'restart', ''),
  secret('events.password'),
  key('events.max_queue', 'int', 'restart', 100000),
  secret('events.ip_salt'),
  key('events.requests', 'bool', 'restart', true),
  key('mode', 'enum', 'live', 'shadow', ['shadow', 'enforce']),
  key('policy.thresholds.suspicious', 'int', 'live', 30),
  key('policy.thresholds.bot', 'int', 'live', 70),
  key('policy.actions.suspicious', 'enum', 'live', 'allow', ACTIONS),
  key('policy.actions.bot', 'enum', 'live', 'block', ACTIONS),
  key('policy.actions.verified_bot', 'enum', 'live', 'allow', ACTIONS),
  key('policy.block_status', 'int', 'live', 403),
  key('policy.hosts', 'host_modes', 'live', {}),
  key('rules', 'rules', 'live', []),
  key('rate_limits', 'rate_limits', 'live', []),
  key('connection_limits.open_per_ip', 'int', 'restart', 0),
  key('connection_limits.new_per_ip', 'rate', 'restart', ''),
  key('connection_limits.new_burst_per_ip', 'int', 'restart', 1),
  key('connection_limits.pending_per_ip', 'int', 'restart', 128),
  key('docker.socket', 'string', 'yaml', ''),
  key('docker.poll_interval', 'duration', 'restart', '5s'),
  key('behavior.enabled', 'bool', 'restart', true),
  key('behavior.window', 'duration', 'restart', '10m'),
  key('behavior.max_clients', 'int', 'restart', 500000),
  key('honeypot.paths', 'strings', 'live', [
    '/.env',
    '/.env.*',
    '/.git/*',
    '/.svn/*',
    '/.aws/*',
    '/.ssh/*',
    '/.DS_Store',
    '/wp-config.php*',
    '/.htpasswd',
    '/server-status',
    '/phpinfo.php',
  ]),
  key('honeypot.ttl', 'duration', 'restart', '1h'),
  key('throttle', 'throttle', 'live', null),
  key('tarpit.duration', 'duration', 'restart', '30s'),
  key('tarpit.interval', 'duration', 'restart', '1s'),
  key('tarpit.chunk', 'int', 'restart', 16),
  key('tarpit.max_active', 'int', 'restart', 1000),
  key('decoy.html_file', 'string', 'yaml', ''),
  key('decoy.json_file', 'string', 'yaml', ''),
  key('decoy.labyrinth', 'bool', 'restart', false),
  key('http3.enabled', 'bool', 'restart', false),
  key('http3.idle_timeout', 'duration', 'restart', '30s'),
  key('http3.retry', 'bool', 'restart', true),
  key('http3.max_connections', 'int', 'restart', 10000),
  key('http3.alt_svc_max_age', 'duration', 'restart', '24h'),
  key('http3.advertise_port', 'int', 'restart', 0),
  key('model.file', 'string', 'yaml', ''),
  key('model.threshold', 'number', 'live', 0.8),
  key('model.log_features', 'bool', 'restart', true),
  key('crawlers.verify', 'bool', 'restart', true),
  key('crawlers.ai', 'enum', 'live', 'default', ['default', ...ACTIONS]),
  key('crawlers.ai_robots', 'bool', 'live', false),
  key('crawlers.ip_ranges', 'bool', 'restart', true),
  key('crawlers.ranges_refresh', 'duration', 'restart', '24h'),
  key('web_bot_auth.enabled', 'bool', 'restart', true),
  key('web_bot_auth.trusted', 'strings', 'live', ['chatgpt.com']),
  key('web_bot_auth.max_validity', 'duration', 'restart', '24h'),
  key(
    'asn.url',
    'string',
    'restart',
    'https://iptoasn.com/data/ip2asn-combined.tsv.gz',
  ),
  key('asn.refresh', 'duration', 'restart', '24h'),
  key('data_dir', 'string', 'yaml', ''),
  key('ca_file', 'string', 'yaml', ''),
  key('captcha.provider', 'enum', 'restart', '', [
    '',
    'builtin',
    'turnstile',
    'hcaptcha',
    'recaptcha',
  ]),
  key('captcha.site_key', 'string', 'restart', ''),
  key('captcha.secret_file', 'string', 'yaml', ''),
  secret('captcha.secret'),
  key('captcha.verify_url', 'string', 'yaml', ''),
  key('captcha.check_hostname', 'bool', 'restart', true),
  key('captcha.escalate', 'bool', 'restart', true),
  key('captcha.rounds', 'int', 'restart', 2),
  key('captcha.round_timeout', 'duration', 'restart', '30s'),
  key('captcha.difficulty', 'int', 'restart', 12),
  key('xdp.enabled', 'bool', 'restart', false),
  key('xdp.interface', 'string', 'restart', ''),
  key('xdp.mode', 'enum', 'restart', 'auto', ['auto', 'native', 'generic']),
  key('xdp.syn_rate', 'rate', 'restart', ''),
  key('xdp.syn_burst', 'int', 'restart', 1),
  key('xdp.drop_invalid', 'bool', 'restart', true),
  key('xdp.drop_fragments', 'bool', 'restart', false),
  key('xdp.heartbeat_timeout', 'duration', 'restart', '5s'),
  key('xdp.block_honeypot', 'bool', 'restart', false),
  key('challenge.keys_file', 'string', 'yaml', ''),
  key('challenge.token_ttl', 'duration', 'restart', '12h'),
  key('challenge.difficulty.suspicious', 'int', 'restart', 16),
  key('challenge.difficulty.bot', 'int', 'restart', 19),
  key('challenge.token_credit', 'int', 'restart', 40),
  key('challenge.endpoint_rate', 'rate', 'restart', '30/m'),
  key('challenge.endpoint_burst', 'int', 'restart', 10),
  key('attack.auto_rps', 'int', 'restart', 0),
  key('attack.auto_duration', 'duration', 'restart', '10m'),
  key('notify.name', 'string', 'restart', ''),
  { ...secret('notify.webhook'), apply: 'yaml' },
  { ...secret('notify.telegram.token'), apply: 'yaml' },
  key('notify.telegram.chat_id', 'string', 'yaml', ''),
  key('notify.nats_down_after', 'duration', 'restart', '1m'),
  key('notify.repeat_after', 'duration', 'restart', '5m'),
  key('admin.socket', 'string', 'yaml', ''),
  key('admin.state_file', 'string', 'yaml', ''),
  key('admin.modes_file', 'string', 'yaml', ''),
  key('admin.settings_file', 'string', 'yaml', ''),
  key('admin.decisions', 'int', 'restart', 10000),
  key('fingerprints.library', 'string', 'yaml', ''),
  key('metrics.listen', 'endpoint', 'yaml', '127.0.0.1:9900'),
  key('log_level', 'enum', 'restart', 'info', [
    'debug',
    'info',
    'warn',
    'error',
  ]),
  key('whoami', 'bool', 'restart', false),
];

function rate(count: number, periodMs: number): string {
  const unit =
    periodMs === 86_400_000
      ? 'd'
      : periodMs === 3_600_000
        ? 'h'
        : periodMs === 60_000
          ? 'm'
          : 's';
  return `${count}/${unit}`;
}

// The development main file: what MOCK_CONFIG shows, plus deployment paths.
function mainFile(): Map<string, SettingValue> {
  const c = MOCK_CONFIG;
  return new Map<string, SettingValue>([
    ['mode', c.policy.enforce ? 'enforce' : 'shadow'],
    ['policy.thresholds.suspicious', c.policy.suspicious_threshold],
    ['policy.thresholds.bot', c.policy.bot_threshold],
    ['policy.actions.suspicious', c.policy.suspicious_action],
    ['policy.actions.bot', c.policy.bot_action],
    [
      'rules',
      c.rules.map((rule) => ({
        name: rule.name,
        when: rule.when,
        action: rule.action,
        ...(rule.action === 'score' ? { score: rule.score ?? 0 } : {}),
      })),
    ],
    [
      'rate_limits',
      c.rate_limits.map((limit) => ({
        name: limit.name,
        hosts: limit.hosts,
        paths: limit.paths,
        methods: limit.methods,
        classes: limit.classes,
        key: limit.key,
        rate: rate(limit.count, limit.period_ms),
        burst: limit.burst,
        ...(limit.statuses.length ? { statuses: limit.statuses } : {}),
      })),
    ],
    [
      'throttle',
      c.throttle
        ? {
            rate: rate(c.throttle.count, c.throttle.period_ms),
            burst: c.throttle.burst,
            key: c.throttle.key,
          }
        : null,
    ],
    ['honeypot.paths', c.honeypot_paths],
    ['crawlers.ai', c.crawlers.ai_action ?? 'default'],
    ['captcha.provider', c.captcha.provider],
    ['attack.auto_rps', c.attack.auto_rps],
    ['events.nats', '127.0.0.1:4222'],
    ['events.token', 'dev-token'],
    ['events.ip_salt', 'dev-salt'],
    ['docker.socket', '/var/run/docker.sock'],
    ['data_dir', '/var/lib/bot-shield/data'],
    ['admin.socket', '/run/bot-shield/admin.sock'],
    ['admin.state_file', '/var/lib/bot-shield/lists.json'],
    ['admin.modes_file', '/var/lib/bot-shield/modes.json'],
    ['admin.settings_file', '/var/lib/bot-shield/settings.yaml'],
    ['challenge.keys_file', '/etc/bot-shield/challenge-keys.json'],
    ['whoami', false],
  ]);
}

const DURATION = /^\d+(ms|s|m|h)$/;
const RATE = /^\d+\/[smhd]$/;

function fail(path: string, message: string): never {
  throw new AdminError(422, `${path}: ${message}`, undefined, path);
}

function checkValue(spec: MockKey, value: SettingValue): void {
  const { path } = spec;
  const shape = (ok: boolean, expected: string) => {
    if (!ok)
      throw new AdminError(
        400,
        `${path}: expected ${expected}`,
        undefined,
        path,
      );
  };
  switch (spec.type) {
    case 'bool':
      shape(typeof value === 'boolean', 'true or false');
      return;
    case 'int':
      shape(Number.isInteger(value), 'an integer');
      if ((value as number) < 0) fail(path, 'expected >= 0');
      return;
    case 'number':
      shape(typeof value === 'number', 'a number');
      return;
    case 'enum':
      shape(
        typeof value === 'string' && (spec.options ?? []).includes(value),
        'one of the listed values',
      );
      return;
    case 'duration':
      shape(typeof value === 'string', 'a string');
      if (
        !DURATION.test(value as string) ||
        /^0+(ms|s|m|h)$/.test(value as string)
      )
        fail(path, 'expected a positive duration like 5s or 250ms');
      return;
    case 'rate':
      shape(typeof value === 'string', 'a string');
      if (value !== '' && !RATE.test(value as string))
        fail(path, 'expected a rate like 30/m');
      return;
    case 'string':
    case 'endpoint':
      shape(typeof value === 'string', 'a string');
      return;
    case 'strings':
      shape(
        Array.isArray(value) && value.every((item) => typeof item === 'string'),
        'a list of strings',
      );
      return;
    case 'host_modes':
      shape(
        typeof value === 'object' && value !== null && !Array.isArray(value),
        'host: mode pairs',
      );
      return;
    case 'rules':
    case 'rate_limits':
      shape(Array.isArray(value), 'a list');
      return;
    case 'throttle':
      shape(
        value === null || (typeof value === 'object' && !Array.isArray(value)),
        '{rate, burst, key} or null',
      );
      return;
  }
}

// What the gateway's parser would refuse across keys.
function checkConfig(get: (path: string) => SettingValue): void {
  const range = (path: string, low: number, high: number) => {
    const value = get(path) as number;
    if (value < low || value > high) fail(path, `expected ${low}..${high}`);
  };
  range('captcha.rounds', 1, 5);
  range('captcha.difficulty', 0, 20);
  range('challenge.difficulty.suspicious', 0, 26);
  range('challenge.difficulty.bot', 0, 26);
  range('challenge.token_credit', 0, 100);
  range('policy.block_status', 400, 599);
  range('traefik.pool_size', 1, 64);
  range('http3.advertise_port', 0, 65535);
  const suspicious = get('policy.thresholds.suspicious') as number;
  const bot = get('policy.thresholds.bot') as number;
  if (suspicious < 1 || bot > 100 || suspicious > bot) {
    fail(
      'policy.thresholds.suspicious',
      'expected 1 <= suspicious <= bot <= 100',
    );
  }
  const threshold = get('model.threshold') as number;
  if (threshold <= 0 || threshold >= 1)
    fail('model.threshold', 'expected 0 < threshold < 1');
  const provider = get('captcha.provider');
  if (
    provider !== '' &&
    provider !== 'builtin' &&
    (get('captcha.site_key') === '' || get('captcha.secret') === '')
  ) {
    fail(
      'captcha.provider',
      `${String(provider)} needs site_key and secret_file (or secret)`,
    );
  }
  if (get('xdp.enabled') === true && get('xdp.interface') === '') {
    fail('xdp.interface', 'required when xdp.enabled (e.g. eth0)');
  }
}

export interface MockSettings {
  view(): Settings;
  validate(change: GatewaySettingsChange): SettingsDiff;
  apply(change: GatewaySettingsChange): SettingsDiff;
  history(): SettingsHistory;
  rollback(revision: string, base: string): SettingsDiff;
  value(path: string): SettingValue;
}

export function createMockSettings(now: () => number): MockSettings {
  const file = mainFile();
  let layer = new Map<string, SettingValue>([['captcha.difficulty', 14]]);
  let counter = 1;
  const revisionOf = (n: number) => n.toString(16).padStart(16, '0');
  let revision = revisionOf(counter);
  const history: {
    revision: string;
    replaced_at_ms: number;
    layer: Map<string, SettingValue>;
  }[] = [];
  const byPath = new Map(MOCK_KEYS.map((spec) => [spec.path, spec]));

  const effective = (from: Map<string, SettingValue>, path: string) => {
    if (from.has(path)) return from.get(path) as SettingValue;
    if (file.has(path)) return file.get(path) as SettingValue;
    return byPath.get(path)?.default ?? null;
  };
  const source = (
    from: Map<string, SettingValue>,
    path: string,
  ): SettingSource =>
    from.has(path) ? 'console' : file.has(path) ? 'file' : 'default';
  // What the running process started with.
  const running = new Map(
    MOCK_KEYS.map((spec) => [spec.path, effective(layer, spec.path)]),
  );
  const same = (a: SettingValue, b: SettingValue) =>
    JSON.stringify(a) === JSON.stringify(b);
  const pending = (spec: MockKey, from: Map<string, SettingValue>) =>
    spec.apply === 'restart' &&
    !same(effective(from, spec.path), running.get(spec.path) ?? null);

  const diff = (next: Map<string, SettingValue>): SettingChange[] => {
    const changes: SettingChange[] = [];
    for (const spec of MOCK_KEYS) {
      const before = effective(layer, spec.path);
      const after = effective(next, spec.path);
      const base = {
        path: spec.path,
        apply: spec.apply,
        source_before: source(layer, spec.path),
        source_after: source(next, spec.path),
        pending_restart: pending(spec, next),
      };
      if (same(before, after) && base.source_before === base.source_after)
        continue;
      changes.push(
        spec.secret
          ? {
              ...base,
              secret: true,
              set_before: before !== '',
              set_after: after !== '',
              value_changed: !same(before, after),
            }
          : { ...base, secret: false, before, after },
      );
    }
    return changes;
  };

  const prepare = (change: GatewaySettingsChange) => {
    if (change.base_revision !== revision) {
      throw new AdminError(409, 'the settings changed since they were read');
    }
    const next = new Map(layer);
    for (const [path, value] of Object.entries(change.set)) {
      const spec = byPath.get(path);
      if (!spec)
        throw new AdminError(400, `unknown key '${path}'`, undefined, path);
      if (spec.apply === 'yaml') fail(path, 'can only be set in the main file');
      checkValue(spec, value);
      next.set(path, value);
    }
    for (const path of change.reset) next.delete(path);
    checkConfig((path) => effective(next, path));
    return next;
  };

  const commit = (next: Map<string, SettingValue>): SettingsDiff => {
    const changes = diff(next);
    history.unshift({ revision, replaced_at_ms: now(), layer });
    history.splice(20);
    layer = next;
    counter += 1;
    revision = revisionOf(counter);
    return { revision, changes };
  };

  return {
    view: () => {
      const keys = MOCK_KEYS.map((spec) => {
        const base = {
          path: spec.path,
          type: spec.type,
          apply: spec.apply,
          source: source(layer, spec.path),
          pending_restart: pending(spec, layer),
          ...(spec.options ? { options: spec.options } : {}),
        };
        if (spec.secret) {
          return {
            ...base,
            secret: true as const,
            set: effective(layer, spec.path) !== '',
          };
        }
        return {
          ...base,
          secret: false as const,
          value: effective(layer, spec.path),
          default: spec.default,
          ...(layer.has(spec.path) && file.has(spec.path)
            ? { file_value: file.get(spec.path) as SettingValue }
            : {}),
        };
      });
      return {
        editable: true,
        revision,
        error: null,
        pending_restart: keys.some((key) => key.pending_restart),
        keys,
      };
    },
    validate: (change) => {
      const next = prepare(change);
      return { revision: revisionOf(counter + 1), changes: diff(next) };
    },
    apply: (change) => commit(prepare(change)),
    history: () => ({
      revision,
      versions: history.map((version) => ({
        revision: version.revision,
        replaced_at_ms: version.replaced_at_ms,
        keys: [...version.layer.keys()],
      })),
    }),
    rollback: (target, base) => {
      if (base !== revision) {
        throw new AdminError(409, 'the settings changed since they were read');
      }
      const version = history.find((item) => item.revision === target);
      if (!version) throw new AdminError(404, `no version ${target}`);
      return commit(new Map(version.layer));
    },
    value: (path) => effective(layer, path),
  };
}
