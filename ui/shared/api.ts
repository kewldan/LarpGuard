// The console API (/api/*): request and response schemas shared by the BFF,
// which validates what it receives and sends, and the SPA, which takes its
// types from here. Times are Unix milliseconds; addresses are never full,
// only ip_prefix (/24, /48) and ip_hash (as in events).

import { z } from 'zod';

import {
  ACTIONS,
  BOT_CLASSES,
  HOST_MODES,
  LIST_KINDS,
  MODE_SOURCES,
  RANGES,
  ROLES,
} from './domain.ts';

export const actionSchema = z.enum(ACTIONS);
export const botClassSchema = z.enum(BOT_CLASSES);
export const hostModeSchema = z.enum(HOST_MODES);
export const modeSourceSchema = z.enum(MODE_SOURCES);
export const rangeSchema = z.enum(RANGES);
export const roleSchema = z.enum(ROLES);
export const listKindSchema = z.enum(LIST_KINDS);

// Host names as the gateway accepts them: a name or "*.parent".
export const hostSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(
    /^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$/,
    'invalid host name',
  );

export const errorSchema = z.object({
  error: z.string(),
  // Column (1-based, in the whole text) of a rule compile error.
  column: z.number().int().optional(),
  // The settings key a refused change is about.
  path: z.string().optional(),
});
export type ApiError = z.infer<typeof errorSchema>;

// --- Session -----------------------------------------------------------------

export const sessionSchema = z.object({
  user: z.object({ name: z.string(), role: roleSchema }),
  csrf: z.string(),
  expires_at: z.number(),
});
export type Session = z.infer<typeof sessionSchema>;

export const loginSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256),
  totp: z.string().regex(/^\d{6}$/, 'six digits'),
});
export type Login = z.infer<typeof loginSchema>;

// For the sign-in screen: what the gateway decided about the current
// request (its X-Bot-* headers, set when the console sits behind it;
// fields are null otherwise) and whether passkeys are on.
export const whoamiSchema = z.object({
  score: z.number().nullable(),
  class: z.string().nullable(),
  reasons: z.array(z.string()),
  request_id: z.string().nullable(),
  ip_prefix: z.string().nullable(),
  passkeys: z.boolean(),
});
export type Whoami = z.infer<typeof whoamiSchema>;

// The sign-in screen's connection check: the browser times these calls
// for the network; the answer is the server side of it. `server_ms` is
// the time spent answering (subtracted from the round trip), `loop_ms`
// how far the console's event loop lagged recently, `gateway_ms` how long
// the gateway's admin API took (null: it did not answer).
export const pingSchema = z.object({
  server_ms: z.number(),
  loop_ms: z.number(),
  gateway_ms: z.number().nullable(),
});
export type Ping = z.infer<typeof pingSchema>;

// --- Passkeys ----------------------------------------------------------------

// WebAuthn JSON (PublicKeyCredential*OptionsJSON, *ResponseJSON) is checked
// by the WebAuthn library on the server; here only its outline.
const webauthnJson = z.custom<object>(
  (value) => typeof value === 'object' && value !== null,
);
const credentialResponse = z.looseObject({ id: z.string().min(1).max(1024) });

export const passkeyOptionsSchema = z.object({
  // Names the challenge of this sign-in (absent for registration, which is
  // bound to the session).
  ceremony: z.string().optional(),
  options: webauthnJson,
});
export type PasskeyOptions = z.infer<typeof passkeyOptionsSchema>;

export const passkeySignInSchema = z.object({
  ceremony: z.string().max(64),
  response: credentialResponse,
});

// Adding a passkey asks for the password and a code again: a stolen
// session alone cannot plant a lasting credential.
export const passkeyReauthSchema = loginSchema.omit({ username: true });

export const newPasskeySchema = z.object({
  name: z.string().trim().min(1).max(64),
  response: credentialResponse,
});
export type NewPasskey = z.infer<typeof newPasskeySchema>;

export const passkeySchema = z.object({
  id: z.string(),
  name: z.string(),
  created_at: z.number(),
  last_used_at: z.number().nullable(),
});
export type Passkey = z.infer<typeof passkeySchema>;

export const passkeyListSchema = z.object({
  // False when console.yaml sets passkeys_file: null.
  enabled: z.boolean(),
  passkeys: z.array(passkeySchema),
});
export type PasskeyList = z.infer<typeof passkeyListSchema>;

// --- Status and health -------------------------------------------------------

export const sourceStateSchema = z.enum(['ok', 'degraded', 'down', 'off']);
export type SourceState = z.infer<typeof sourceStateSchema>;

export const statusSchema = z.object({
  gateway: z
    .object({
      version: z.string(),
      uptime_s: z.number(),
      mode: z.enum(['shadow', 'enforce']),
      generation: z.number(),
      built_at_ms: z.number(),
      workers: z.number(),
      connections_active: z.number(),
      nats_connected: z.boolean(),
      events_dropped: z.number(),
      list_entries: z.number(),
      attack_entries: z.number(),
    })
    .nullable(),
  health: z.object({
    // Admin API reachable.
    admin: sourceStateSchema,
    // /health: every worker loop beats ("degraded": one stalled).
    workers: sourceStateSchema,
    events: sourceStateSchema,
    clickhouse: sourceStateSchema,
    // Seconds since the newest request event (null: unknown).
    clickhouse_lag_s: z.number().nullable(),
    xdp: sourceStateSchema,
  }),
  metrics: z
    .object({
      // Proxied and local requests per second since the previous scrape.
      rps: z.number().nullable(),
      xdp_blocked: z.number().nullable(),
      attack_auto_activations: z.number(),
    })
    .nullable(),
});
export type Status = z.infer<typeof statusSchema>;

// --- Gateway configuration (GET /config, passed through) -------------------

const limitSchema = z.object({
  name: z.string(),
  hosts: z.array(z.string()),
  paths: z.array(z.string()),
  methods: z.array(z.string()),
  classes: z.array(z.string()),
  key: z.array(z.string()),
  count: z.number(),
  period_ms: z.number(),
  burst: z.number(),
  // Origin response statuses the limit counts; empty: every request.
  statuses: z.array(z.number()).default([]),
});
export type Limit = z.infer<typeof limitSchema>;

export const gatewayConfigSchema = z.object({
  generation: z.number(),
  built_at_ms: z.number(),
  policy: z.object({
    enforce: z.boolean(),
    suspicious_threshold: z.number(),
    bot_threshold: z.number(),
    suspicious_action: actionSchema,
    bot_action: actionSchema,
    verified_bot_action: actionSchema,
    block_status: z.number(),
  }),
  rules: z.array(
    z.object({
      name: z.string(),
      when: z.string(),
      action: z.union([actionSchema, z.literal('score')]),
      score: z.number().optional(),
    }),
  ),
  rate_limits: z.array(limitSchema),
  throttle: limitSchema.nullable(),
  honeypot_paths: z.array(z.string()),
  crawlers: z.object({
    verify: z.boolean(),
    ip_ranges: z.boolean(),
    ai_action: actionSchema.nullable(),
    catalog: z.array(
      z.object({
        id: z.string(),
        ai: z.boolean(),
        domains: z.array(z.string()),
        ranges: z.array(z.string()),
      }),
    ),
  }),
  web_bot_auth: z.object({
    enabled: z.boolean(),
    trusted: z.array(z.string()),
  }),
  challenge: z.object({
    suspicious_difficulty: z.number(),
    bot_difficulty: z.number(),
    token_ttl_ms: z.number(),
    token_credit: z.number(),
  }),
  captcha: z.object({
    provider: z.string(),
    escalate: z.boolean(),
    rounds: z.number(),
  }),
  attack: z.object({
    auto_rps: z.number(),
    auto_duration_ms: z.number(),
  }),
  library: z.object({
    version: z.string(),
    profiles: z.number(),
    weights: z.record(z.string(), z.number()),
    automation: z.array(
      z.object({
        id: z.string(),
        weight: z.number(),
        ja4: z.string(),
        h2_fp: z.string(),
        header_fp: z.string(),
        user_agent: z.string(),
      }),
    ),
  }),
  model: z.object({ loaded: z.boolean(), threshold: z.number() }),
});
export type GatewayConfig = z.infer<typeof gatewayConfigSchema>;

// --- Gateway settings (ADR-018) ---------------------------------------------
// Every configuration key with its effective value and where it comes from;
// changes go to the gateway's settings layer. Secrets carry only "set".

export const SETTING_TYPES = [
  'bool',
  'int',
  'number',
  'string',
  'duration',
  'rate',
  'endpoint',
  'enum',
  'strings',
  'host_modes',
  'rules',
  'rate_limits',
  'throttle',
] as const;
export type SettingType = (typeof SETTING_TYPES)[number];
// live: applied at once; restart: after a restart; yaml: main file only.
export const SETTING_APPLY = ['live', 'restart', 'yaml'] as const;
export type SettingApply = (typeof SETTING_APPLY)[number];
export const SETTING_SOURCES = ['default', 'file', 'console'] as const;
export type SettingSource = (typeof SETTING_SOURCES)[number];
export const settingSourceSchema = z.enum(SETTING_SOURCES);

// A value as YAML holds it.
export type SettingValue =
  | string
  | number
  | boolean
  | null
  | SettingValue[]
  | { [key: string]: SettingValue };
export const settingValueSchema: z.ZodType<SettingValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(settingValueSchema),
    z.record(z.string(), settingValueSchema),
  ]),
);

const settingPathSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[a-z0-9_]+(\.[a-z0-9_]+)*$/, 'invalid key');

const settingKeyBase = z.object({
  path: z.string(),
  type: z.enum(SETTING_TYPES),
  apply: z.enum(SETTING_APPLY),
  source: settingSourceSchema,
  pending_restart: z.boolean(),
  options: z.array(z.string()).optional(),
});

// Unknown fields are dropped: a secret's schema has no value to keep.
export const settingKeySchema = z.discriminatedUnion('secret', [
  settingKeyBase.extend({
    secret: z.literal(false),
    value: settingValueSchema,
    default: settingValueSchema,
    // The main file's value under a console one.
    file_value: settingValueSchema.optional(),
  }),
  settingKeyBase.extend({ secret: z.literal(true), set: z.boolean() }),
]);
export type SettingKey = z.infer<typeof settingKeySchema>;

export const settingsSchema = z.object({
  // False without admin.settings_file: read-only.
  editable: z.boolean(),
  revision: z.string(),
  // Why the layer was set aside at startup.
  error: z.string().nullable(),
  pending_restart: z.boolean(),
  keys: z.array(settingKeySchema),
});
export type Settings = z.infer<typeof settingsSchema>;

export const settingsChangeSchema = z
  .object({
    base_revision: z.string().min(1).max(64),
    // Secrets too, as strings ("" clears one).
    set: z.record(settingPathSchema, settingValueSchema).default({}),
    // Keys the main file decides again.
    reset: z.array(settingPathSchema).max(200).default([]),
  })
  .refine(
    (change) => Object.keys(change.set).length + change.reset.length > 0,
    'nothing to change',
  );
export type SettingsChange = z.input<typeof settingsChangeSchema>;

const settingChangeBase = z.object({
  path: z.string(),
  apply: z.enum(SETTING_APPLY),
  source_before: settingSourceSchema,
  source_after: settingSourceSchema,
  pending_restart: z.boolean(),
});

export const settingChangeSchema = z.discriminatedUnion('secret', [
  settingChangeBase.extend({
    secret: z.literal(false),
    before: settingValueSchema,
    after: settingValueSchema,
  }),
  settingChangeBase.extend({
    secret: z.literal(true),
    set_before: z.boolean(),
    set_after: z.boolean(),
    value_changed: z.boolean(),
  }),
]);
export type SettingChange = z.infer<typeof settingChangeSchema>;

export const settingsDiffSchema = z.object({
  revision: z.string(),
  changes: z.array(settingChangeSchema),
});
export type SettingsDiff = z.infer<typeof settingsDiffSchema>;

export const settingsHistorySchema = z.object({
  revision: z.string(),
  versions: z.array(
    z.object({
      revision: z.string(),
      replaced_at_ms: z.number(),
      keys: z.array(z.string()),
    }),
  ),
});
export type SettingsHistory = z.infer<typeof settingsHistorySchema>;

export const settingsRollbackSchema = z.object({
  revision: z.string().min(1).max(64),
  base_revision: z.string().min(1).max(64),
});

// --- Overview ----------------------------------------------------------------

export const verdictPointSchema = z.object({
  t: z.number(),
  // Requests per second in the bucket.
  allowed: z.number(),
  challenged: z.number(),
  blocked: z.number(),
  // On shadow hosts: would have been blocked (not enforced).
  would_block: z.number(),
});
export type VerdictPoint = z.infer<typeof verdictPointSchema>;

export const asnInfoSchema = z.object({
  asn: z.number(),
  org: z.string(),
  country: z.string(),
  hosting: z.boolean(),
});
export type AsnInfo = z.infer<typeof asnInfoSchema>;

export const hostModeInfoSchema = z.object({
  mode: hostModeSchema,
  source: modeSourceSchema,
});

export const overviewSchema = z.object({
  range: rangeSchema,
  step_s: z.number(),
  series: z.array(verdictPointSchema),
  totals: z.object({
    requests: z.number(),
    allowed: z.number(),
    challenged: z.number(),
    blocked: z.number(),
    would_block: z.number(),
  }),
  hosts: z.array(
    z.object({
      host: z.string(),
      requests: z.number(),
      blocked: z.number(),
      would_block: z.number(),
      // Requests per bucket, same buckets as `series`.
      spark: z.array(z.number()),
      mode: hostModeInfoSchema.nullable(),
    }),
  ),
  reasons: z.array(z.object({ reason: z.string(), requests: z.number() })),
  asns: z.array(
    z.object({
      asn: z.number(),
      info: asnInfoSchema.nullable(),
      requests: z.number(),
      blocked: z.number(),
      challenged: z.number(),
    }),
  ),
  crawlers: z.array(
    z.object({ id: z.string(), verified: z.number(), fake: z.number() }),
  ),
});
export type Overview = z.infer<typeof overviewSchema>;

// --- Requests explorer -------------------------------------------------------

const csv = z
  .string()
  .max(2000)
  .transform((text) =>
    text
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0),
  );

export const requestFilterSchema = z.object({
  range: rangeSchema.default('1h'),
  host: csv.optional(),
  action: csv.pipe(z.array(actionSchema)).optional(),
  class: csv.pipe(z.array(botClassSchema)).optional(),
  reason: z.string().max(200).optional(),
  asn: z.coerce.number().int().min(0).max(4294967295).optional(),
  ja4: z.string().max(200).optional(),
  ip_prefix: z.string().max(64).optional(),
  ip_hash: z
    .string()
    .regex(/^[0-9a-f]{1,32}$/)
    .optional(),
  path: z.string().max(500).optional(),
  min_score: z.coerce.number().int().min(0).max(100).optional(),
  max_score: z.coerce.number().int().min(0).max(100).optional(),
  // Older than this request (ts in ms); the explorer pages backwards.
  before: z.coerce.number().int().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});
export type RequestFilter = z.input<typeof requestFilterSchema>;
export type RequestFilterParsed = z.output<typeof requestFilterSchema>;

export const requestRowSchema = z.object({
  ts: z.number(),
  request_id: z.string(),
  host: z.string(),
  method: z.string(),
  path_group: z.string(),
  ip_prefix: z.string(),
  ip_hash: z.string(),
  asn: z.number(),
  score: z.number(),
  class: z.string(),
  reasons: z.array(z.string()),
  action: z.string(),
  would_action: z.string(),
  status: z.number(),
  ja4: z.string(),
  user_agent: z.string(),
});
export type RequestRow = z.infer<typeof requestRowSchema>;

export const facetSchema = z.array(
  z.object({ value: z.string(), requests: z.number() }),
);

export const requestPageSchema = z.object({
  rows: z.array(requestRowSchema),
  // Matching requests in the range (all pages).
  total: z.number(),
  facets: z.object({
    action: facetSchema,
    class: facetSchema,
    host: facetSchema,
  }),
  asns: z.array(asnInfoSchema),
});
export type RequestPage = z.infer<typeof requestPageSchema>;

export const requestDetailSchema = z.object({
  row: requestRowSchema.extend({
    http_version: z.string(),
    sni: z.string(),
    header_fp: z.string(),
    header_names: z.array(z.string()),
    pseudo_order: z.string(),
    h2_fp: z.string(),
    tcp_fp: z.string(),
    ja4h: z.string(),
    accept_language: z.string(),
    sec_ch_ua: z.string(),
    sec_ch_ua_platform: z.string(),
    sec_ch_ua_mobile: z.string(),
    sec_fetch_mode: z.string(),
    sec_fetch_site: z.string(),
    rate_limit: z.string(),
    duration_ms: z.number(),
    local: z.boolean(),
    signed_agent: z.string(),
    client_fp: z.string(),
    model_score: z.number().nullable(),
    // Kernel TCP round trip and TLS 1.3 handshake, microseconds.
    tcp_rtt_us: z.number().nullable(),
    handshake_us: z.number().nullable(),
  }),
  asn: asnInfoSchema.nullable(),
  mode: hostModeInfoSchema.nullable(),
  // The gateway's decision record while it is still in its ring buffer.
  decision_available: z.boolean(),
});
export type RequestDetail = z.infer<typeof requestDetailSchema>;

// --- Fingerprints ------------------------------------------------------------

export const FINGERPRINT_KINDS = [
  'ja4',
  'h2_fp',
  'header_fp',
  'tcp_fp',
] as const;
export const fingerprintKindSchema = z.enum(FINGERPRINT_KINDS);
export type FingerprintKind = z.infer<typeof fingerprintKindSchema>;

export const fingerprintQuerySchema = z.object({
  kind: fingerprintKindSchema.default('ja4'),
  q: z.string().max(200).optional(),
});

export const fingerprintRowSchema = z.object({
  value: z.string(),
  requests: z.number(),
  clients: z.number(),
  // Requests per hour over the last 24 hours, oldest first.
  hourly: z.array(z.number()),
  allowed: z.number(),
  challenged: z.number(),
  blocked: z.number(),
  median_score: z.number(),
  first_seen: z.number(),
  last_seen: z.number(),
  ua_sample: z.string(),
  // Automation signature from the library that matches it, if any.
  known_as: z.string().nullable(),
});
export type FingerprintRow = z.infer<typeof fingerprintRowSchema>;

export const fingerprintsSchema = z.object({
  kind: fingerprintKindSchema,
  rows: z.array(fingerprintRowSchema),
  kinds: z.array(
    z.object({ kind: fingerprintKindSchema, distinct: z.number() }),
  ),
});
export type Fingerprints = z.infer<typeof fingerprintsSchema>;

// --- Rules -------------------------------------------------------------------

export const rulesSchema = z.object({
  generation: z.number(),
  rules: z.array(
    z.object({
      name: z.string(),
      when: z.string(),
      action: z.union([actionSchema, z.literal('score')]),
      score: z.number().optional(),
      // Requests with "rule:<name>" in their reasons, last hour.
      hits_1h: z.number(),
    }),
  ),
});
export type Rules = z.infer<typeof rulesSchema>;

export const ruleTestRequestSchema = z.object({
  when: z.string().min(1).max(4000),
  action: z.union([actionSchema, z.literal('score')]),
});
export type RuleTestRequest = z.infer<typeof ruleTestRequestSchema>;

export const ruleCheckSchema = z.object({
  references: z.array(z.string()),
});
export type RuleCheck = z.infer<typeof ruleCheckSchema>;

export const ruleSampleSchema = z.object({
  ts: z.number(),
  host: z.string(),
  path_group: z.string(),
  score: z.number(),
  class: z.string(),
  asn: z.number(),
  ip_prefix: z.string(),
  action: z.string(),
  after: z.string(),
});

export const ruleTestResultSchema = z.object({
  // Requests in the last hour and how many were sampled and evaluated.
  total: z.number(),
  sampled: z.number(),
  matched: z.number(),
  // Matches scaled from the sample to the whole hour.
  estimated: z.number(),
  // Matches whose action would change.
  action_changes: z.number(),
  shadow_hosts: z.number(),
  verified_bots: z.number(),
  by_host: z.array(z.object({ host: z.string(), matched: z.number() })),
  // Fields the expression reads that events lack or only approximate
  // (header(), has_header(), alpn, cidr() on /24 or /48 prefixes, path as
  // a normalized path group).
  approximate: z.array(z.string()),
  references: z.array(z.string()),
  samples: z.array(ruleSampleSchema),
});
export type RuleTestResult = z.infer<typeof ruleTestResultSchema>;

export const reloadResultSchema = z.object({
  reloaded: z.literal(true),
  summary: z.string(),
});
export type ReloadResult = z.infer<typeof reloadResultSchema>;

// --- Lists -------------------------------------------------------------------

export const listEntrySchema = z.object({
  id: z.number(),
  kind: listKindSchema,
  value: z.string(),
  action: z.enum(['allow', 'block']),
  host: z.string(),
  created_at: z.number(),
  expires_at: z.number(),
  comment: z.string(),
});
export type ListEntry = z.infer<typeof listEntrySchema>;

export const listsSchema = z.object({
  entries: z.array(
    listEntrySchema.extend({
      // Requests with "list:<id>" in their reasons, last 24 hours.
      hits_24h: z.number().nullable(),
      added_by: z.string().nullable(),
    }),
  ),
});
export type Lists = z.infer<typeof listsSchema>;

export const newListEntrySchema = z.object({
  kind: listKindSchema,
  value: z.string().min(1).max(200),
  action: z.enum(['allow', 'block']),
  host: z.union([hostSchema, z.literal('')]).optional(),
  ttl: z
    .string()
    .regex(/^\d+(ms|s|m|h)$/)
    .optional(),
  comment: z.string().max(200).optional(),
});
export type NewListEntry = z.infer<typeof newListEntrySchema>;

// --- Rate limits -------------------------------------------------------------

export const limitsSchema = z.object({
  limits: z.array(
    limitSchema.extend({
      // Requests refused by this limit, last hour (rate_limit column).
      refused_1h: z.number(),
    }),
  ),
  throttle: limitSchema.nullable(),
  // Busiest clients of the last 60 s, by ip_prefix (events have no full
  // address), with the host they hit most.
  consumers: z.array(
    z.object({
      ip_prefix: z.string(),
      ip_hash_count: z.number(),
      host: z.string(),
      rps: z.number(),
      refused: z.number(),
    }),
  ),
});
export type Limits = z.infer<typeof limitsSchema>;

// --- Hosts -------------------------------------------------------------------

export const hostRowSchema = z.object({
  host: z.string(),
  mode: hostModeSchema,
  source: modeSourceSchema,
  route: z.string(),
  certificate: z.boolean(),
  rate_limits: z.array(z.string()),
  // Last hour.
  requests: z.number(),
  rps: z.number(),
  blocked: z.number(),
  would_block: z.number(),
  challenged: z.number(),
});
export type HostRow = z.infer<typeof hostRowSchema>;

export const hostsSchema = z.object({
  default_mode: z.enum(['shadow', 'enforce']),
  hosts: z.array(hostRowSchema),
});
export type Hosts = z.infer<typeof hostsSchema>;

// Enforce readiness of one host: what enforce mode would do (on a shadow
// host) or does (on an enforce host) to its traffic, and which clients it
// blocks that look legitimate: they passed a challenge elsewhere in the
// window, are verified crawlers, or the blocked request was classed human.
export const READINESS_RANGES = ['1h', '24h', '7d'] as const;
export type ReadinessRange = (typeof READINESS_RANGES)[number];

export const readinessQuerySchema = z.object({
  host: z.string().min(1).max(253),
  range: z.enum(READINESS_RANGES).default('24h'),
});

export const READINESS_EVIDENCE = [
  'passed_challenge',
  'verified_crawler',
  'classed_human',
] as const;
export type ReadinessEvidence = (typeof READINESS_EVIDENCE)[number];

export const readinessSchema = z.object({
  host: z.string(),
  mode: hostModeSchema,
  range: z.enum(READINESS_RANGES),
  requests: z.number(),
  clients: z.number(),
  block: z.object({
    requests: z.number(),
    clients: z.number(),
    legit_requests: z.number(),
    legit_clients: z.number(),
  }),
  challenge: z.object({ requests: z.number(), clients: z.number() }),
  // Signals of the blocked requests.
  reasons: z.array(
    z.object({
      reason: z.string(),
      requests: z.number(),
      clients: z.number(),
      legit_clients: z.number(),
    }),
  ),
  // Blocked clients that look legitimate, most requests first.
  suspects: z.array(
    z.object({
      ip_prefix: z.string(),
      ip_hash: z.string(),
      asn: z.number(),
      as_name: z.string().nullable(),
      user_agent: z.string(),
      requests: z.number(),
      reasons: z.array(z.string()),
      evidence: z.array(z.enum(READINESS_EVIDENCE)),
      last_seen: z.number(),
    }),
  ),
});
export type Readiness = z.infer<typeof readinessSchema>;

export const setModeSchema = z.object({
  host: hostSchema,
  mode: hostModeSchema,
});
export type SetMode = z.infer<typeof setModeSchema>;

// --- Crawlers ----------------------------------------------------------------

export const crawlersSchema = z.object({
  verify: z.boolean(),
  ip_ranges: z.boolean(),
  ai_action: actionSchema.nullable(),
  web_bot_auth: z.object({
    enabled: z.boolean(),
    trusted: z.array(z.string()),
  }),
  crawlers: z.array(
    z.object({
      id: z.string(),
      ai: z.boolean(),
      domains: z.array(z.string()),
      ranges: z.array(z.string()),
      // Last 24 hours, from reasons.
      verified: z.number(),
      fake: z.number(),
    }),
  ),
  signed_agents: z.array(z.object({ agent: z.string(), requests: z.number() })),
  impostors: z.array(
    z.object({
      crawler: z.string(),
      ip_prefix: z.string(),
      asn: z.number(),
      requests: z.number(),
      action: z.string(),
      last_seen: z.number(),
    }),
  ),
});
export type Crawlers = z.infer<typeof crawlersSchema>;

// --- Attack mode -------------------------------------------------------------

export const attackEntrySchema = z.object({
  host: z.string(),
  source: z.string(),
  since: z.number(),
  until: z.number().optional(),
  // Only clients with this signature (automatic, from the attack itself);
  // absent: every client of the host.
  signature: z
    .object({ kind: z.enum(['ip_prefix', 'asn', 'ja4']), value: z.string() })
    .optional(),
});
export type AttackEntry = z.infer<typeof attackEntrySchema>;

export const attackSchema = z.object({
  entries: z.array(attackEntrySchema),
  // Per host, requests per second; 0: only manual.
  auto_rps: z.number(),
  auto_duration_ms: z.number(),
  rps: z.number().nullable(),
  // Requests per second of the busiest host over the last minute.
  busiest: z.object({ host: z.string(), rps: z.number() }).nullable(),
  auto_activations: z.number().nullable(),
  // Of the last 5 minutes: shares that attack mode would not challenge.
  impact: z
    .object({
      requests: z.number(),
      token: z.number(),
      verified_or_listed: z.number(),
      rest: z.number(),
    })
    .nullable(),
});
export type Attack = z.infer<typeof attackSchema>;

export const enableAttackSchema = z.object({
  host: z.union([hostSchema, z.literal('*')]),
  ttl: z
    .string()
    .regex(/^\d+(s|m|h)$/)
    .optional(),
});
export type EnableAttack = z.infer<typeof enableAttackSchema>;

// --- Audit (the design's "Decision log") ------------------------------------

export const AUDIT_KINDS = [
  'list',
  'attack',
  'mode',
  'reload',
  'settings',
  'auth',
] as const;
export const auditKindSchema = z.enum(AUDIT_KINDS);
export type AuditKind = z.infer<typeof auditKindSchema>;

export const auditEntrySchema = z.object({
  id: z.string(),
  ts: z.number(),
  kind: auditKindSchema,
  actor: z.string(),
  what: z.string(),
  // State before and after (JSON), when the action has one.
  before: z.unknown().optional(),
  after: z.unknown().optional(),
  facts: z.array(z.tuple([z.string(), z.string()])),
  // Another entry this one reverted.
  reverts: z.string().optional(),
  revertible: z.boolean(),
});
export type AuditEntry = z.infer<typeof auditEntrySchema>;

export const auditSchema = z.object({
  entries: z.array(auditEntrySchema),
  // The hash chain of the log file checks out.
  intact: z.boolean(),
});
export type Audit = z.infer<typeof auditSchema>;

// --- Command palette ---------------------------------------------------------

export const searchResultSchema = z.object({
  kind: z.enum(['host', 'rule', 'ip', 'ja4', 'asn', 'request']),
  value: z.string(),
  meta: z.string(),
});
export type SearchResult = z.infer<typeof searchResultSchema>;

export const searchSchema = z.object({ results: z.array(searchResultSchema) });
