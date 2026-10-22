// Client of the gateway's admin API (HTTP/1.1 over its unix socket). Only
// the calls below exist: the console never forwards arbitrary paths, and
// every response is checked against a schema. Full client addresses from
// /decisions are dropped here, before anything else sees them.

import { request } from 'node:http';

import { z } from 'zod';

import {
  type AsnInfo,
  attackEntrySchema,
  type GatewayConfig,
  gatewayConfigSchema,
  type ListEntry,
  listEntrySchema,
  type NewListEntry,
} from '../../shared/api.ts';
import type { HostMode } from '../../shared/domain.ts';

const TIMEOUT_MS = 10_000;
const MAX_RESPONSE = 16 * 1024 * 1024;

export class AdminError extends Error {
  readonly status: number;
  // Column of a rule compile error (422 from /rules/test).
  readonly column: number | undefined;

  constructor(status: number, message: string, column?: number) {
    super(message);
    this.name = 'AdminError';
    this.status = status;
    this.column = column;
  }
}

export const adminStatusSchema = z.object({
  version: z.string(),
  uptime_s: z.number(),
  mode: z.enum(['shadow', 'enforce']),
  verdicts_generation: z.number(),
  workers: z.number(),
  certificates: z.number(),
  label_hosts: z.number(),
  connections_active: z.number(),
  rate_limit_keys: z.number(),
  list_entries: z.number(),
  attack_entries: z.number(),
  nats_connected: z.boolean(),
  events_published: z.number(),
  events_dropped: z.number(),
});
export type AdminStatus = z.infer<typeof adminStatusSchema>;

export const hostPolicySchema = z.object({
  host: z.string(),
  mode: z.enum(['shadow', 'enforce', 'off']),
  mode_source: z.enum(['console', 'policy.hosts', 'labels', 'mode']),
  route: z.string(),
  certificate: z.boolean(),
  rate_limits: z.array(z.string()),
});
export type HostPolicy = z.infer<typeof hostPolicySchema>;

const modeEntrySchema = z.object({
  host: z.string(),
  mode: z.enum(['shadow', 'enforce', 'off']),
});

export const policyOverviewSchema = z.object({
  default: z.enum(['shadow', 'enforce']),
  console: z.array(modeEntrySchema),
  policy_hosts: z.array(modeEntrySchema),
  labels: z.array(
    z.object({
      host: z.string(),
      container: z.string(),
      passthrough: z.boolean(),
      mode: z.enum(['shadow', 'enforce', 'off']).optional(),
    }),
  ),
  passthrough_hosts: z.array(z.string()),
});
export type PolicyOverview = z.infer<typeof policyOverviewSchema>;

// A decision without the full address ("ip" is never kept).
export const decisionSchema = z.object({
  request_id: z.string(),
  time_ms: z.number(),
  host: z.string(),
  method: z.string(),
  path_group: z.string(),
  ip_prefix: z.string().optional(),
  ip_hash: z.string().optional(),
  user_agent: z.string(),
  ja4: z.string(),
  h2_fp: z.string(),
  header_fp: z.string(),
  mode: z.string(),
  score: z.number(),
  class: z.string(),
  reasons: z.array(z.string()),
  action: z.string(),
  would_action: z.string(),
  rate_limit: z.string().optional(),
  status: z.number(),
  local: z.boolean(),
  duration_ms: z.number(),
});
export type Decision = z.infer<typeof decisionSchema>;

export const attackStateSchema = z.object({
  entries: z.array(attackEntrySchema),
  auto_rps: z.number(),
});

export const rulesTestSchema = z.object({
  references: z.array(z.string()),
  evaluated: z.number(),
  matched: z.array(z.number()),
});
export type RulesTestResponse = z.infer<typeof rulesTestSchema>;

const asnResponseSchema = z.object({
  loaded: z.boolean(),
  asns: z.array(
    z.object({
      asn: z.number(),
      org: z.string(),
      country: z.string(),
      hosting: z.boolean(),
    }),
  ),
});

const reloadSchema = z.object({
  reloaded: z.literal(true),
  summary: z.string(),
});

// Fields of a req event that a rule test sends to the gateway.
export interface RuleSampleEvent {
  host: string;
  method: string;
  path: string;
  http_version: string;
  sni: string;
  ja4: string;
  h2_fp: string;
  pseudo_order: string;
  header_fp: string;
  tcp_fp: string;
  user_agent: string;
  score: number;
  class: string;
  reasons: string[];
  asn: number;
  signed_agent: string;
  ip_prefix: string;
}

export interface AdminApi {
  status(): Promise<AdminStatus>;
  config(): Promise<GatewayConfig>;
  policy(host: string): Promise<HostPolicy>;
  policyOverview(): Promise<PolicyOverview>;
  setMode(host: string, mode: HostMode): Promise<void>;
  clearMode(host: string): Promise<boolean>;
  lists(): Promise<ListEntry[]>;
  addList(entry: NewListEntry): Promise<ListEntry>;
  removeList(id: number): Promise<boolean>;
  decision(requestId: string): Promise<Decision | null>;
  attack(): Promise<z.infer<typeof attackStateSchema>>;
  enableAttack(host: string, ttl?: string): Promise<void>;
  disableAttack(host: string): Promise<boolean>;
  testRule(
    when: string,
    samples: RuleSampleEvent[],
  ): Promise<RulesTestResponse>;
  asns(numbers: number[]): Promise<AsnInfo[]>;
  reload(): Promise<string>;
}

interface RawResponse {
  status: number;
  body: unknown;
}

// One request over the socket; the gateway closes the connection after it.
function call(
  socketPath: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<RawResponse> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath,
        method,
        path,
        headers: {
          host: 'bot-shield',
          ...(payload === undefined
            ? {}
            : {
                'content-type': 'application/json',
                'content-length': Buffer.byteLength(payload),
              }),
        },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE) {
            req.destroy(new Error('admin API response too large'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: unknown;
          try {
            parsed = JSON.parse(text);
          } catch {
            reject(new AdminError(502, 'admin API sent invalid JSON'));
            return;
          }
          resolve({ status: res.statusCode ?? 0, body: parsed });
        });
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error('admin API timed out')));
    req.on('error', (error) => {
      reject(new AdminError(503, `admin API unavailable: ${error.message}`));
    });
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const gatewayErrorSchema = z.object({
  error: z.string(),
  column: z.number().optional(),
});

// The gateway leaves out an empty host and comment (ListStore::ToJson).
const gatewayListEntry = listEntrySchema.extend({
  host: z.string().default(''),
  comment: z.string().default(''),
});

export function createAdminClient(socketPath: string): AdminApi {
  async function json<T>(
    schema: z.ZodType<T>,
    method: string,
    path: string,
    body?: unknown,
    allow404 = false,
  ): Promise<T | null> {
    const response = await call(socketPath, method, path, body);
    if (response.status === 404 && allow404) return null;
    if (response.status < 200 || response.status >= 300) {
      const error = gatewayErrorSchema.safeParse(response.body);
      throw new AdminError(
        response.status,
        error.success
          ? error.data.error
          : `admin API status ${response.status}`,
        error.success ? error.data.column : undefined,
      );
    }
    const parsed = schema.safeParse(response.body);
    if (!parsed.success) {
      throw new AdminError(
        502,
        `admin API ${method} ${path}: unexpected response (${parsed.error.issues[0]?.message ?? 'invalid'})`,
      );
    }
    return parsed.data;
  }
  const must = async <T>(
    schema: z.ZodType<T>,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> => {
    const value = await json(schema, method, path, body);
    if (value === null) throw new AdminError(502, 'admin API: empty response');
    return value;
  };
  const ok = z.unknown();

  return {
    status: () => must(adminStatusSchema, 'GET', '/status'),
    config: () => must(gatewayConfigSchema, 'GET', '/config'),
    policy: (host) =>
      must(hostPolicySchema, 'GET', `/policy?host=${encodeURIComponent(host)}`),
    policyOverview: () => must(policyOverviewSchema, 'GET', '/policy'),
    setMode: async (host, mode) => {
      await must(ok, 'POST', '/policy', { host, mode });
    },
    clearMode: async (host) =>
      (await json(
        ok,
        'DELETE',
        `/policy/${encodeURIComponent(host)}`,
        undefined,
        true,
      )) !== null,
    lists: async () =>
      (
        await must(
          z.object({ entries: z.array(gatewayListEntry) }),
          'GET',
          '/lists',
        )
      ).entries,
    addList: (entry) => must(gatewayListEntry, 'POST', '/lists', entry),
    removeList: async (id) =>
      (await json(ok, 'DELETE', `/lists/${id}`, undefined, true)) !== null,
    decision: (requestId) =>
      json(
        decisionSchema,
        'GET',
        `/decisions/${encodeURIComponent(requestId)}`,
        undefined,
        true,
      ),
    attack: () => must(attackStateSchema, 'GET', '/attack'),
    enableAttack: async (host, ttl) => {
      await must(
        ok,
        'POST',
        '/attack',
        ttl === undefined ? { host } : { host, ttl },
      );
    },
    disableAttack: async (host) =>
      (await json(
        ok,
        'DELETE',
        `/attack/${encodeURIComponent(host)}`,
        undefined,
        true,
      )) !== null,
    testRule: (when, samples) =>
      must(rulesTestSchema, 'POST', '/rules/test', { when, samples }),
    asns: async (numbers) => {
      if (numbers.length === 0) return [];
      const response = await must(
        asnResponseSchema,
        'GET',
        `/asn?numbers=${numbers.join(',')}`,
      );
      return response.asns;
    },
    reload: async () => (await must(reloadSchema, 'POST', '/reload')).summary,
  };
}
