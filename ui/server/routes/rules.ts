// GET /api/rules: rules in effect with their hits.
// POST /api/rules/test: a draft rule on a sample of the last hour.
// POST /api/reload: the gateway re-reads its configuration file.

import type { Hono } from 'hono';

import {
  type ReloadChange,
  type RuleTestResult,
  reloadResultSchema,
  ruleCheckSchema,
  rulesSchema,
  ruleTestRequestSchema,
  ruleTestResultSchema,
} from '../../shared/api.ts';
import type { SampleEvent } from '../analytics/analytics.ts';
import type { AppEnv } from '../deps.ts';
import type { RuleSampleEvent } from '../gateway/admin.ts';
import { jsonBody, parseOr400, send } from '../http.ts';
import { requireRole } from '../roles.ts';
import { actor, analytics } from './common.ts';

const SAMPLE_TARGET = 2000;
const SHOWN_SAMPLES = 12;
// What events lack or only approximate.
const APPROXIMATE = new Set([
  'header()',
  'has_header()',
  'cookie()',
  'has_cookie()',
  'query()',
  'has_query()',
  'country',
  'cidr()',
  'path',
]);

function toEvent(sample: SampleEvent): RuleSampleEvent {
  return {
    host: sample.host,
    method: sample.method,
    path: sample.path,
    http_version: sample.http_version,
    sni: sample.sni,
    ja4: sample.ja4,
    h2_fp: sample.h2_fp,
    pseudo_order: sample.pseudo_order,
    header_fp: sample.header_fp,
    tcp_fp: sample.tcp_fp,
    user_agent: sample.user_agent,
    score: sample.score,
    class: sample.class,
    reasons: sample.reasons,
    asn: sample.asn,
    signed_agent: sample.signed_agent,
    ip_prefix: sample.ip_prefix,
    tcp_rtt_us: sample.tcp_rtt_us,
    handshake_us: sample.handshake_us,
    alpn: sample.alpn,
  };
}

// What enforce mode does with a request now: the would-be action.
function current(sample: SampleEvent): string {
  return sample.would_action || sample.action || 'allow';
}

// Before and after of what a reload changed, for the decision log's diff;
// a secret shows only whether it is set.
function reloadStates(changes: ReloadChange[]): {
  before: Record<string, unknown>;
  after: Record<string, unknown>;
} {
  const before: Record<string, unknown> = {};
  const after: Record<string, unknown> = {};
  for (const change of changes) {
    before[change.path] = change.secret
      ? { set: change.set_before ?? false }
      : change.before;
    after[change.path] = change.secret
      ? { set: change.set_after ?? false }
      : change.after;
  }
  return { before, after };
}

export function registerRules(app: Hono<AppEnv>): void {
  app.get('/api/rules', async (c) => {
    const deps = c.get('deps');
    const [config, hits, settings] = await Promise.all([
      deps.admin.config(),
      deps.analytics
        ? deps.analytics.reasonCounts('rule:', 3600).catch(() => null)
        : Promise.resolve(null),
      deps.admin.settings().catch(() => null),
    ]);
    const key = settings?.keys.find((item) => item.path === 'rules');
    return send(c, rulesSchema, {
      generation: config.generation,
      rules: config.rules.map((rule) => ({
        ...rule,
        hits_1h: hits?.get(rule.name) ?? 0,
      })),
      source: key?.source ?? 'file',
      editable: settings?.editable ?? false,
      revision: settings?.revision ?? null,
    });
  });

  // Compile only: the gateway's parser and type checks, no traffic.
  app.post('/api/rules/check', async (c) => {
    const deps = c.get('deps');
    const draft = parseOr400(ruleTestRequestSchema, await jsonBody(c));
    const result = await deps.admin.testRule(draft.when, []);
    return send(c, ruleCheckSchema, { references: result.references });
  });

  app.post('/api/rules/test', async (c) => {
    const deps = c.get('deps');
    const draft = parseOr400(ruleTestRequestSchema, await jsonBody(c));
    // Compile first: errors come back fast, without touching ClickHouse.
    const check = await deps.admin.testRule(draft.when, []);
    const { total, samples } = await analytics(deps).ruleSamples(
      3600,
      SAMPLE_TARGET,
    );
    const result =
      samples.length === 0
        ? check
        : await deps.admin.testRule(draft.when, samples.map(toEvent));
    const matched = result.matched
      .map((index) => samples[index])
      .filter((sample): sample is SampleEvent => sample !== undefined);
    const hosts = [...new Set(matched.map((sample) => sample.host))].slice(
      0,
      50,
    );
    const modes = new Map(
      await Promise.all(
        hosts.map(
          async (host) =>
            [
              host,
              (await deps.admin.policy(host).catch(() => null))?.mode,
            ] as const,
        ),
      ),
    );
    const after = (sample: SampleEvent) =>
      draft.action === 'score' ? current(sample) : draft.action;
    const byHost = new Map<string, number>();
    for (const sample of matched) {
      byHost.set(sample.host, (byHost.get(sample.host) ?? 0) + 1);
    }
    const response: RuleTestResult = {
      total,
      sampled: samples.length,
      matched: matched.length,
      estimated:
        samples.length === 0
          ? 0
          : Math.round((matched.length / samples.length) * total),
      action_changes: matched.filter(
        (sample) => current(sample) !== after(sample),
      ).length,
      shadow_hosts: matched.filter(
        (sample) => modes.get(sample.host) === 'shadow',
      ).length,
      verified_bots: matched.filter((sample) => sample.class === 'verified_bot')
        .length,
      by_host: [...byHost]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([host, count]) => ({ host, matched: count })),
      approximate: result.references.filter((name) => APPROXIMATE.has(name)),
      references: result.references,
      samples: matched.slice(0, SHOWN_SAMPLES).map((sample) => ({
        ts: sample.ts,
        host: sample.host,
        path_group: sample.path,
        score: sample.score,
        class: sample.class,
        asn: sample.asn,
        ip_prefix: sample.ip_prefix,
        action: current(sample),
        after: after(sample),
      })),
    };
    return send(c, ruleTestResultSchema, response);
  });

  app.post('/api/reload', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    try {
      const result = await deps.admin.reload();
      const { before, after } = reloadStates(result.changes);
      const waiting = result.changes.filter((change) => change.pending_restart);
      deps.audit.append({
        kind: 'reload',
        actor: actor(c),
        what:
          result.changes.length === 0
            ? 'Configuration reloaded, nothing changed'
            : `Configuration reloaded: ${result.changes.map((change) => change.path).join(', ')}`,
        ...(result.changes.length > 0 ? { before, after } : {}),
        facts: [
          ['Summary', result.summary],
          ['Config', result.config_hash],
          ...(waiting.length > 0
            ? ([
                [
                  'Waits for a restart',
                  waiting.map((change) => change.path).join(', '),
                ],
              ] as [string, string][])
            : []),
        ],
      });
      return send(c, reloadResultSchema, result);
    } catch (error) {
      deps.audit.append({
        kind: 'reload',
        actor: actor(c),
        what: 'Configuration reload failed',
        facts: [
          ['Error', error instanceof Error ? error.message : String(error)],
        ],
      });
      throw error;
    }
  });
}
