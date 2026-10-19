// GET /api/search?q=: the command palette. What `q` is follows from its
// shape: an address or prefix, an IP hash, a JA4, an AS number, a host or
// a rule name.

import { isIP } from 'node:net';

import type { Hono } from 'hono';
import { z } from 'zod';

import { searchSchema, type SearchResult } from '../../shared/api.ts';
import type { AppEnv } from '../deps.ts';
import { addressPrefix, parseOr400, send } from '../http.ts';

const JA4_PATTERN = /^[tqd]\d{2}[di]\d{2}/;

export function registerSearch(app: Hono<AppEnv>): void {
  app.get('/api/search', async (c) => {
    const deps = c.get('deps');
    const { q } = parseOr400(
      z.object({ q: z.string().trim().min(1).max(200) }),
      c.req.query(),
    );
    const results: SearchResult[] = [];
    const data = deps.analytics;
    const safe = <T>(promise: Promise<T[]>) => promise.catch(() => [] as T[]);
    const asn = /^(?:as)?(\d{1,10})$/i.exec(q);

    if (isIP(q.replace(/\/\d+$/, '')) !== 0) {
      // A full address becomes its network: events only have prefixes.
      const prefix = q.includes('/') ? q : addressPrefix(q);
      results.push({
        kind: 'ip',
        value: prefix,
        meta: 'requests from this network',
      });
    } else if (/^[0-9a-f]{4,32}$/.test(q) && data) {
      for (const row of await safe(data.search('ip_hash', q))) {
        results.push({
          kind: 'ip',
          value: `h:${row.value}`,
          meta: `${row.requests} req · 24h`,
        });
      }
    }
    if (JA4_PATTERN.test(q) && data) {
      for (const row of await safe(data.search('ja4', q))) {
        results.push({
          kind: 'ja4',
          value: row.value,
          meta: `${row.requests} req · 24h`,
        });
      }
    }
    if (asn?.[1]) {
      const number = Number(asn[1]);
      const info = (await deps.admin.asns([number]).catch(() => []))[0];
      results.push({
        kind: 'asn',
        value: `AS${number}`,
        meta: info
          ? `${info.org}${info.country ? ` · ${info.country}` : ''}`
          : 'AS number',
      });
    }
    if (data && /^[a-z0-9.*-]+$/i.test(q)) {
      for (const row of await safe(data.search('host', q))) {
        results.push({
          kind: 'host',
          value: row.value,
          meta: `${row.requests} req · 24h`,
        });
      }
    }
    const config = await deps.admin.config().catch(() => null);
    for (const rule of config?.rules ?? []) {
      if (rule.name.toLowerCase().includes(q.toLowerCase())) {
        results.push({ kind: 'rule', value: rule.name, meta: rule.action });
      }
    }
    if (/^[\w.-]+-\d+-\d+$/.test(q)) {
      results.push({ kind: 'request', value: q, meta: 'request id' });
    }
    return send(c, searchSchema, { results: results.slice(0, 12) });
  });
}
