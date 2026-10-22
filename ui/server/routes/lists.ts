// GET /api/lists, POST /api/lists, DELETE /api/lists/:id: the gateway's
// operational allow/block lists.

import type { Hono } from 'hono';

import {
  type ListEntry,
  listEntrySchema,
  listsSchema,
  newListEntrySchema,
} from '../../shared/api.ts';
import type { AppEnv, Deps } from '../deps.ts';
import { fail, jsonBody, parseOr400, send } from '../http.ts';
import { requireRole } from '../roles.ts';
import { actor, formatTtl } from './common.ts';

export function describeEntry(entry: ListEntry, now: number): string {
  const verb = entry.action === 'allow' ? 'Allowed' : 'Blocked';
  const scope = entry.host ? ` on ${entry.host}` : '';
  const ttl =
    entry.expires_at === 0
      ? ''
      : ` for ${formatTtl(Math.max(1, entry.expires_at - Math.floor(now / 1000)))}`;
  return `${verb} ${entry.kind} ${entry.value}${scope}${ttl}`;
}

// Re-adds a removed entry with what is left of its lifetime; null when it
// has expired since.
export async function restoreEntry(
  deps: Deps,
  entry: ListEntry,
): Promise<ListEntry | null> {
  const nowSeconds = Math.floor(deps.now() / 1000);
  if (entry.expires_at !== 0 && entry.expires_at <= nowSeconds) return null;
  return deps.admin.addList({
    kind: entry.kind,
    value: entry.value,
    action: entry.action,
    host: entry.host,
    comment: entry.comment,
    ...(entry.expires_at === 0
      ? {}
      : { ttl: `${entry.expires_at - nowSeconds}s` }),
  });
}

export function registerLists(app: Hono<AppEnv>): void {
  app.get('/api/lists', async (c) => {
    const deps = c.get('deps');
    const [entries, hits] = await Promise.all([
      deps.admin.lists(),
      deps.analytics
        ? deps.analytics.reasonCounts('list:', 86_400).catch(() => null)
        : Promise.resolve(null),
    ]);
    // Who added each entry, from the audit log.
    const addedBy = new Map<number, string>();
    for (const item of deps.audit.list(() => false).reverse()) {
      const after = listEntrySchema.safeParse(item.after);
      if (item.kind === 'list' && after.success) {
        addedBy.set(after.data.id, item.actor);
      }
    }
    return send(c, listsSchema, {
      entries: entries
        .slice()
        .sort((a, b) => b.created_at - a.created_at)
        .map((entry) => ({
          ...entry,
          hits_24h: hits ? (hits.get(String(entry.id)) ?? 0) : null,
          added_by: addedBy.get(entry.id) ?? null,
        })),
    });
  });

  app.post('/api/lists', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const entry = parseOr400(newListEntrySchema, await jsonBody(c));
    const stored = await deps.admin.addList(entry);
    deps.audit.append({
      kind: 'list',
      actor: actor(c),
      what: describeEntry(stored, deps.now()),
      after: stored,
      facts: [
        ['Entry', `#${stored.id}`],
        ...(stored.comment
          ? ([['Comment', stored.comment]] as [string, string][])
          : []),
      ],
    });
    return send(c, listEntrySchema, stored, 201);
  });

  app.delete('/api/lists/:id', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const id = Number(c.req.param('id'));
    if (!Number.isSafeInteger(id) || id <= 0) fail(400, 'invalid id');
    const entry = (await deps.admin.lists()).find((item) => item.id === id);
    if (!entry || !(await deps.admin.removeList(id))) {
      return fail(404, 'no such entry');
    }
    deps.audit.append({
      kind: 'list',
      actor: actor(c),
      what: `Removed: ${describeEntry(entry, deps.now())}`,
      before: entry,
      facts: [['Entry', `#${entry.id}`]],
    });
    return c.body(null, 204);
  });
}
