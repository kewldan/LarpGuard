// GET /api/audit: the console's change log. POST /api/audit/:id/revert
// undoes a change that has an inverse (lists, attack mode, host modes,
// settings without secrets).

import type { Hono } from 'hono';
import { z } from 'zod';

import {
  attackEntrySchema,
  auditSchema,
  hostModeSchema,
  listEntrySchema,
} from '../../shared/api.ts';
import type { StoredEntry } from '../audit.ts';
import type { AppEnv, Deps } from '../deps.ts';
import { fail, send } from '../http.ts';
import { requireRole } from '../roles.ts';
import { actor, formatTtl } from './common.ts';
import { applyMode } from './hosts.ts';
import { describeEntry, restoreEntry } from './lists.ts';
import { revertSettings, settingsStateSchema } from './settings.ts';

const modeStateSchema = z.object({
  host: z.string(),
  mode: hostModeSchema.nullable(),
});

type Revert = (deps: Deps) => Promise<{ what: string; after?: unknown }>;

// How to undo an entry, or null when it cannot be undone.
function planRevert(entry: StoredEntry): Revert | null {
  if (entry.kind === 'list') {
    const added = listEntrySchema.safeParse(entry.after);
    const removed = listEntrySchema.safeParse(entry.before);
    if (added.success && removed.success) {
      // A change in place: back to the old lifetime and comment.
      const old = removed.data;
      return async (deps) => {
        const now = Math.floor(deps.now() / 1000);
        if (old.expires_at !== 0 && old.expires_at <= now) {
          fail(409, 'the old lifetime would have ended by now');
        }
        const restored = await deps.admin.updateList(old.id, {
          ttl: old.expires_at === 0 ? null : `${old.expires_at - now}s`,
          comment: old.comment,
        });
        if (!restored) fail(409, 'the entry is gone already');
        return {
          what: `Changed #${old.id} back: ${describeEntry(restored, deps.now())}`,
          after: restored,
        };
      };
    }
    if (added.success) {
      return async (deps) => {
        if (!(await deps.admin.removeList(added.data.id))) {
          fail(409, 'the entry is gone already');
        }
        return { what: `Removed: ${describeEntry(added.data, deps.now())}` };
      };
    }
    if (removed.success) {
      return async (deps) => {
        const restored = await restoreEntry(deps, removed.data);
        if (!restored) fail(409, 'the entry would have expired by now');
        return { what: describeEntry(restored, deps.now()), after: restored };
      };
    }
    return null;
  }
  if (entry.kind === 'attack') {
    const before = attackEntrySchema.safeParse(entry.before);
    const after = attackEntrySchema.safeParse(entry.after);
    if (!before.success && after.success) {
      return async (deps) => {
        if (!(await deps.admin.disableAttack(after.data.host))) {
          fail(409, 'attack mode is off already');
        }
        return { what: `Attack mode off for ${after.data.host}` };
      };
    }
    if (before.success) {
      return async (deps) => {
        const now = Math.floor(deps.now() / 1000);
        const until = before.data.until;
        if (until !== undefined && until <= now) {
          fail(409, 'the previous attack mode would have ended by now');
        }
        const ttl = until === undefined ? undefined : formatTtl(until - now);
        await deps.admin.enableAttack(before.data.host, ttl);
        return {
          what: `Attack mode back on for ${before.data.host}${ttl ? ` (${ttl})` : ''}`,
        };
      };
    }
    return null;
  }
  if (entry.kind === 'mode') {
    const before = modeStateSchema.safeParse(entry.before);
    if (!before.success) return null;
    return async (deps) => {
      await applyMode(deps, before.data.host, before.data.mode);
      return {
        what:
          before.data.mode === null
            ? `${before.data.host}: console override removed`
            : `${before.data.host}: console mode back to ${before.data.mode}`,
        after: before.data,
      };
    };
  }
  if (entry.kind === 'settings') {
    const before = settingsStateSchema.safeParse(entry.before);
    const after = settingsStateSchema.safeParse(entry.after);
    if (!before.success || !after.success) return null;
    // Secret values are never logged, so they cannot be put back.
    const states = [
      ...Object.values(before.data),
      ...Object.values(after.data),
    ];
    if (states.length === 0 || states.some((state) => state.set !== undefined))
      return null;
    return (deps) => revertSettings(deps, before.data, after.data);
  }
  return null;
}

export function registerAudit(app: Hono<AppEnv>): void {
  app.get('/api/audit', (c) => {
    const deps = c.get('deps');
    return send(c, auditSchema, {
      entries: deps.audit.list((entry) => planRevert(entry) !== null),
      intact: deps.audit.intact,
    });
  });

  app.post('/api/audit/:id/revert', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const entry = deps.audit.find(c.req.param('id'));
    if (!entry) return fail(404, 'no such entry');
    if (deps.audit.isReverted(entry.id)) fail(409, 'reverted already');
    const revert = planRevert(entry);
    if (!revert) return fail(409, 'this change cannot be reverted');
    const done = await revert(deps);
    deps.audit.append({
      kind: entry.kind,
      actor: actor(c),
      what: `Reverted: ${done.what}`,
      ...(done.after === undefined ? {} : { after: done.after }),
      facts: [['Reverts', entry.what]],
      reverts: entry.id,
    });
    return c.body(null, 204);
  });
}
