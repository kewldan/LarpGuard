// Gateway settings (ADR-018): GET /api/settings and /api/settings/history
// for every role; POST /api/settings/validate (dry run), POST /api/settings
// and POST /api/settings/rollback for operators, audited with a diff of the
// values that are not secret. Secrets only travel in POST bodies, to the
// gateway, and come back as "set" or "not set".

import type { Hono } from 'hono';
import { z } from 'zod';

import {
  type SettingChange,
  settingSourceSchema,
  settingsChangeSchema,
  settingsDiffSchema,
  settingsHistorySchema,
  settingsRollbackSchema,
  settingsSchema,
  settingValueSchema,
} from '../../shared/api.ts';
import type { AppEnv, Deps } from '../deps.ts';
import { fail, jsonBody, parseOr400, send } from '../http.ts';
import { requireRole } from '../roles.ts';
import { actor } from './common.ts';

// One key's state in an audit entry: a value, or for a secret only whether
// it is set.
export const settingStateSchema = z.object({
  source: settingSourceSchema,
  value: settingValueSchema.optional(),
  set: z.boolean().optional(),
});
export const settingsStateSchema = z.record(z.string(), settingStateSchema);
export type SettingsState = z.infer<typeof settingsStateSchema>;

export function auditStates(changes: SettingChange[]): {
  before: SettingsState;
  after: SettingsState;
} {
  const before: SettingsState = {};
  const after: SettingsState = {};
  for (const change of changes) {
    if (change.secret) {
      before[change.path] = {
        source: change.source_before,
        set: change.set_before,
      };
      after[change.path] = {
        source: change.source_after,
        set: change.set_after,
      };
    } else {
      before[change.path] = {
        source: change.source_before,
        value: change.before,
      };
      after[change.path] = { source: change.source_after, value: change.after };
    }
  }
  return { before, after };
}

function short(value: unknown): string {
  const text = JSON.stringify(value) ?? '';
  return text.length > 40 ? `${text.slice(0, 39)}…` : text;
}

// "captcha.rounds 2 → 3" for one key, else the count and the keys.
export function describeChanges(changes: SettingChange[]): string {
  const [only] = changes;
  if (changes.length === 1 && only) {
    if (only.secret) {
      return `${only.path} ${
        only.source_after !== 'console'
          ? `back to the ${only.source_after} value`
          : only.set_after
            ? 'replaced'
            : 'cleared'
      }`;
    }
    return `${only.path} ${short(only.before)} → ${short(only.after)}`;
  }
  const paths = changes.map((change) => change.path);
  const listed = paths.slice(0, 4).join(', ');
  return `${changes.length} settings changed: ${listed}${paths.length > 4 ? ', …' : ''}`;
}

export function auditFacts(changes: SettingChange[]): [string, string][] {
  const facts: [string, string][] = [];
  const by = (apply: string) =>
    changes.filter((change) => change.apply === apply).map((c) => c.path);
  const live = by('live');
  const restart = changes
    .filter((change) => change.pending_restart)
    .map((change) => change.path);
  if (live.length) facts.push(['Applied now', live.join(', ')]);
  if (restart.length) facts.push(['Pending restart', restart.join(', ')]);
  for (const change of changes) {
    if (change.secret) {
      facts.push([
        change.path,
        change.source_after !== 'console'
          ? 'secret: main file again'
          : change.set_after
            ? 'secret replaced (not recorded)'
            : 'secret cleared',
      ]);
    }
  }
  return facts;
}

// Applies the inverse of an audited change, if every key is still as the
// change left it; secrets cannot be restored from the log.
export async function revertSettings(
  deps: Deps,
  before: SettingsState,
  after: SettingsState,
): Promise<{ what: string; after: unknown }> {
  const current = await deps.admin.settings();
  if (!current.editable) fail(409, 'settings are read-only');
  const set: Record<string, z.infer<typeof settingValueSchema>> = {};
  const reset: string[] = [];
  for (const [path, state] of Object.entries(before)) {
    const now = current.keys.find((key) => key.path === path);
    const left = after[path];
    if (!now || now.secret || !left) fail(409, `${path} cannot be reverted`);
    if (
      now.source !== left.source ||
      JSON.stringify(now.value) !== JSON.stringify(left.value)
    ) {
      fail(409, `${path} changed since`);
    }
    if (state.source === 'console') set[path] = state.value ?? null;
    else reset.push(path);
  }
  const diff = await deps.admin.applySettings({
    base_revision: current.revision,
    set,
    reset,
  });
  return {
    what: diff.changes.length
      ? describeChanges(diff.changes)
      : 'settings unchanged',
    after: auditStates(diff.changes).after,
  };
}

export function registerSettings(app: Hono<AppEnv>): void {
  app.get('/api/settings', async (c) =>
    send(c, settingsSchema, await c.get('deps').admin.settings()),
  );

  app.get('/api/settings/history', async (c) =>
    send(c, settingsHistorySchema, await c.get('deps').admin.settingsHistory()),
  );

  app.post('/api/settings/validate', requireRole('operator'), async (c) => {
    const change = parseOr400(settingsChangeSchema, await jsonBody(c));
    const diff = await c.get('deps').admin.validateSettings(change);
    return send(c, settingsDiffSchema, diff);
  });

  app.post('/api/settings', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const change = parseOr400(settingsChangeSchema, await jsonBody(c));
    const diff = await deps.admin.applySettings(change);
    if (diff.changes.length > 0) {
      deps.audit.append({
        kind: 'settings',
        actor: actor(c),
        what: describeChanges(diff.changes),
        ...auditStates(diff.changes),
        facts: auditFacts(diff.changes),
      });
    }
    return send(c, settingsDiffSchema, diff);
  });

  app.post('/api/settings/rollback', requireRole('operator'), async (c) => {
    const deps = c.get('deps');
    const { revision, base_revision } = parseOr400(
      settingsRollbackSchema,
      await jsonBody(c),
    );
    const diff = await deps.admin.rollbackSettings(revision, base_revision);
    deps.audit.append({
      kind: 'settings',
      actor: actor(c),
      what: `Settings rolled back to version ${revision.slice(0, 8)}`,
      ...auditStates(diff.changes),
      facts: [['Version', revision], ...auditFacts(diff.changes)],
    });
    return send(c, settingsDiffSchema, diff);
  });
}
