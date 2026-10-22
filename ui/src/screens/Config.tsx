// Configuration: every gateway setting (ADR-018) with its value, default and
// source. Changes collect in a draft that the gateway checks as you type;
// "Review" shows the diff and applies it to the console's settings layer
// over bot-shield.yaml. Live keys apply at once, the rest after a restart;
// file paths, sockets and listen addresses stay in the YAML.

import { useNavigate, useSearch } from '@tanstack/react-router';
import { useEffect, useMemo, useRef, useState } from 'react';

import type {
  SettingChange,
  SettingKey,
  SettingsDiff,
  SettingValue,
} from '../../shared/api.ts';
import { SETTINGS_HELP } from '../../shared/settings-help.ts';
import { useCanOperate } from '../app/session.ts';
import { ApiError } from '../lib/api.ts';
import { dateTime } from '../lib/format.ts';
import { useCompact } from '../lib/media.ts';
import {
  useApplySettings,
  useRollbackSettings,
  useSettings,
  useSettingsHistory,
  useValidateSettings,
} from '../lib/queries.ts';
import {
  type Draft,
  type DraftEntry,
  findSection,
  fromText,
  isMultiline,
  OTHER,
  preview,
  SECTIONS,
  type Section,
  sectionOf,
  shortName,
  toChange,
  toText,
  without,
  withReset,
  withValue,
} from '../lib/settings.ts';
import { Button } from '../ui/Button.tsx';
import { PageHead } from '../ui/Card.tsx';
import controls from '../ui/controls.module.css';
import { Segmented, Select, Switch, TextInput } from '../ui/controls.tsx';
import { Dialog } from '../ui/Overlay.tsx';
import states from '../ui/states.module.css';
import {
  EmptyState,
  ErrorState,
  PermissionNote,
  Skeleton,
} from '../ui/states.tsx';
import { useToast } from '../ui/toast-context.ts';
import styles from './Config.module.css';
import screens from './screens.module.css';

const HISTORY: Section = {
  id: 'history',
  name: 'Versions',
  keys: [],
  help: [],
};

const SOURCE_LABEL = {
  default: 'default',
  file: 'bot-shield.yaml',
  console: 'console',
} as const;

// The checked state of the draft: the diff, or the key the gateway refused.
type Check =
  | { state: 'idle' }
  | { state: 'checking' }
  | { state: 'ok'; diff: SettingsDiff }
  | { state: 'error'; message: string; path: string | undefined };

export function Config() {
  const search = useSearch({ from: '/config' });
  const navigate = useNavigate({ from: '/config' });
  const settings = useSettings();
  const canOperate = useCanOperate();
  const compact = useCompact();
  const toast = useToast();
  const validate = useValidateSettings();
  const apply = useApplySettings();
  const [draft, setDraft] = useState<Draft>(new Map());
  const [check, setCheck] = useState<Check>({ state: 'idle' });
  const [reviewing, setReviewing] = useState(false);
  const revision = settings.data?.revision ?? '';
  const editable = canOperate && settings.data?.editable === true;

  // The gateway checks the draft a moment after the last keystroke.
  const run = useRef(0);
  const { mutate: dryRun } = validate;
  useEffect(() => {
    const id = run.current + 1;
    run.current = id;
    if (draft.size === 0 || !editable) {
      setCheck({ state: 'idle' });
      return;
    }
    const built = toChange(draft, revision);
    if ('error' in built) {
      setCheck({ state: 'error', message: built.error, path: built.path });
      return;
    }
    setCheck({ state: 'checking' });
    const timer = setTimeout(() => {
      dryRun(built.change, {
        onSuccess: (diff) => {
          if (run.current === id) setCheck({ state: 'ok', diff });
        },
        onError: (error) => {
          if (run.current !== id) return;
          setCheck({
            state: 'error',
            message: error.message,
            path: error instanceof ApiError ? error.path : undefined,
          });
        },
      });
    }, 350);
    return () => {
      clearTimeout(timer);
    };
  }, [draft, revision, editable, dryRun]);

  const keys = settings.data?.keys ?? [];
  const groups = useMemo(() => {
    const map = new Map<string, SettingKey[]>();
    for (const key of keys) {
      const id = sectionOf(key.path).id;
      map.set(id, [...(map.get(id) ?? []), key]);
    }
    return map;
  }, [keys]);
  const sections = [
    ...SECTIONS.filter((section) => groups.has(section.id)),
    ...(groups.has(OTHER.id) ? [OTHER] : []),
    HISTORY,
  ];
  const fromKey = search.key ? sectionOf(search.key) : undefined;
  const current =
    findSection(search.section) ??
    (search.section === HISTORY.id ? HISTORY : undefined) ??
    fromKey ??
    sections[0] ??
    HISTORY;

  // A key from ⌘K: scroll to it once it is on screen.
  useEffect(() => {
    if (!search.key || !settings.data) return;
    document
      .getElementById(`key-${search.key}`)
      ?.scrollIntoView({ block: 'center' });
  }, [search.key, settings.data]);

  if (settings.isError)
    return (
      <ErrorState
        error={settings.error}
        onRetry={() => void settings.refetch()}
      />
    );
  if (!settings.data)
    return <Skeleton loading rows={10} label="Loading settings" />;
  const data = settings.data;

  const select = (id: string) => {
    void navigate({ search: { section: id } });
  };
  const dirtyIn = (id: string) =>
    (groups.get(id) ?? []).filter((key) => draft.has(key.path)).length;
  const errorPath = check.state === 'error' ? check.path : undefined;
  const restartKeys = keys.filter((key) => key.pending_restart);

  const submit = () => {
    const built = toChange(draft, revision);
    if ('error' in built) return;
    apply.mutate(built.change, {
      onSuccess: (diff) => {
        setReviewing(false);
        setDraft(new Map());
        const waiting = diff.changes.filter((c) => c.pending_restart).length;
        toast(
          `Applied ${diff.changes.length} change${diff.changes.length === 1 ? '' : 's'}${waiting ? ` · ${waiting} after a restart` : ''}`,
        );
      },
      onError: (error) => {
        setReviewing(false);
        toast(
          error instanceof ApiError && error.status === 409
            ? 'The settings changed meanwhile: they are reloaded, check your draft'
            : error.message,
        );
      },
    });
  };

  return (
    <>
      <PageHead
        title="Configuration"
        sub="Every gateway setting, from bot-shield.yaml and the console's layer over it."
      />
      <div className={styles.banners}>
        {data.error ? (
          <div role="alert" className={states.degraded}>
            <span
              className={states.dot}
              style={{ background: 'var(--color-challenged)' }}
            />
            <span style={{ flex: '1 1 260px' }}>
              <b>The console layer was set aside at startup.</b> {data.error}
            </span>
          </div>
        ) : null}
        {restartKeys.length > 0 ? (
          <div role="status" className={states.degraded}>
            <span
              className={states.dot}
              style={{ background: 'var(--color-challenged)' }}
            />
            <span style={{ flex: '1 1 260px' }}>
              <b>
                {restartKeys.length} saved setting
                {restartKeys.length === 1 ? ' waits' : 's wait'} for a restart
              </b>{' '}
              of the gateway ({restartKeys.map((k) => k.path).join(', ')}). The
              console never restarts it: run{' '}
              <span className="mono">systemctl restart bot-shield</span> when it
              suits you.
            </span>
          </div>
        ) : null}
        {!data.editable ? (
          <PermissionNote>
            Settings are read-only: the gateway has no{' '}
            <span className="mono">admin.settings_file</span>. Set it in
            bot-shield.yaml and restart to change settings here.
          </PermissionNote>
        ) : !canOperate ? (
          <PermissionNote>
            You can see every setting; changing them needs the operator role.
          </PermissionNote>
        ) : null}
      </div>

      <div
        className={screens.split}
        style={{ minHeight: 'calc(100vh - 220px)' }}
      >
        {compact ? null : (
          <aside className={screens.splitList} aria-label="Sections">
            <div style={{ flex: 1, overflow: 'auto' }}>
              {sections.map((section) => {
                const list = groups.get(section.id) ?? [];
                const fromConsole = list.filter(
                  (key) => key.source === 'console',
                ).length;
                const pending = list.filter(
                  (key) => key.pending_restart,
                ).length;
                const dirty = dirtyIn(section.id);
                return (
                  <button
                    key={section.id}
                    type="button"
                    className={screens.listItem}
                    aria-current={section.id === current.id}
                    onClick={() => {
                      select(section.id);
                    }}
                  >
                    <span className={styles.sectionName}>
                      {section.name}
                      {dirty ? (
                        <span className={styles.badge} data-tone="pending">
                          {dirty} edited
                        </span>
                      ) : null}
                    </span>
                    <span className={styles.sectionMeta}>
                      {section.id === HISTORY.id ? (
                        <span>Earlier layers and rollback</span>
                      ) : (
                        <>
                          <span>
                            {list.length} key{list.length === 1 ? '' : 's'}
                          </span>
                          {fromConsole ? (
                            <span>· {fromConsole} from the console</span>
                          ) : null}
                          {pending ? (
                            <span>· {pending} need a restart</span>
                          ) : null}
                        </>
                      )}
                    </span>
                  </button>
                );
              })}
            </div>
          </aside>
        )}
        <div className={screens.splitDetail}>
          {compact ? (
            <div className={styles.phoneSections}>
              <Select
                label="Section"
                value={current.id}
                onChange={(event) => {
                  select(event.target.value);
                }}
              >
                {sections.map((section) => (
                  <option key={section.id} value={section.id}>
                    {section.name}
                    {dirtyIn(section.id)
                      ? ` (${dirtyIn(section.id)} edited)`
                      : ''}
                  </option>
                ))}
              </Select>
            </div>
          ) : null}
          {current.id === HISTORY.id ? (
            <Versions revision={revision} canRollback={editable} />
          ) : (
            <>
              <div className={screens.detailHead}>
                <div
                  style={{ display: 'flex', flexDirection: 'column', gap: 6 }}
                >
                  <h2 style={{ fontSize: 17, fontWeight: 600 }}>
                    {current.name}
                  </h2>
                  {current.help.map((name) =>
                    SETTINGS_HELP[name] ? (
                      <p key={name} className={styles.sectionHelp}>
                        {SETTINGS_HELP[name]}
                      </p>
                    ) : null,
                  )}
                </div>
              </div>
              <div className={styles.keys}>
                {(groups.get(current.id) ?? []).map((key) => (
                  <KeyRow
                    key={key.path}
                    setting={key}
                    entry={draft.get(key.path)}
                    editable={editable}
                    focused={search.key === key.path}
                    error={
                      errorPath === key.path && check.state === 'error'
                        ? check.message
                        : undefined
                    }
                    onDraft={setDraft}
                  />
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {draft.size > 0 ? (
        <div className={styles.bar} role="region" aria-label="Unsaved changes">
          <span className={styles.barText}>
            <b>
              {draft.size} unsaved change{draft.size === 1 ? '' : 's'}
            </b>
            {' · '}
            {check.state === 'checking'
              ? 'checking with the gateway…'
              : check.state === 'error'
                ? `${check.path ? `${check.path}: ` : ''}${check.message.replace(`${check.path ?? ''}: `, '')}`
                : check.state === 'ok'
                  ? 'the gateway accepts them'
                  : ''}
          </span>
          <Button
            variant="ghost"
            size="sm"
            style={{ color: 'inherit' }}
            onClick={() => {
              setDraft(new Map());
            }}
          >
            Discard
          </Button>
          <Button
            size="sm"
            className={styles.barAction}
            disabled={check.state !== 'ok'}
            onClick={() => {
              setReviewing(true);
            }}
          >
            Review
          </Button>
        </div>
      ) : null}

      <Dialog
        open={reviewing && check.state === 'ok'}
        onClose={() => {
          setReviewing(false);
        }}
        label="Review settings changes"
      >
        {check.state === 'ok' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600 }}>
              Apply {check.diff.changes.length} change
              {check.diff.changes.length === 1 ? '' : 's'}?
            </h2>
            <p
              style={{
                fontSize: 13.5,
                color: 'var(--color-text-2)',
                lineHeight: 1.5,
              }}
            >
              They go to the console layer over bot-shield.yaml and to the
              decision log. Live keys apply at once; the rest wait for a
              restart.
            </p>
            <DiffList changes={check.diff.changes} />
            <div
              style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}
            >
              <Button
                variant="ghost"
                onClick={() => {
                  setReviewing(false);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                disabled={apply.isPending}
                onClick={submit}
              >
                Apply
              </Button>
            </div>
          </div>
        ) : null}
      </Dialog>
    </>
  );
}

function Badges({ setting }: { setting: SettingKey }) {
  return (
    <span className={styles.badges}>
      <span
        className={styles.badge}
        data-tone={setting.source === 'console' ? 'console' : undefined}
        title="Where the value in effect comes from"
      >
        {SOURCE_LABEL[setting.source]}
      </span>
      {setting.apply === 'live' ? (
        <span className={styles.badge} data-tone="live">
          live
        </span>
      ) : setting.apply === 'restart' ? (
        <span className={styles.badge}>restart</span>
      ) : (
        <span className={styles.badge}>yaml only</span>
      )}
      {setting.secret ? (
        <span className={styles.badge} data-tone="secret">
          secret
        </span>
      ) : null}
      {setting.pending_restart ? (
        <span className={styles.badge} data-tone="pending">
          pending restart
        </span>
      ) : null}
    </span>
  );
}

function KeyRow({
  setting,
  entry,
  editable,
  focused,
  error,
  onDraft,
}: {
  setting: SettingKey;
  entry: DraftEntry | undefined;
  editable: boolean;
  focused: boolean;
  error: string | undefined;
  onDraft: (update: (draft: Draft) => Draft) => void;
}) {
  const help = SETTINGS_HELP[setting.path];
  const canEdit = editable && setting.apply !== 'yaml';
  return (
    <div
      id={`key-${setting.path}`}
      className={styles.key}
      data-dirty={entry !== undefined}
      data-focus={focused}
    >
      <div className={styles.keyHead}>
        <span className={styles.keyName}>{shortName(setting.path)}</span>
        <span className={styles.keyPath}>{setting.path}</span>
        <Badges setting={setting} />
        {help ? <span className={styles.keyHelp}>{help}</span> : null}
        {setting.apply === 'yaml' ? (
          <span className={styles.keyHelp}>
            Only in bot-shield.yaml: the console never points the gateway at
            files, sockets or addresses.
          </span>
        ) : null}
      </div>
      <div className={styles.control}>
        {setting.secret ? (
          <SecretControl
            setting={setting}
            entry={entry}
            canEdit={canEdit}
            onDraft={onDraft}
          />
        ) : (
          <ValueControl
            setting={setting}
            entry={entry}
            canEdit={canEdit}
            onDraft={onDraft}
          />
        )}
        {error ? (
          <div role="alert" className={styles.error}>
            {error}
          </div>
        ) : entry?.kind === 'set' && entry.error ? (
          <div role="alert" className={styles.error}>
            {entry.error}
          </div>
        ) : null}
        <Under
          setting={setting}
          entry={entry}
          canEdit={canEdit}
          onDraft={onDraft}
        />
      </div>
    </div>
  );
}

// Default, the main file's value and the way back to it.
function Under({
  setting,
  entry,
  canEdit,
  onDraft,
}: {
  setting: SettingKey;
  entry: DraftEntry | undefined;
  canEdit: boolean;
  onDraft: (update: (draft: Draft) => Draft) => void;
}) {
  return (
    <div className={styles.under}>
      {!setting.secret ? (
        <span>
          default <code>{preview(setting.default)}</code>
        </span>
      ) : null}
      {!setting.secret && setting.file_value !== undefined ? (
        <span>
          bot-shield.yaml <code>{preview(setting.file_value)}</code>
        </span>
      ) : null}
      {entry ? (
        <button
          type="button"
          className={styles.link}
          onClick={() => {
            onDraft((draft) => without(draft, setting.path));
          }}
        >
          Undo edit
        </button>
      ) : setting.source === 'console' && canEdit ? (
        <button
          type="button"
          className={styles.link}
          onClick={() => {
            onDraft((draft) => withReset(draft, setting.path));
          }}
        >
          {!setting.secret && setting.file_value === undefined
            ? 'Use the default'
            : 'Use the bot-shield.yaml value'}
        </button>
      ) : null}
      {entry?.kind === 'reset' ? (
        <span>back to the main file on apply</span>
      ) : null}
    </div>
  );
}

function ValueControl({
  setting,
  entry,
  canEdit,
  onDraft,
}: {
  setting: Extract<SettingKey, { secret: false }>;
  entry: DraftEntry | undefined;
  canEdit: boolean;
  onDraft: (update: (draft: Draft) => Draft) => void;
}) {
  const value: SettingValue =
    entry?.kind === 'set' ? entry.value : setting.value;
  const text =
    entry?.kind === 'set' && entry.text !== undefined
      ? entry.text
      : toText(setting.type, value);
  const set = (next: SettingValue, raw?: string, error?: string) => {
    onDraft((draft) => withValue(draft, setting, next, raw, error));
  };

  if (!canEdit) {
    return (
      <div className={styles.readonly}>
        {setting.type === 'bool'
          ? String(value)
          : toText(setting.type, value) || '""'}
      </div>
    );
  }
  if (setting.type === 'bool') {
    return (
      <Switch
        checked={value === true}
        label={setting.path}
        onChange={(checked) => {
          set(checked);
        }}
      >
        <span style={{ fontSize: 13 }}>{value === true ? 'on' : 'off'}</span>
      </Switch>
    );
  }
  if (setting.type === 'enum') {
    const options = setting.options ?? [];
    const labelOf = (option: string) => (option === '' ? 'off' : option);
    if (options.length <= 4) {
      return (
        <Segmented
          label={setting.path}
          options={options.map((option) => ({
            value: option,
            label: labelOf(option),
          }))}
          value={String(value)}
          onChange={(next) => {
            set(next);
          }}
        />
      );
    }
    return (
      <select
        aria-label={setting.path}
        className={`${controls.input} ${controls.select}`}
        value={String(value)}
        onChange={(event) => {
          set(event.target.value);
        }}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {labelOf(option)}
          </option>
        ))}
      </select>
    );
  }
  const onText = (raw: string) => {
    const parsed = fromText(setting.type, raw);
    if ('error' in parsed) set(value, raw, parsed.error);
    else set(parsed.value, raw);
  };
  if (isMultiline(setting.type)) {
    return (
      <textarea
        aria-label={setting.path}
        spellCheck={false}
        className={`${controls.input} ${controls.textarea} mono`}
        rows={Math.min(14, Math.max(3, text.split('\n').length + 1))}
        value={text}
        placeholder={
          setting.type === 'host_modes'
            ? 'shop.example.com: enforce'
            : setting.type === 'strings'
              ? 'one per line'
              : setting.type === 'throttle'
                ? 'empty: no throttle'
                : '[]'
        }
        onChange={(event) => {
          onText(event.target.value);
        }}
      />
    );
  }
  return (
    <input
      aria-label={setting.path}
      className={`${controls.input} mono`}
      inputMode={
        setting.type === 'int' || setting.type === 'number'
          ? 'decimal'
          : undefined
      }
      spellCheck={false}
      autoComplete="off"
      value={text}
      placeholder={
        setting.type === 'duration'
          ? '30s, 250ms, 10m, 1h'
          : setting.type === 'rate'
            ? '30/m (empty: off)'
            : undefined
      }
      onChange={(event) => {
        onText(event.target.value);
      }}
    />
  );
}

// Secrets: whether one is set, and a field to replace it. The value is
// never shown and never comes back from the gateway.
function SecretControl({
  setting,
  entry,
  canEdit,
  onDraft,
}: {
  setting: Extract<SettingKey, { secret: true }>;
  entry: DraftEntry | undefined;
  canEdit: boolean;
  onDraft: (update: (draft: Draft) => Draft) => void;
}) {
  const [replacing, setReplacing] = useState(false);
  const typed = entry?.kind === 'set' ? String(entry.value) : '';
  const status =
    entry?.kind === 'set'
      ? typed === ''
        ? 'will be cleared'
        : 'will be replaced'
      : setting.set
        ? 'set'
        : 'not set';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 8,
        }}
      >
        <span className={styles.readonly} style={{ flex: '1 1 120px' }}>
          {status}
        </span>
        {canEdit && !replacing ? (
          <>
            <Button
              size="sm"
              onClick={() => {
                setReplacing(true);
              }}
            >
              Replace
            </Button>
            {setting.set ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  onDraft((draft) => withValue(draft, setting, ''));
                }}
              >
                Clear
              </Button>
            ) : null}
          </>
        ) : null}
      </div>
      {canEdit && replacing ? (
        <TextInput
          label={`New ${shortName(setting.path)}`}
          type="password"
          autoComplete="new-password"
          mono
          value={typed}
          onChange={(event) => {
            const next = event.target.value;
            onDraft((draft) =>
              next === ''
                ? without(draft, setting.path)
                : withValue(draft, setting, next),
            );
          }}
          hint="Sent to the gateway once; the console never shows or logs it."
        />
      ) : null}
    </div>
  );
}

function DiffList({ changes }: { changes: SettingChange[] }) {
  if (changes.length === 0) {
    return (
      <EmptyState title="No effect">
        The values in effect stay the same.
      </EmptyState>
    );
  }
  return (
    <div className={styles.diff}>
      {changes.map((change) => (
        <div key={change.path} className={styles.diffRow}>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <span className="mono" style={{ fontWeight: 500 }}>
              {change.path}
            </span>
            <span
              className={styles.badge}
              data-tone={change.apply === 'live' ? 'live' : undefined}
            >
              {change.apply === 'live' ? 'applies now' : 'after a restart'}
            </span>
          </div>
          <div className={styles.diffValues}>
            {change.secret ? (
              <span>
                {change.source_after !== 'console'
                  ? 'back to the main file'
                  : change.set_after
                    ? 'secret replaced'
                    : 'secret cleared'}
              </span>
            ) : (
              <>
                <span className={styles.before}>{preview(change.before)}</span>
                <span>→</span>
                <span>{preview(change.after)}</span>
              </>
            )}
            {change.source_before !== change.source_after ? (
              <span style={{ color: 'var(--color-text-3)' }}>
                ({SOURCE_LABEL[change.source_before]} →{' '}
                {SOURCE_LABEL[change.source_after]})
              </span>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  );
}

function Versions({
  revision,
  canRollback,
}: {
  revision: string;
  canRollback: boolean;
}) {
  const history = useSettingsHistory();
  const rollback = useRollbackSettings();
  const toast = useToast();
  const [target, setTarget] = useState<string | null>(null);
  return (
    <>
      <div className={screens.detailHead}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <h2 style={{ fontSize: 17, fontWeight: 600 }}>Versions</h2>
          <p className={styles.sectionHelp}>
            The console layer before each of the last changes, newest first.
            Rolling back applies that layer again, secrets included, and is a
            change of its own. Current version{' '}
            <span className="mono">{revision.slice(0, 8)}</span>.
          </p>
        </div>
      </div>
      {history.isError ? (
        <div style={{ padding: 20 }}>
          <ErrorState
            error={history.error}
            onRetry={() => void history.refetch()}
          />
        </div>
      ) : !history.data ? (
        <Skeleton loading rows={4} label="Loading versions" />
      ) : history.data.versions.length === 0 ? (
        <EmptyState title="No earlier versions">
          Every change made here keeps the layer it replaced.
        </EmptyState>
      ) : (
        history.data.versions.map((version) => (
          <div key={version.revision} className={styles.version}>
            <span style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span className="mono">{version.revision.slice(0, 8)}</span>
              <span style={{ color: 'var(--color-text-3)', fontSize: 12 }}>
                replaced {dateTime(version.replaced_at_ms)} ·{' '}
                {version.keys.length
                  ? `${version.keys.length} keys: ${version.keys.slice(0, 3).join(', ')}${version.keys.length > 3 ? ', …' : ''}`
                  : 'empty layer'}
              </span>
            </span>
            {canRollback ? (
              <Button
                size="sm"
                onClick={() => {
                  setTarget(version.revision);
                }}
              >
                Roll back
              </Button>
            ) : null}
          </div>
        ))
      )}
      <Dialog
        open={target !== null}
        onClose={() => {
          setTarget(null);
        }}
        label="Confirm rollback"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600 }}>
            Roll back to {target?.slice(0, 8)}?
          </h2>
          <p
            style={{
              fontSize: 13.5,
              color: 'var(--color-text-2)',
              lineHeight: 1.5,
            }}
          >
            The whole console layer goes back to that version and is checked
            like any change. Live keys apply at once.
          </p>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <Button
              variant="ghost"
              onClick={() => {
                setTarget(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={rollback.isPending}
              onClick={() => {
                if (!target) return;
                rollback.mutate(
                  { revision: target, base_revision: revision },
                  {
                    onSuccess: (diff) => {
                      toast(
                        `Rolled back: ${diff.changes.length} setting${diff.changes.length === 1 ? '' : 's'} changed`,
                      );
                    },
                    onError: (error) => {
                      toast(error.message);
                    },
                  },
                );
                setTarget(null);
              }}
            >
              Roll back
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
