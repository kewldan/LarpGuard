// Rules: the rules in effect (first match wins), an editor that
// type-checks with the gateway's own parser as you type, and a test of the
// draft against a sample of the last hour. Saving, switching off,
// deleting and reordering go to the gateway's settings layer (the `rules`
// key, ADR-018) and apply at once; the YAML snippet is there for those who
// keep rules in the main file.

import { useNavigate, useSearch } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';

import type { Rules as RulesData, RuleTestResult } from '../../shared/api.ts';
import { ACTIONS, type Action } from '../../shared/domain.ts';
import { useCanOperate } from '../app/session.ts';
import { ActionChip } from '../domain/verdict.tsx';
import { ApiError } from '../lib/api.ts';
import { type RuleDraft, ruleSpec, ruleYaml } from '../lib/config-yaml.ts';
import {
  clock,
  compact,
  count,
  duration,
  lineColumn,
  percent,
} from '../lib/format.ts';
import { useCompact } from '../lib/media.ts';
import {
  useApplySettings,
  useGatewayConfig,
  useReload,
  useRuleCheck,
  useRules,
  useRuleTest,
} from '../lib/queries.ts';
import { highlight } from '../lib/rule-syntax.ts';
import { thresholdsOf } from '../lib/signals.ts';
import { toneText } from '../lib/tone.ts';
import { Button } from '../ui/Button.tsx';
import { Segmented } from '../ui/controls.tsx';
import { Icon, Spinner } from '../ui/Icon.tsx';
import {
  EmptyState,
  ErrorState,
  PermissionNote,
  Skeleton,
} from '../ui/states.tsx';
import table from '../ui/table.module.css';
import { useCopy, useToast } from '../ui/toast-context.ts';
import styles from './screens.module.css';

type RuleAction = Action | 'score';
type Draft = RuleDraft;

const DRAFTS_KEY = 'larpguard.rule-drafts';

// Unsaved edits survive a reload or an expired session (per browser).
function loadDrafts(): Record<string, Draft> {
  try {
    return JSON.parse(localStorage.getItem(DRAFTS_KEY) ?? '{}') as Record<
      string,
      Draft
    >;
  } catch {
    return {};
  }
}

function saveDrafts(drafts: Record<string, Draft>): void {
  try {
    localStorage.setItem(DRAFTS_KEY, JSON.stringify(drafts));
  } catch {
    // Storage unavailable: drafts last for this page.
  }
}

function isDirty(
  draft: Draft,
  original: RulesData['rules'][number] | undefined,
): boolean {
  if (original === undefined) return true;
  return (
    draft.when !== original.when ||
    draft.action !== original.action ||
    (draft.action === 'score' && draft.score !== (original.score ?? 0))
  );
}

function fromRule(rule: RulesData['rules'][number]): Draft {
  return {
    name: rule.name,
    when: rule.when,
    action: rule.action,
    score: rule.score ?? 0,
    disabled: rule.disabled,
  };
}

const RULE_NAME = /^[\w.-]{1,64}$/;

function Editor({
  value,
  onChange,
  errorLine,
}: {
  value: string;
  onChange: (value: string) => void;
  errorLine: number | null;
}) {
  const lines = value.split('\n');
  return (
    <div
      style={{
        display: 'flex',
        border: '1px solid var(--color-line-strong)',
        borderRadius: 10,
        background: 'var(--color-surface-1)',
        overflow: 'hidden',
      }}
    >
      <div
        className="mono"
        aria-hidden="true"
        style={{
          padding: '12px 0 12px 12px',
          fontSize: 12,
          lineHeight: '22px',
          color: 'var(--color-text-3)',
          textAlign: 'right',
          borderRight: '1px solid var(--color-line)',
          userSelect: 'none',
        }}
      >
        {lines.map((_, i) => (
          <div
            // biome-ignore lint/suspicious/noArrayIndexKey: line numbers are the index.
            key={i}
            style={{
              paddingRight: 10,
              color:
                errorLine === i + 1 ? 'var(--color-blocked-text)' : undefined,
            }}
          >
            {i + 1}
          </div>
        ))}
      </div>
      <div style={{ position: 'relative', flex: 1, minWidth: 0 }}>
        <div
          className="mono"
          aria-hidden="true"
          style={{
            padding: '12px 14px',
            fontSize: 13,
            lineHeight: '22px',
            minHeight: 154,
          }}
        >
          {lines.map((line, i) => (
            <div
              // biome-ignore lint/suspicious/noArrayIndexKey: editor lines are positional.
              key={i}
              style={{
                whiteSpace: 'pre-wrap',
                overflowWrap: 'anywhere',
                minHeight: 22,
              }}
            >
              {highlight(line).map((token, j) => (
                <span
                  // biome-ignore lint/suspicious/noArrayIndexKey: tokens are positional.
                  key={j}
                  style={{ color: token.color, fontWeight: token.weight }}
                >
                  {token.text}
                </span>
              ))}
            </div>
          ))}
        </div>
        <textarea
          aria-label="Expression"
          spellCheck={false}
          className="mono"
          value={value}
          onChange={(event) => {
            onChange(event.target.value);
          }}
          style={{
            position: 'absolute',
            inset: 0,
            width: '100%',
            height: '100%',
            padding: '12px 14px',
            border: 0,
            background: 'transparent',
            color: 'transparent',
            caretColor: 'var(--color-text)',
            fontSize: 13,
            lineHeight: '22px',
            resize: 'none',
            whiteSpace: 'pre-wrap',
            overflowWrap: 'anywhere',
          }}
        />
      </div>
    </div>
  );
}

function TestResult({
  result,
  action,
}: {
  result: RuleTestResult;
  action: RuleAction;
}) {
  const config = useGatewayConfig().data;
  const thresholds = thresholdsOf(config);
  const pct = result.sampled ? percent(result.matched, result.sampled) : '0%';
  const tiles = (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
        borderBottom: '1px solid var(--color-line)',
      }}
    >
      <div
        style={{
          padding: '14px 16px',
          borderRight: '1px solid var(--color-line)',
        }}
      >
        <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
          Would match
        </div>
        <div
          className="mono"
          style={{
            fontSize: 26,
            fontWeight: 500,
            letterSpacing: '-0.02em',
            marginTop: 4,
          }}
        >
          {result.source === 'live' ? '' : '≈'}
          {compact(result.estimated)}
        </div>
        <div
          className="mono"
          style={{ fontSize: 12, color: 'var(--color-text-3)' }}
        >
          {pct} of {compact(result.total)}
        </div>
      </div>
      <div
        style={{
          padding: '14px 16px',
          borderRight: '1px solid var(--color-line)',
        }}
      >
        <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
          Action changes
        </div>
        <div
          className="mono"
          style={{
            fontSize: 26,
            fontWeight: 500,
            letterSpacing: '-0.02em',
            marginTop: 4,
            color: result.action_changes
              ? 'var(--color-text)'
              : 'var(--color-text-3)',
          }}
        >
          {count(result.action_changes)}
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
          in the sample, now handled → <span className="mono">{action}</span>
        </div>
      </div>
      <div
        className={result.shadow_hosts ? 'hatch' : ''}
        style={{
          padding: '14px 16px',
          borderRight: '1px solid var(--color-line)',
        }}
      >
        <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
          On shadow hosts
        </div>
        <div
          className="mono"
          style={{
            fontSize: 26,
            fontWeight: 500,
            letterSpacing: '-0.02em',
            marginTop: 4,
          }}
        >
          {count(result.shadow_hosts)}
        </div>
        <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
          logged only, not enforced
        </div>
      </div>
      <div
        style={{
          padding: '14px 16px',
          background:
            result.verified_bots && action !== 'allow'
              ? 'var(--color-challenged-soft)'
              : 'transparent',
        }}
      >
        <div style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
          Verified crawlers hit
        </div>
        <div
          className="mono"
          style={{
            fontSize: 26,
            fontWeight: 500,
            letterSpacing: '-0.02em',
            marginTop: 4,
            color:
              result.verified_bots && action !== 'allow'
                ? 'var(--color-challenged-text)'
                : 'var(--color-text-3)',
          }}
        >
          {count(result.verified_bots)}
        </div>
        <div
          style={{
            fontSize: 12,
            color:
              result.verified_bots && action !== 'allow'
                ? 'var(--color-challenged-text)'
                : 'var(--color-text-3)',
          }}
        >
          {result.verified_bots && action !== 'allow'
            ? 'Check this is intended'
            : 'none affected'}
        </div>
      </div>
    </div>
  );
  return (
    <>
      {tiles}
      {result.approximate.length > 0 ? (
        <div
          style={{
            padding: '10px 16px',
            borderBottom: '1px solid var(--color-line)',
            fontSize: 12.5,
            color: 'var(--color-challenged-text)',
            background: 'var(--color-challenged-soft)',
          }}
        >
          Approximate: events do not carry{' '}
          <span className="mono">{result.approximate.join(', ')}</span> exactly
          (no header, cookie or query values, addresses as /24 or /48 prefixes,
          paths as normalized groups). Test live for exact results.
        </div>
      ) : null}
      {result.by_host.length > 0 ? (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 8,
            padding: '12px 16px',
            borderBottom: '1px solid var(--color-line)',
          }}
        >
          {result.by_host.map((row) => (
            <span
              key={row.host}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                height: 24,
                padding: '0 9px',
                borderRadius: 999,
                border: '1px solid var(--color-line-strong)',
                fontSize: 12,
                color: 'var(--color-text-2)',
              }}
            >
              <span className="mono">{row.host}</span>
              <span className="mono" style={{ color: 'var(--color-text)' }}>
                {count(row.matched)}
              </span>
            </span>
          ))}
        </div>
      ) : null}
      {result.samples.length > 0 ? (
        <div className={table.wrap}>
          <table
            className={table.table}
            style={{ minWidth: 680, fontSize: 12.5 }}
          >
            <thead>
              <tr>
                <th>Sample</th>
                <th>Host · path</th>
                <th>Score</th>
                <th>Class</th>
                <th>ASN</th>
                <th>Client</th>
                <th>Now → after</th>
              </tr>
            </thead>
            <tbody>
              {result.samples.map((sample, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: samples have no id and never reorder.
                <tr key={i}>
                  <td className={`mono ${table.muted}`}>{clock(sample.ts)}</td>
                  <td className="mono">
                    <span style={{ color: 'var(--color-text-2)' }}>
                      {sample.host}
                    </span>{' '}
                    {sample.path_group}
                  </td>
                  <td
                    className="mono"
                    style={{ color: toneText(sample.score, thresholds) }}
                  >
                    {sample.score}
                  </td>
                  <td className="mono" style={{ color: 'var(--color-text-2)' }}>
                    {sample.class}
                  </td>
                  <td className="mono" style={{ color: 'var(--color-text-2)' }}>
                    {sample.asn ? `AS${sample.asn}` : '—'}
                  </td>
                  <td className="mono" style={{ color: 'var(--color-text-2)' }}>
                    {sample.ip_prefix}
                  </td>
                  <td className="mono">
                    <span style={{ color: 'var(--color-text-3)' }}>
                      {sample.action}
                    </span>{' '}
                    → <ActionChip action={sample.after} small />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          style={{
            padding: '28px 16px',
            fontSize: 13,
            color: 'var(--color-text-3)',
            textAlign: 'center',
          }}
        >
          No request in the sample matches.
        </div>
      )}
    </>
  );
}

export function Rules() {
  const rules = useRules();
  const search = useSearch({ from: '/rules' });
  const navigate = useNavigate({ from: '/rules' });
  const canOperate = useCanOperate();
  const compactLayout = useCompact();
  const reload = useReload();
  const apply = useApplySettings();
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const check = useRuleCheck();
  const test = useRuleTest();
  const toast = useToast();
  const copy = useCopy();
  const [drafts, setDrafts] = useState<Record<string, Draft>>(loadDrafts);
  const [testedKey, setTestedKey] = useState<string | null>(null);
  // Where to test: an hour of events, or the gateway's recent requests
  // (exact headers, cookies, query, address and path).
  const [source, setSource] = useState<'events' | 'live'>('events');

  const list = useMemo(() => rules.data?.rules ?? [], [rules.data]);
  const names = list.map((rule) => rule.name);
  const newNames = Object.keys(drafts).filter((name) => !names.includes(name));
  const selected = search.rule ?? list[0]?.name ?? newNames[0];
  const original = list.find((rule) => rule.name === selected);
  const draft: Draft | undefined =
    (selected ? drafts[selected] : undefined) ??
    (original ? fromRule(original) : undefined);
  const dirty = draft !== undefined && isDirty(draft, original);
  const key = draft ? `${draft.when}|${draft.action}|${source}` : '';

  const update = (patch: Partial<Draft>) => {
    if (!draft || !selected) return;
    const next = { ...drafts, [selected]: { ...draft, ...patch } };
    setDrafts(next);
    saveDrafts(next);
  };
  const discard = () => {
    if (!selected) return;
    const next = Object.fromEntries(
      Object.entries(drafts).filter(([name]) => name !== selected),
    );
    setDrafts(next);
    saveDrafts(next);
  };

  // Type-check as you type (the gateway's parser, no traffic).
  const { mutate: runCheck } = check;
  useEffect(() => {
    if (!draft?.when.trim()) return;
    const timer = setTimeout(() => {
      runCheck({ when: draft.when, action: draft.action });
    }, 400);
    return () => {
      clearTimeout(timer);
    };
  }, [draft?.when, draft?.action, runCheck]);

  const compileError =
    check.error instanceof ApiError && check.error.status === 422
      ? check.error
      : null;
  const errorPosition =
    compileError?.column !== undefined && draft
      ? lineColumn(draft.when, compileError.column)
      : null;
  const tested = test.data !== undefined && testedKey === key;
  const result = tested ? test.data : undefined;

  // The whole list goes to the settings layer: the gateway checks it with
  // its own parser and applies it at once (or refuses, nothing changes).
  const saveRules = (next: Draft[], done: string, after?: () => void) => {
    const revision = rules.data?.revision;
    if (!revision) return;
    apply.mutate(
      { base_revision: revision, set: { rules: next.map(ruleSpec) } },
      {
        onSuccess: () => {
          toast(done);
          after?.();
        },
        onError: (error) => {
          toast(error.message);
        },
      },
    );
  };
  const inEffect = list.map(fromRule);
  // The main file decides again (the layer's `rules` key goes).
  const backToFile = () => {
    const revision = rules.data?.revision;
    if (!revision) return;
    apply.mutate(
      { base_revision: revision, reset: ['rules'] },
      {
        onSuccess: () => {
          toast('Rules from bot-shield.yaml again');
        },
        onError: (error) => {
          toast(error.message);
        },
      },
    );
  };
  const save = () => {
    if (!draft) return;
    const next = original
      ? inEffect.map((rule) =>
          rule.name === original.name
            ? { ...draft, disabled: rule.disabled ?? false }
            : rule,
        )
      : [...inEffect, { ...draft, disabled: false }];
    saveRules(next, `Saved ${draft.name}`, discard);
  };
  const setDisabled = (disabled: boolean) => {
    if (!original) return;
    saveRules(
      inEffect.map((rule) =>
        rule.name === original.name ? { ...rule, disabled } : rule,
      ),
      `${original.name} ${disabled ? 'switched off' : 'switched on'}`,
    );
  };
  const remove = () => {
    if (!original) return;
    const name = original.name;
    saveRules(
      inEffect.filter((rule) => rule.name !== name),
      `Deleted ${name}`,
      () => {
        setConfirmDelete(null);
        void navigate({ search: {} });
      },
    );
  };
  const move = (by: -1 | 1) => {
    if (!original) return;
    const from = names.indexOf(original.name);
    const to = from + by;
    if (to < 0 || to >= inEffect.length) return;
    const next = [...inEffect];
    const [moved] = next.splice(from, 1);
    if (moved) next.splice(to, 0, moved);
    saveRules(next, `Moved ${original.name} to ${to + 1}`);
  };
  const rename = (name: string) => {
    if (!draft || original || !selected) return;
    const rest = Object.fromEntries(
      Object.entries(drafts).filter(([key]) => key !== selected),
    );
    const next = { ...rest, [name]: { ...draft, name } };
    setDrafts(next);
    saveDrafts(next);
    void navigate({ search: { rule: name } });
  };
  const nameProblem =
    draft && !original
      ? !RULE_NAME.test(draft.name)
        ? 'Letters, digits, ".", "-" and "_" only.'
        : names.includes(draft.name)
          ? 'A rule has this name already.'
          : null
      : null;
  const canSave =
    canOperate &&
    rules.data?.editable === true &&
    draft !== undefined &&
    dirty &&
    draft.when.trim() !== '' &&
    compileError === null &&
    nameProblem === null &&
    !apply.isPending;

  const newRule = () => {
    let n = 1;
    while (names.includes(`new_rule_${n}`) || drafts[`new_rule_${n}`]) n += 1;
    const name = `new_rule_${n}`;
    const next = {
      ...drafts,
      [name]: {
        name,
        when: 'score >= 70 and asn_hosting',
        action: 'challenge' as const,
        score: 0,
      },
    };
    setDrafts(next);
    saveDrafts(next);
    void navigate({ search: { rule: name } });
  };

  const items = useMemo<
    {
      name: string;
      action: RuleAction;
      when: string;
      hits: number | null;
      disabled: boolean;
    }[]
  >(
    () => [
      ...list.map((rule) => ({
        name: rule.name,
        action: rule.action,
        when: rule.when,
        hits: rule.hits_1h,
        disabled: rule.disabled,
      })),
      ...newNames.map((name) => ({
        name,
        action: drafts[name]?.action ?? 'allow',
        when: drafts[name]?.when ?? '',
        hits: null,
        disabled: false,
      })),
    ],
    [list, newNames, drafts],
  );

  if (rules.isError)
    return (
      <ErrorState error={rules.error} onRetry={() => void rules.refetch()} />
    );
  if (!rules.data) return <Skeleton loading rows={8} label="Loading rules" />;

  const listPane = (
    <aside className={styles.splitList} aria-label="Rules">
      <div
        style={{
          padding: '14px 16px',
          borderBottom: '1px solid var(--color-line)',
        }}
      >
        <h1 style={{ fontSize: 17, fontWeight: 600 }}>Rules</h1>
        <div
          style={{ fontSize: 11.5, color: 'var(--color-text-3)', marginTop: 4 }}
        >
          Score rules first, then the first matching action rule · lists run
          before rules
        </div>
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        {items.map((item, i) => (
          <button
            key={item.name}
            type="button"
            className={styles.listItem}
            aria-current={item.name === selected}
            onClick={() => void navigate({ search: { rule: item.name } })}
            style={item.disabled ? { opacity: 0.55 } : undefined}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span
                className="mono"
                style={{
                  fontSize: 11,
                  color: 'var(--color-text-3)',
                  width: 16,
                }}
              >
                {i + 1}
              </span>
              <span
                className="mono"
                style={{
                  flex: 1,
                  minWidth: 0,
                  fontSize: 12.5,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {item.name}
              </span>
              {drafts[item.name] ? (
                <span
                  title="Unsaved draft"
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: 9,
                    background: 'var(--color-text)',
                  }}
                />
              ) : null}
              {item.disabled ? (
                <span
                  className="mono"
                  style={{ fontSize: 11, color: 'var(--color-text-3)' }}
                >
                  off
                </span>
              ) : item.action === 'score' ? (
                <span
                  className="mono"
                  style={{ fontSize: 11, color: 'var(--color-text-2)' }}
                >
                  score
                </span>
              ) : (
                <ActionChip action={item.action} small />
              )}
            </div>
            <div
              className="mono"
              style={{
                margin: '0 0 0 24px',
                fontSize: 11.5,
                color: 'var(--color-text-3)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {item.when.replace(/\s+/g, ' ')}
            </div>
            <div
              style={{
                marginLeft: 24,
                fontSize: 11,
                color: 'var(--color-text-3)',
              }}
            >
              <span className="mono">
                {item.hits === null ? 'draft' : `${compact(item.hits)}/h`}
              </span>
            </div>
          </button>
        ))}
        {items.length === 0 ? (
          <EmptyState title="No rules">
            The configuration has no rules yet.
          </EmptyState>
        ) : null}
      </div>
      <div
        style={{
          padding: '12px 16px',
          borderTop: '1px solid var(--color-line)',
        }}
      >
        <Button
          size="sm"
          block
          onClick={newRule}
          style={{ borderStyle: 'dashed' }}
        >
          + New rule
        </Button>
      </div>
    </aside>
  );

  return (
    <div
      className={styles.split}
      style={{ minHeight: compactLayout ? undefined : 'calc(100vh - 130px)' }}
    >
      {listPane}
      {draft ? (
        <section
          className={styles.splitDetail}
          aria-label={`Rule ${draft.name}`}
        >
          <div className={styles.detailHead}>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
                {original
                  ? `Rule ${names.indexOf(original.name) + 1} of ${names.length} · set ${rules.data.generation}${original.disabled ? ' · switched off' : ''}`
                  : 'New rule · not in the configuration yet'}
                {dirty ? ' · edited' : ''}
              </div>
              {original ? (
                <div
                  className="mono"
                  style={{ fontSize: 16, fontWeight: 500, marginTop: 2 }}
                >
                  {draft.name}
                </div>
              ) : (
                <input
                  aria-label="Rule name"
                  aria-invalid={nameProblem ? true : undefined}
                  title={nameProblem ?? undefined}
                  className="mono"
                  value={draft.name}
                  onChange={(event) => {
                    rename(event.target.value);
                  }}
                  style={{
                    marginTop: 2,
                    fontSize: 15,
                    height: 30,
                    padding: '0 8px',
                    borderRadius: 6,
                    border: `1px solid ${nameProblem ? 'var(--color-blocked)' : 'var(--color-line-strong)'}`,
                    background: 'var(--color-surface-1)',
                  }}
                />
              )}
            </div>
            <div style={{ flex: 1 }} />
            {drafts[draft.name] ? (
              <Button size="sm" variant="ghost" onClick={discard}>
                Discard draft
              </Button>
            ) : null}
            <Button
              disabled={
                !draft.when.trim() || compileError !== null || test.isPending
              }
              onClick={() => {
                setTestedKey(key);
                test.mutate({
                  when: draft.when,
                  action: draft.action,
                  source,
                });
              }}
            >
              {test.isPending ? <Spinner size={14} /> : null}
              {tested
                ? 'Test again'
                : source === 'live'
                  ? 'Test live'
                  : 'Test against 1h'}
            </Button>
            {canOperate && rules.data.editable && original && !dirty ? (
              <>
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label="Move up"
                  disabled={
                    apply.isPending || names.indexOf(original.name) === 0
                  }
                  onClick={() => {
                    move(-1);
                  }}
                >
                  ↑
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label="Move down"
                  disabled={
                    apply.isPending ||
                    names.indexOf(original.name) === names.length - 1
                  }
                  onClick={() => {
                    move(1);
                  }}
                >
                  ↓
                </Button>
                <Button
                  size="sm"
                  disabled={apply.isPending}
                  onClick={() => {
                    setDisabled(!original.disabled);
                  }}
                >
                  {original.disabled ? 'Switch on' : 'Switch off'}
                </Button>
                {confirmDelete === original.name ? (
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={apply.isPending}
                    onClick={remove}
                  >
                    Delete {original.name}?
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="dangerOutline"
                    onClick={() => {
                      setConfirmDelete(original.name);
                    }}
                  >
                    Delete
                  </Button>
                )}
              </>
            ) : null}
            {canOperate && rules.data.editable ? (
              <Button variant="primary" disabled={!canSave} onClick={save}>
                {apply.isPending ? <Spinner size={14} /> : null}
                {original ? 'Save' : 'Add rule'}
              </Button>
            ) : null}
            {canOperate ? (
              <Button
                variant="ghost"
                disabled={reload.isPending}
                onClick={() => {
                  reload.mutate(undefined, {
                    onSuccess: (result) => {
                      toast(
                        `Reloaded: ${result.changes.length === 0 ? 'nothing changed' : `${result.changes.length} changed`}`,
                      );
                    },
                    onError: (error) => {
                      toast(`Reload failed: ${error.message}`);
                    },
                  });
                }}
              >
                Reload config
              </Button>
            ) : null}
          </div>

          <div className={styles.detailBody}>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: '16px 28px',
                alignItems: 'flex-end',
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: 12,
                    color: 'var(--color-text-3)',
                    marginBottom: 6,
                  }}
                >
                  Action when matched
                </div>
                <div
                  role="group"
                  aria-label="Action"
                  style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 4 }}
                >
                  {[...ACTIONS, 'score' as const].map((action) => {
                    const on = draft.action === action;
                    return (
                      <button
                        key={action}
                        type="button"
                        aria-pressed={on}
                        className="mono"
                        onClick={() => {
                          update({ action });
                        }}
                        style={{
                          height: 30,
                          padding: '0 10px',
                          borderRadius: 6,
                          fontSize: 12,
                          border: `1px solid ${on ? 'var(--color-text)' : 'var(--color-line-strong)'}`,
                          background: on
                            ? 'var(--color-surface-3)'
                            : 'transparent',
                          color: on
                            ? 'var(--color-text)'
                            : 'var(--color-text-2)',
                        }}
                      >
                        {action}
                      </button>
                    );
                  })}
                </div>
              </div>
              {draft.action === 'score' ? (
                <label
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 6,
                    fontSize: 12,
                    color: 'var(--color-text-3)',
                  }}
                >
                  Score change
                  <input
                    type="number"
                    min={-100}
                    max={100}
                    value={draft.score}
                    className="mono"
                    onChange={(event) => {
                      update({ score: Number(event.target.value) });
                    }}
                    style={{
                      width: 90,
                      height: 30,
                      padding: '0 8px',
                      borderRadius: 6,
                      border: '1px solid var(--color-line-strong)',
                      background: 'var(--color-surface-1)',
                    }}
                  />
                </label>
              ) : null}
            </div>

            <div>
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  justifyContent: 'space-between',
                  alignItems: 'baseline',
                  gap: 8,
                  marginBottom: 6,
                }}
              >
                <span style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                  Expression
                </span>
                <span style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
                  and · or · not · == != &lt; &gt; ~ in · header() cookie()
                  query() cidr()
                </span>
              </div>
              <Editor
                value={draft.when}
                onChange={(when) => {
                  update({ when });
                }}
                errorLine={errorPosition?.line ?? null}
              />
              <div style={{ marginTop: 8, minHeight: 18 }}>
                {compileError && errorPosition ? (
                  <div
                    className="mono"
                    role="alert"
                    style={{
                      display: 'flex',
                      gap: 10,
                      fontSize: 12,
                      color: 'var(--color-blocked-text)',
                      animation: 'fade 160ms var(--ease-out) both',
                    }}
                  >
                    <span style={{ color: 'var(--color-text-3)' }}>
                      L{errorPosition.line}:{errorPosition.col}
                    </span>
                    {compileError.message.replace(/^col \d+: /, '')}
                  </div>
                ) : check.data ? (
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      fontSize: 12,
                      color: 'var(--color-text-2)',
                    }}
                  >
                    <span
                      style={{
                        width: 7,
                        height: 7,
                        borderRadius: 9,
                        background: 'var(--color-healthy)',
                      }}
                    />
                    Type-checks · bool expression ·{' '}
                    {check.data.references.length} fields referenced
                  </div>
                ) : check.isError && !compileError ? (
                  <div
                    style={{
                      fontSize: 12,
                      color: 'var(--color-challenged-text)',
                    }}
                  >
                    {check.error.message}
                  </div>
                ) : null}
              </div>
            </div>

            <section
              aria-label="Test preview"
              style={{
                border: '1px solid var(--color-line)',
                borderRadius: 12,
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: 8,
                  padding: '12px 16px',
                  borderBottom: '1px solid var(--color-line)',
                  background: 'var(--color-surface-1)',
                }}
              >
                <h2 style={{ fontSize: 14, fontWeight: 600 }}>
                  {source === 'live'
                    ? 'Test against live traffic'
                    : 'Test against last 1h of traffic'}
                </h2>
                <Segmented<'events' | 'live'>
                  label="Sample"
                  mono={false}
                  options={[
                    { value: 'events', label: 'Last hour' },
                    { value: 'live', label: 'Live, exact' },
                  ]}
                  value={source}
                  onChange={setSource}
                />
                <span style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                  {test.isPending
                    ? 'running'
                    : result
                      ? result.source === 'live'
                        ? `${count(result.sampled)} recent requests${result.window_ms ? `, last ${duration(result.window_ms)}` : ''}`
                        : `${count(result.sampled)} sampled of ${compact(result.total)}`
                      : 'not run'}
                </span>
              </div>
              {test.isPending ? (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 10,
                    height: 120,
                    fontSize: 13,
                    color: 'var(--color-text-3)',
                  }}
                >
                  <Spinner />{' '}
                  {source === 'live'
                    ? "Evaluating on the gateway's recent requests…"
                    : 'Sampling the last hour and evaluating…'}
                </div>
              ) : test.isError && testedKey === key ? (
                <ErrorState error={test.error} />
              ) : result ? (
                <TestResult result={result} action={draft.action} />
              ) : (
                <div
                  style={{
                    padding: '28px 16px',
                    fontSize: 13,
                    color: 'var(--color-text-3)',
                    textAlign: 'center',
                  }}
                >
                  {test.data
                    ? 'Edited since the last test. Run it again before changing the config.'
                    : source === 'live'
                      ? 'Live tests run in the gateway on its recent requests, with headers, cookies, query and the full address; only event fields come back.'
                      : 'Run the test to see what this rule would have matched in the last hour.'}
                </div>
              )}
            </section>

            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                gap: '6px 12px',
                fontSize: 12,
                color: 'var(--color-text-3)',
              }}
            >
              <span style={{ flex: '1 1 320px' }}>
                {rules.data.editable
                  ? rules.data.source === 'console'
                    ? 'The rules come from the console (settings layer) and win over bot-shield.yaml.'
                    : "The rules come from bot-shield.yaml. Saving here moves the whole list to the console's settings layer, which then wins over the file."
                  : 'The gateway has no admin.settings_file: rules change only in bot-shield.yaml. Copy the snippet below and reload.'}
              </span>
              {canOperate &&
              rules.data.editable &&
              rules.data.source === 'console' ? (
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={apply.isPending}
                  onClick={backToFile}
                >
                  Back to the file&apos;s rules
                </Button>
              ) : null}
            </div>

            <section aria-label="Configuration snippet">
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 6,
                }}
              >
                <span style={{ fontSize: 12, color: 'var(--color-text-3)' }}>
                  In <span className="mono">bot-shield.yaml</span> (the
                  configuration is the source of truth)
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    copy(ruleYaml(draft), 'YAML');
                  }}
                >
                  <Icon name="copy" size={13} /> Copy YAML
                </Button>
              </div>
              <pre className={styles.code}>{ruleYaml(draft)}</pre>
              {!canOperate ? (
                <div style={{ marginTop: 12 }}>
                  <PermissionNote>
                    You can draft and test rules; saving them or reloading the
                    configuration needs the operator role.
                  </PermissionNote>
                </div>
              ) : null}
            </section>
          </div>
        </section>
      ) : (
        <section className={styles.splitDetail}>
          <EmptyState title="Pick a rule" />
        </section>
      )}
    </div>
  );
}
