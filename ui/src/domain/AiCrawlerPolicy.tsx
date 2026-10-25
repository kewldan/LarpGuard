// How AI crawlers are treated (crawlers.ai, crawlers.ai_robots), switched
// right here through the settings layer: the same change, audit and
// revert as on the Configuration screen.

import { Link } from '@tanstack/react-router';

import type { SettingValue } from '../../shared/api.ts';
import { useCanOperate } from '../app/session.ts';
import { ApiError } from '../lib/api.ts';
import { useApplySettings, useSettings } from '../lib/queries.ts';
import { Segmented, Switch } from '../ui/controls.tsx';
import { useToast } from '../ui/toast-context.ts';

const AI_ACTIONS = [
  'default',
  'allow',
  'challenge',
  'block',
  'decoy',
  'tarpit',
] as const;
type AiAction = (typeof AI_ACTIONS)[number];

const ACTION_TEXT: Record<AiAction, string> = {
  default: 'Scored like anyone else.',
  allow: 'Let through.',
  challenge: 'JavaScript challenge; crawlers rarely pass it.',
  block: 'Refused.',
  decoy: 'Served fake pages instead of the site.',
  tarpit: 'Answered at a trickle, wasting their time.',
};

export function AiCrawlerPolicy() {
  const settings = useSettings();
  const apply = useApplySettings();
  const canOperate = useCanOperate();
  const toast = useToast();
  const data = settings.data;
  if (!data) return null;

  const value = (path: string): SettingValue | undefined => {
    const key = data.keys.find((k) => k.path === path);
    return key && !key.secret ? key.value : undefined;
  };
  const raw = value('crawlers.ai');
  const action = (
    AI_ACTIONS.includes(raw as AiAction) ? raw : 'default'
  ) as AiAction;
  const robots = value('crawlers.ai_robots') === true;
  const labyrinth = value('decoy.labyrinth') === true;
  const editable = canOperate && data.editable && !apply.isPending;

  const change = (path: string, next: SettingValue, done: string) => {
    apply.mutate(
      { base_revision: data.revision, set: { [path]: next } },
      {
        onSuccess: () => {
          toast(done);
        },
        onError: (error) => {
          toast(
            error instanceof ApiError && error.status === 409
              ? 'The settings changed meanwhile; try again'
              : error.message,
          );
        },
      },
    );
  };

  return (
    <section
      aria-label="AI crawlers"
      style={{
        border: '1px solid var(--color-line)',
        borderRadius: 12,
        padding: 18,
        marginBottom: 16,
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
      }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
        }}
      >
        <h2 style={{ fontSize: 15, fontWeight: 600 }}>AI crawlers</h2>
        <Segmented
          label="Action for AI crawlers"
          options={AI_ACTIONS}
          value={action}
          onChange={(next) => {
            if (editable && next !== action) {
              change('crawlers.ai', next, `AI crawlers: ${next}`);
            }
          }}
        />
      </div>
      <div style={{ fontSize: 12.5, color: 'var(--color-text-2)' }}>
        {ACTION_TEXT[action]}
        {action === 'decoy'
          ? labyrinth
            ? ' The decoy is an endless maze of linked pages.'
            : ' Turn on decoy.labyrinth to make it an endless maze.'
          : ''}{' '}
        Rules and admin lists still win.
      </div>
      <Switch
        checked={robots}
        disabled={!editable}
        label="robots.txt for AI crawlers"
        onChange={(next) => {
          change(
            'crawlers.ai_robots',
            next,
            next
              ? 'AI crawlers now get Disallow: / in robots.txt'
              : 'AI crawlers get the site’s robots.txt again',
          );
        }}
      >
        <span style={{ fontSize: 12.5 }}>
          Answer <span className="mono">/robots.txt</span> to AI crawlers with{' '}
          <span className="mono">Disallow: /</span>; search engines and people
          get the site’s own.
        </span>
      </Switch>
      {!canOperate || !data.editable ? (
        <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
          {canOperate
            ? 'Read-only: the gateway has no admin.settings_file.'
            : 'Changing these needs the operator role.'}{' '}
          <Link to="/config">Configuration</Link> shows every setting.
        </div>
      ) : null}
    </section>
  );
}
