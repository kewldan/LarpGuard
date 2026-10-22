import { describe, expect, it } from 'vitest';

import type { SettingKey } from '../../shared/api.ts';
import {
  fromText,
  matchKeys,
  sectionOf,
  shortName,
  toChange,
  toText,
  withReset,
  withValue,
} from './settings.ts';

const rounds: SettingKey = {
  path: 'captcha.rounds',
  type: 'int',
  apply: 'restart',
  source: 'default',
  pending_restart: false,
  secret: false,
  value: 2,
  default: 2,
};
const secret: SettingKey = {
  path: 'captcha.secret',
  type: 'string',
  apply: 'restart',
  source: 'default',
  pending_restart: false,
  secret: true,
  set: false,
};

describe('settings', () => {
  it('puts keys in their sections', () => {
    expect(sectionOf('captcha.rounds').id).toBe('captcha');
    expect(sectionOf('mode').id).toBe('policy');
    expect(sectionOf('policy.thresholds.bot').id).toBe('policy');
    expect(sectionOf('log_level').id).toBe('admin');
    expect(sectionOf('brand_new.key').id).toBe('other');
    expect(shortName('challenge.difficulty.bot')).toBe('difficulty.bot');
    expect(shortName('workers')).toBe('workers');
  });

  it('turns values into text and back', () => {
    expect(fromText('int', ' 12 ')).toEqual({ value: 12 });
    expect(fromText('int', '1.5')).toEqual({ error: 'expected an integer' });
    expect(fromText('number', '0.65')).toEqual({ value: 0.65 });
    expect(fromText('strings', '/a\n\n /b ')).toEqual({ value: ['/a', '/b'] });
    expect(toText('strings', ['/a', '/b'])).toBe('/a\n/b');
    expect(fromText('host_modes', 'a.test: enforce\n*.b.test: off')).toEqual({
      value: { 'a.test': 'enforce', '*.b.test': 'off' },
    });
    expect(fromText('host_modes', 'a.test')).toHaveProperty('error');
    expect(toText('host_modes', { 'a.test': 'shadow' })).toBe('a.test: shadow');
    expect(fromText('throttle', '')).toEqual({ value: null });
    expect(fromText('rules', '[{"name": "x"}]')).toEqual({
      value: [{ name: 'x' }],
    });
    expect(fromText('rules', '[{')).toHaveProperty('error');
    expect(fromText('duration', '30s')).toEqual({ value: '30s' });
  });

  it('keeps only real changes in the draft and builds the request', () => {
    let draft = withValue(new Map(), rounds, 3, '3');
    expect(draft.size).toBe(1);
    draft = withValue(draft, rounds, 2, '2');
    expect(draft.size).toBe(0);
    // A secret is always a change: its value is unknown here.
    draft = withValue(draft, secret, 's3cret');
    draft = withReset(draft, 'captcha.difficulty');
    expect(toChange(draft, 'r1')).toEqual({
      change: {
        base_revision: 'r1',
        set: { 'captcha.secret': 's3cret' },
        reset: ['captcha.difficulty'],
      },
    });
    draft = withValue(draft, rounds, 2, '2.5', 'expected an integer');
    expect(toChange(draft, 'r1')).toEqual({
      path: 'captcha.rounds',
      error: 'expected an integer',
    });
  });

  it('finds keys for the command palette', () => {
    expect(matchKeys([rounds, secret], 'c')).toEqual([]);
    expect(matchKeys([rounds, secret], 'ROUND')).toEqual([rounds]);
  });
});
