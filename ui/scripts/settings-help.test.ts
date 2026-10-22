import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { MOCK_KEYS } from '../server/dev/mock-settings.ts';
import { SETTINGS_HELP } from '../shared/settings-help.ts';
import {
  extractSettingsHelp,
  helpFor,
  renderSettingsHelp,
} from './settings-help.ts';

const read = (path: string) =>
  readFileSync(fileURLToPath(new URL(path, import.meta.url)), 'utf8');

describe('settings help', () => {
  it('is generated from the current deploy/bot-shield.yaml', () => {
    expect(read('../shared/settings-help.ts')).toBe(
      renderSettingsHelp(
        extractSettingsHelp(read('../../deploy/bot-shield.yaml')),
      ),
    );
  });

  it('only describes keys and sections that exist', () => {
    const known = new Set<string>();
    for (const { path } of MOCK_KEYS) {
      const parts = path.split('.');
      for (let i = 1; i <= parts.length; i += 1) {
        known.add(parts.slice(0, i).join('.'));
      }
    }
    for (const path of Object.keys(SETTINGS_HELP)) {
      expect(known, path).toContain(path);
    }
  });

  it('reads blocks, line ends and sections, and skips examples', () => {
    const help = extractSettingsHelp(
      [
        '# The section.',
        'events:',
        '  # Where events go.',
        '  nats: ""   # "" disables',
        '  # nats: "nats://127.0.0.1:4222"',
        '  token: ""',
        '',
        '# A limit for throttled requests.',
        '# throttle:',
        '#   rate: 30/m',
        '',
        'rules: []',
        '#  - name: x',
      ].join('\n'),
    );
    expect(help).toEqual({
      events: 'The section.',
      'events.nats': 'Where events go. "" disables',
      throttle: 'A limit for throttled requests.',
    });
    expect(helpFor(help, 'events.token')).toBe('The section.');
    expect(helpFor(help, 'rules')).toBeUndefined();
  });
});
