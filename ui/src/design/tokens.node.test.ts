import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import { color, scoreThreshold, scoreTone } from './tokens.ts';
import { kebab, renderTokensCss } from './tokens-css.ts';

describe('tokens', () => {
  it('tokens.css is generated from tokens.ts (run npm run tokens)', () => {
    const css = readFileSync(
      join(process.cwd(), 'src/design/tokens.css'),
      'utf8',
    );
    expect(css).toBe(renderTokensCss());
  });

  it('keeps the design values of the verdict colors', () => {
    expect(color.blocked).toEqual({ dark: '#ff5e1f', light: '#ff5e1f' });
    expect(color.challenged).toEqual({ dark: '#f5b301', light: '#ffac00' });
    expect(color.allowed).toEqual({ dark: '#5c5c5c', light: '#cfcfcf' });
    expect(color.verified).toEqual({ dark: '#7b9cff', light: '#3557d6' });
    expect(color.healthy).toEqual({ dark: '#2fb8a6', light: '#058378' });
  });

  it('maps scores to tones at the thresholds', () => {
    expect(scoreThreshold).toEqual({ challenge: 40, block: 70 });
    expect(scoreTone(0)).toBe('allowed');
    expect(scoreTone(39)).toBe('allowed');
    expect(scoreTone(40)).toBe('challenged');
    expect(scoreTone(69)).toBe('challenged');
    expect(scoreTone(70)).toBe('blocked');
    expect(scoreTone(100)).toBe('blocked');
    expect(scoreTone(35, { challenge: 30, block: 70 })).toBe('challenged');
  });

  it('names custom properties in kebab case', () => {
    expect(kebab('surface1')).toBe('surface-1');
    expect(kebab('onBlockedChip')).toBe('on-blocked-chip');
    expect(kebab('2xl')).toBe('2xl');
    expect(kebab('md+')).toBe('md-plus');
    expect(kebab('1.5')).toBe('1_5');
  });
});
