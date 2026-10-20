// Score tones as colors.

import { scoreTone, type Tone } from '../design/tokens.ts';

export interface Thresholds {
  challenge: number;
  block: number;
}

export const TONE_TEXT: Record<Tone, string> = {
  allowed: 'var(--color-allowed-text)',
  challenged: 'var(--color-challenged-text)',
  blocked: 'var(--color-blocked-text)',
};

export function toneText(score: number, thresholds?: Thresholds): string {
  return TONE_TEXT[scoreTone(score, thresholds)];
}
