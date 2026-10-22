import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { ScoreCell } from './ScoreBar.tsx';
import styles from './verdict.module.css';
import { ActionChip, ClassBadge, ModeBadge } from './verdict.tsx';

describe('verdict primitives', () => {
  it('folds actions into tones', () => {
    const { rerender } = render(<ActionChip action="block" />);
    expect(screen.getByText('block')).toHaveClass(styles.block ?? '');
    rerender(<ActionChip action="tarpit" />);
    expect(screen.getByText('tarpit')).toHaveClass(styles.degrade ?? '');
    rerender(<ActionChip action="captcha" />);
    expect(screen.getByText('captcha')).toHaveClass(styles.challenge ?? '');
    rerender(<ActionChip action="" />);
    expect(screen.getByText('allow')).toHaveClass(styles.allow ?? '');
  });

  it('labels classes and modes', () => {
    render(
      <>
        <ClassBadge value="verified_bot" />
        <ModeBadge mode="shadow" />
      </>,
    );
    expect(screen.getByText('verified_bot')).toHaveClass(
      styles.verified_bot ?? '',
    );
    expect(screen.getByText('SHADOW')).toHaveClass('hatch');
  });

  it('clamps the score meter', () => {
    render(<ScoreCell score={140} />);
    expect(screen.getByRole('meter', { name: 'Score' })).toHaveAttribute(
      'aria-valuenow',
      '100',
    );
  });
});
