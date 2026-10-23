import { describe, expect, it } from 'vitest';

import type { Readiness } from '../../shared/api.ts';
import { readinessHeadline, readinessVerdict } from './readiness.ts';

function report(over: Partial<Readiness> = {}): Readiness {
  return {
    host: 'a.example',
    mode: 'shadow',
    range: '24h',
    requests: 5000,
    clients: 400,
    block: { requests: 300, clients: 20, legit_requests: 0, legit_clients: 0 },
    challenge: { requests: 100, clients: 10 },
    reasons: [],
    suspects: [],
    ...over,
  };
}

describe('enforce readiness', () => {
  it('needs enough traffic to judge', () => {
    expect(readinessVerdict(report({ requests: 50 }))).toBe('thin');
    expect(readinessHeadline(report({ requests: 1 }))).toMatch(
      /^Too little traffic to tell: 1 request in/,
    );
  });

  it('is ready when no blocked client looks legitimate', () => {
    expect(readinessVerdict(report())).toBe('ready');
    expect(readinessHeadline(report())).toBe(
      'None of the 20 clients enforce would block looks legitimate.',
    );
    const none = report({
      block: { requests: 0, clients: 0, legit_requests: 0, legit_clients: 0 },
    });
    expect(readinessHeadline(none)).toBe('Enforce would block nobody here.');
  });

  it('asks for a review of legitimate-looking clients', () => {
    const one = report({
      block: {
        requests: 300,
        clients: 20,
        legit_requests: 4,
        legit_clients: 1,
      },
    });
    expect(readinessVerdict(one)).toBe('review');
    expect(readinessHeadline(one)).toBe(
      '1 client that looks legitimate would be blocked. Check it before switching to enforce.',
    );
    expect(readinessHeadline({ ...one, mode: 'enforce' })).toMatch(
      /^1 client that looks legitimate is blocked\. Check it before keeping/,
    );
  });
});
