// The enforce-readiness verdict of a host from its report (shared/api.ts
// readinessSchema): too little traffic to tell, ready, or clients to look
// at first.

import type { Readiness, ReadinessEvidence } from '../../shared/api.ts';

export type ReadinessVerdict = 'thin' | 'ready' | 'review';

// Fewer requests than this in the window say too little.
export const kMinRequests = 200;

export function readinessVerdict(report: Readiness): ReadinessVerdict {
  if (report.requests < kMinRequests) return 'thin';
  return report.block.legit_clients === 0 ? 'ready' : 'review';
}

const plural = (n: number, word: string) =>
  `${n.toLocaleString('en-US')} ${word}${n === 1 ? '' : 's'}`;

export function readinessHeadline(report: Readiness): string {
  const enforcing = report.mode === 'enforce';
  switch (readinessVerdict(report)) {
    case 'thin':
      return `Too little traffic to tell: ${plural(report.requests, 'request')} in this window. Wait, or pick a longer one.`;
    case 'ready':
      return report.block.clients === 0
        ? `Enforce ${enforcing ? 'blocks' : 'would block'} nobody here.`
        : `None of the ${plural(report.block.clients, 'client')} enforce ${enforcing ? 'blocks' : 'would block'} looks legitimate.`;
    case 'review': {
      const one = report.block.legit_clients === 1;
      const verb = enforcing ? (one ? 'is' : 'are') : 'would be';
      return `${plural(report.block.legit_clients, 'client')} that ${one ? 'looks' : 'look'} legitimate ${verb} blocked. Check ${one ? 'it' : 'them'} before ${enforcing ? 'keeping' : 'switching to'} enforce.`;
    }
  }
}

export const EVIDENCE_TEXT: Record<ReadinessEvidence, string> = {
  passed_challenge: 'passed a challenge',
  verified_crawler: 'verified crawler',
  classed_human: 'classed human',
};
