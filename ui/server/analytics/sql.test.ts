import { describe, expect, it } from 'vitest';

import { requestFilterSchema } from '../../shared/api.ts';
import { challengeStep, createAnalytics } from './analytics.ts';
import { type Query, Sql } from './sql.ts';

const sql = new Sql('bot_shield');
const filter = requestFilterSchema.parse({ range: '1h', before: '1000' });

// The request queries return `toUnixTimestamp64Milli(ts) AS ts`, and
// ClickHouse substitutes SELECT aliases into WHERE: a bare `ts` there would
// compare milliseconds with a DateTime64 and match every row (or none).
function timeConditions(query: Query): string[] {
  const where = query.sql.slice(query.sql.indexOf('WHERE'));
  return [...where.matchAll(/(?<![\w.(])(?:req\.)?ts\b(?!\))/g)].map(
    (match) => match[0],
  );
}

describe('Sql', () => {
  it.each([
    ['requestRows', sql.requestRows(filter)],
    ['requestDetail', sql.requestDetail('abc-1-2', 1_000_000)],
    ['challengeHistory', sql.challengeHistory('a1b2', 1_000_000_000)],
    ['ruleSamples', sql.ruleSamples(3600, 10, 200)],
  ])('%s filters on the column, not the ms alias', (_name, query) => {
    expect(query.sql).toContain('AS ts');
    const conditions = timeConditions(query);
    expect(conditions.length).toBeGreaterThan(0);
    expect(conditions.every((name) => name === 'req.ts')).toBe(true);
  });

  it('keeps readiness aliases off the columns they aggregate', () => {
    // An alias named like a column replaces it everywhere in the query
    // (has(reasons, ...) would then aggregate an aggregate).
    for (const query of [
      sql.readinessSummary('a.example', 86_400),
      sql.readinessReasons('a.example', 86_400, 15),
      sql.readinessSuspects('a.example', 86_400, 20),
    ]) {
      expect(query.sql).not.toMatch(/\bAS (reasons|class|ip_hash|ts)\b/);
      expect(query.params).toMatchObject({ host: 'a.example' });
      expect(timeConditions(query).every((name) => name === 'req.ts')).toBe(
        true,
      );
    }
  });
});

describe('readiness from ClickHouse rows', () => {
  it('turns flags into evidence and fills an empty summary', async () => {
    const analytics = createAnalytics('bot_shield', (query, row) => {
      const rows = query.sql.includes('block_reasons')
        ? [
            {
              ip_hash: 'ab12',
              ip_prefix: '198.51.100.0/24',
              asn: '64496',
              user_agent: 'Mozilla/5.0',
              requests: '4',
              block_reasons: ['hosting_network'],
              passed_challenge: 1,
              verified_crawler: 0,
              classed_human: 1,
              last_seen: '1000',
            },
          ]
        : [];
      return Promise.resolve(rows.map((value) => row.parse(value)));
    });
    const report = await analytics.readiness('a.example', 3600);
    expect(report.requests).toBe(0);
    expect(report.block).toEqual({
      requests: 0,
      clients: 0,
      legit_requests: 0,
      legit_clients: 0,
    });
    expect(report.suspects).toEqual([
      {
        ip_hash: 'ab12',
        ip_prefix: '198.51.100.0/24',
        asn: 64496,
        user_agent: 'Mozilla/5.0',
        requests: 4,
        reasons: ['hosting_network'],
        evidence: ['passed_challenge', 'classed_human'],
        last_seen: 1000,
      },
    ]);
  });
});

describe('challengeStep', () => {
  const event = (action: string, reasons: string[]) => ({
    ts: 1,
    request_id: 'r',
    host: 'a.example',
    path_group: '/__bs/verify',
    action,
    reasons,
  });

  it('reads the page served and the answer', () => {
    expect(challengeStep(event('challenge', ['bot_score']))?.step).toBe(
      'challenge',
    );
    expect(challengeStep(event('captcha', []))?.step).toBe('captcha');
    expect(challengeStep(event('allow', ['challenge:passed']))?.step).toBe(
      'passed',
    );
    expect(
      challengeStep(event('block', ['challenge:failed:webdriver'])),
    ).toMatchObject({ step: 'failed', detail: 'webdriver' });
    expect(
      challengeStep(event('allow', ['challenge:escalated:captcha'])),
    ).toMatchObject({ step: 'escalated', detail: 'captcha' });
    expect(challengeStep(event('allow', ['captcha:passed']))?.step).toBe(
      'captcha_passed',
    );
    expect(
      challengeStep(event('block', ['captcha:failed:timeout'])),
    ).toMatchObject({ step: 'captcha_failed', detail: 'timeout' });
    expect(challengeStep(event('allow', ['token_valid']))).toBeNull();
  });
});
