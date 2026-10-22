import { describe, expect, it } from 'vitest';

import { requestFilterSchema } from '../../shared/api.ts';
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
    ['ruleSamples', sql.ruleSamples(3600, 10, 200)],
  ])('%s filters on the column, not the ms alias', (_name, query) => {
    expect(query.sql).toContain('AS ts');
    const conditions = timeConditions(query);
    expect(conditions.length).toBeGreaterThan(0);
    expect(conditions.every((name) => name === 'req.ts')).toBe(true);
  });
});
