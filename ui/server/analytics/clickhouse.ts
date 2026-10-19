// Runs analytics queries on ClickHouse over HTTP. The user should be
// read-only with readonly = 2 (read queries, but settings such as
// max_execution_time may be set per query): see deploy/console.yaml.

import { readFileSync } from 'node:fs';

import { createClient } from '@clickhouse/client';
import { z } from 'zod';

import type { Run } from './analytics.ts';

export class AnalyticsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AnalyticsError';
  }
}

export interface ClickHouseOptions {
  url: string;
  user: string;
  password_file?: string | undefined;
}

export function createClickHouseRun(options: ClickHouseOptions): {
  run: Run;
  close: () => Promise<void>;
} {
  const password =
    options.password_file === undefined
      ? ''
      : readFileSync(options.password_file, 'utf8').trim();
  const client = createClient({
    url: options.url,
    username: options.user,
    password,
    request_timeout: 20_000,
    clickhouse_settings: {
      max_execution_time: 15,
      max_result_rows: '100000',
      result_overflow_mode: 'break',
      output_format_json_quote_64bit_integers: 0,
    },
  });
  const run: Run = async (query, row) => {
    let data: unknown;
    try {
      const result = await client.query({
        query: query.sql,
        query_params: query.params,
        format: 'JSONEachRow',
      });
      data = await result.json();
    } catch (error) {
      throw new AnalyticsError(
        `ClickHouse: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const parsed = z.array(row).safeParse(data);
    if (!parsed.success) {
      throw new AnalyticsError(
        `ClickHouse: unexpected rows (${parsed.error.issues[0]?.message ?? 'invalid'})`,
      );
    }
    return parsed.data;
  };
  return { run, close: () => client.close() };
}
