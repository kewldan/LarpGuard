// Helpers several routes share.

import type { Context } from 'hono';

import type { AsnInfo } from '../../shared/api.ts';
import type { Analytics } from '../analytics/analytics.ts';
import type { AppEnv, Deps } from '../deps.ts';
import { fail } from '../http.ts';

export type Ctx = Context<AppEnv>;

export function analytics(deps: Deps): Analytics {
  if (deps.analytics === null) fail(503, 'ClickHouse is not configured');
  return deps.analytics;
}

// AS names from the gateway's ASN database; empty when it has none.
export async function asnNames(
  deps: Deps,
  numbers: number[],
): Promise<Map<number, AsnInfo>> {
  const unique = [...new Set(numbers.filter((n) => n > 0))].slice(0, 200);
  try {
    const infos = await deps.admin.asns(unique);
    return new Map(infos.map((info) => [info.asn, info]));
  } catch {
    return new Map();
  }
}

// Where an audit entry's actor comes from.
export function actor(c: Ctx): string {
  return c.get('session').user;
}

export function formatTtl(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
