// SQL for the analytics screens. Every value travels as a ClickHouse query
// parameter ({name:Type}); the only interpolated identifiers are the
// database name (checked against \w+ in the config) and a fingerprint
// column picked from a fixed list.

import type { FingerprintKind, RequestFilterParsed } from '../../shared/api.ts';
import {
  BLOCKING_ACTIONS,
  CHALLENGING_ACTIONS,
  RANGE_SECONDS,
  type Range,
} from '../../shared/domain.ts';

export interface Query {
  sql: string;
  params: Record<string, unknown>;
}

const list = (values: readonly string[]) =>
  values.map((value) => `'${value}'`).join(', ');

// Constant lists of action names (no user input).
const BLOCKED = `action IN (${list(BLOCKING_ACTIONS)})`;
const CHALLENGED = `action IN (${list(CHALLENGING_ACTIONS)})`;
const WOULD_BLOCK = `(would_action IN (${list(BLOCKING_ACTIONS)}) AND NOT ${BLOCKED})`;
// What enforce mode does: on a shadow host would_action, on an enforce
// host the same as action.
const ENFORCE_BLOCKS = `would_action IN (${list(BLOCKING_ACTIONS)})`;
const ENFORCE_CHALLENGES = `would_action IN (${list(CHALLENGING_ACTIONS)})`;
// Clients of the host that look legitimate anywhere in the window: they
// passed a challenge or are verified crawlers (CTE \`legit\`). A request
// looks legitimate when its client does or it was classed human.
const LEGIT_CLIENTS = `legit AS (
  SELECT ip_hash FROM {table}
  WHERE {where} AND ip_hash != ''
  GROUP BY ip_hash
  HAVING max(has(reasons, 'token_valid')) OR max(class = 'verified_bot'))`;
const LEGIT_REQUEST = `(class IN ('human', 'verified_bot') OR ip_hash IN legit)`;

export const TONE_COLUMNS = `countIf(${BLOCKED}) AS blocked,
  countIf(${CHALLENGED}) AS challenged,
  countIf(NOT ${BLOCKED} AND NOT ${CHALLENGED}) AS allowed,
  countIf(${WOULD_BLOCK}) AS would_block`;

const FINGERPRINT_COLUMNS: Record<FingerprintKind, string> = {
  ja4: 'ja4',
  h2_fp: 'h2_fp',
  header_fp: 'header_fp',
  tcp_fp: 'tcp_fp',
};

// Time conditions name the column as `req.ts`: ClickHouse substitutes
// SELECT aliases into WHERE, and the request queries return
// `toUnixTimestamp64Milli(ts) AS ts`, which a bare `ts` would then mean.
export function since(seconds: number): string {
  return `req.ts >= now64(3) - toIntervalSecond(${Math.trunc(seconds)})`;
}

export class Sql {
  private readonly table: string;

  constructor(database: string) {
    if (!/^\w+$/.test(database)) throw new Error('invalid database name');
    // The table is named `req`, which the time conditions rely on.
    this.table = `${database}.req`;
  }

  verdictSeries(range: Range, stepSeconds: number): Query {
    return {
      sql: `SELECT toUnixTimestamp(toStartOfInterval(ts, toIntervalSecond({step:UInt32}))) * 1000 AS t,
  ${TONE_COLUMNS}
FROM ${this.table}
WHERE ${since(RANGE_SECONDS[range])}
GROUP BY t ORDER BY t`,
      params: { step: stepSeconds },
    };
  }

  topHosts(range: Range, limit: number): Query {
    return {
      sql: `SELECT host, count() AS requests, ${TONE_COLUMNS}
FROM ${this.table}
WHERE ${since(RANGE_SECONDS[range])} AND host != ''
GROUP BY host ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { limit },
    };
  }

  hostSeries(range: Range, stepSeconds: number, hosts: string[]): Query {
    return {
      sql: `SELECT host, toUnixTimestamp(toStartOfInterval(ts, toIntervalSecond({step:UInt32}))) * 1000 AS t,
  count() AS requests
FROM ${this.table}
WHERE ${since(RANGE_SECONDS[range])} AND host IN {hosts:Array(String)}
GROUP BY host, t ORDER BY t`,
      params: { step: stepSeconds, hosts },
    };
  }

  // Signals of requests that were (or on shadow hosts would have been)
  // blocked.
  blockedReasons(range: Range, limit: number): Query {
    return {
      sql: `SELECT reason, count() AS requests
FROM ${this.table} ARRAY JOIN reasons AS reason
WHERE ${since(RANGE_SECONDS[range])} AND (${BLOCKED} OR ${WOULD_BLOCK})
GROUP BY reason ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { limit },
    };
  }

  topAsns(range: Range, limit: number): Query {
    return {
      sql: `SELECT asn, count() AS requests, countIf(${BLOCKED}) AS blocked,
  countIf(${CHALLENGED}) AS challenged
FROM ${this.table}
WHERE ${since(RANGE_SECONDS[range])} AND asn != 0
GROUP BY asn ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { limit },
    };
  }

  // verified_crawler:<id> and fake_crawler:<id> per crawler.
  crawlerCounts(seconds: number, limit: number): Query {
    return {
      sql: `SELECT substring(reason, position(reason, ':') + 1) AS id,
  countIf(startsWith(reason, 'verified_crawler:')) AS verified,
  countIf(startsWith(reason, 'fake_crawler:')) AS fake
FROM ${this.table} ARRAY JOIN reasons AS reason
WHERE ${since(seconds)}
  AND (startsWith(reason, 'verified_crawler:') OR startsWith(reason, 'fake_crawler:'))
GROUP BY id ORDER BY verified + fake DESC LIMIT {limit:UInt32}`,
      params: { limit },
    };
  }

  // Seconds since the newest event (NULL without events today).
  lag(): Query {
    return {
      sql: `SELECT if(count() = 0, NULL,
  toFloat64(dateDiff('millisecond', max(ts), now64(3))) / 1000) AS lag_s
FROM ${this.table}
WHERE ${since(86_400)}`,
      params: {},
    };
  }

  // Requests explorer. `except` leaves one dimension out (for its facet).
  private where(
    filter: RequestFilterParsed,
    except?: 'action' | 'class' | 'host',
    withCursor = false,
  ): { clause: string; params: Record<string, unknown> } {
    const parts = [since(RANGE_SECONDS[filter.range])];
    const params: Record<string, unknown> = {};
    if (filter.host?.length && except !== 'host') {
      parts.push('host IN {hosts:Array(String)}');
      params['hosts'] = filter.host;
    }
    if (filter.action?.length && except !== 'action') {
      parts.push('action IN {actions:Array(String)}');
      params['actions'] = filter.action;
    }
    if (filter.class?.length && except !== 'class') {
      parts.push('class IN {classes:Array(String)}');
      params['classes'] = filter.class;
    }
    if (filter.reason) {
      parts.push('has(reasons, {reason:String})');
      params['reason'] = filter.reason;
    }
    if (filter.asn !== undefined) {
      parts.push('asn = {asn:UInt32}');
      params['asn'] = filter.asn;
    }
    if (filter.ja4) {
      parts.push('startsWith(ja4, {ja4:String})');
      params['ja4'] = filter.ja4;
    }
    if (filter.ip_prefix) {
      parts.push('ip_prefix = {ip_prefix:String}');
      params['ip_prefix'] = filter.ip_prefix;
    }
    if (filter.ip_hash) {
      parts.push('startsWith(ip_hash, {ip_hash:String})');
      params['ip_hash'] = filter.ip_hash;
    }
    if (filter.path) {
      parts.push('startsWith(path_group, {path:String})');
      params['path'] = filter.path;
    }
    if (filter.min_score !== undefined) {
      parts.push('score >= {min_score:Int16}');
      params['min_score'] = filter.min_score;
    }
    if (filter.max_score !== undefined) {
      parts.push('score <= {max_score:Int16}');
      params['max_score'] = filter.max_score;
    }
    if (withCursor && filter.before !== undefined) {
      parts.push('req.ts < fromUnixTimestamp64Milli({before:Int64})');
      params['before'] = filter.before;
    }
    return { clause: parts.join('\n  AND '), params };
  }

  requestRows(filter: RequestFilterParsed): Query {
    const { clause, params } = this.where(filter, undefined, true);
    return {
      sql: `SELECT toUnixTimestamp64Milli(ts) AS ts, request_id, host, method,
  path_group, ip_prefix, ip_hash, asn, score, class, reasons, action,
  would_action, status, ja4, user_agent
FROM ${this.table}
WHERE ${clause}
ORDER BY req.ts DESC LIMIT {limit:UInt32}`,
      params: { ...params, limit: filter.limit },
    };
  }

  requestCount(filter: RequestFilterParsed): Query {
    const { clause, params } = this.where(filter);
    return {
      sql: `SELECT count() AS total FROM ${this.table} WHERE ${clause}`,
      params,
    };
  }

  requestFacet(
    filter: RequestFilterParsed,
    dimension: 'action' | 'class' | 'host',
  ): Query {
    const { clause, params } = this.where(filter, dimension);
    return {
      sql: `SELECT ${dimension} AS value, count() AS requests
FROM ${this.table}
WHERE ${clause}
GROUP BY value ORDER BY requests DESC LIMIT 20`,
      params,
    };
  }

  // One request by id; `ts` narrows the scan to its partition.
  requestDetail(requestId: string, ts: number): Query {
    return {
      sql: `SELECT toUnixTimestamp64Milli(ts) AS ts, request_id, host, method,
  path_group, ip_prefix, ip_hash, asn, score, class, reasons, action,
  would_action, status, ja4, user_agent, http_version, sni, header_fp,
  header_names, pseudo_order, h2_fp, tcp_fp, ja4h, accept_language,
  sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile, sec_fetch_mode,
  sec_fetch_site, rate_limit, duration_ms, local, signed_agent, client_fp,
  model_score, tcp_rtt_us, handshake_us
FROM ${this.table}
WHERE req.ts BETWEEN fromUnixTimestamp64Milli({from:Int64}) AND fromUnixTimestamp64Milli({to:Int64})
  AND request_id = {id:String}
LIMIT 1`,
      params: { id: requestId, from: ts - 60_000, to: ts + 60_000 },
    };
  }

  fingerprints(kind: FingerprintKind, q: string | undefined): Query {
    const column = FINGERPRINT_COLUMNS[kind];
    return {
      sql: `SELECT ${column} AS value, count() AS requests,
  uniq(ip_hash) AS clients, ${TONE_COLUMNS},
  quantileExact(0.5)(score) AS median_score,
  toUnixTimestamp64Milli(min(ts)) AS first_seen,
  toUnixTimestamp64Milli(max(ts)) AS last_seen,
  any(user_agent) AS ua_sample
FROM ${this.table}
WHERE ${since(86_400)} AND ${column} != ''
  ${q ? `AND positionCaseInsensitive(${column}, {q:String}) > 0` : ''}
GROUP BY value ORDER BY requests DESC LIMIT 100`,
      params: q ? { q } : {},
    };
  }

  fingerprintHourly(kind: FingerprintKind, values: string[]): Query {
    const column = FINGERPRINT_COLUMNS[kind];
    return {
      sql: `SELECT ${column} AS value,
  toUnixTimestamp(toStartOfHour(ts)) * 1000 AS t, count() AS requests
FROM ${this.table}
WHERE ${since(86_400)} AND ${column} IN {values:Array(String)}
GROUP BY value, t`,
      params: { values },
    };
  }

  fingerprintKinds(): Query {
    return {
      sql: `SELECT uniq(ja4) AS ja4, uniq(h2_fp) AS h2_fp,
  uniq(header_fp) AS header_fp, uniq(tcp_fp) AS tcp_fp
FROM ${this.table} WHERE ${since(86_400)}`,
      params: {},
    };
  }

  // Requests per "<prefix>:<name>" reason, e.g. rule:, list:, signed_agent:.
  reasonCounts(prefix: string, seconds: number): Query {
    return {
      sql: `SELECT substring(reason, length({prefix:String}) + 1) AS name,
  count() AS requests
FROM ${this.table} ARRAY JOIN reasons AS reason
WHERE ${since(seconds)} AND startsWith(reason, {prefix:String})
GROUP BY name ORDER BY requests DESC LIMIT 500`,
      params: { prefix },
    };
  }

  totalSince(seconds: number): Query {
    return {
      sql: `SELECT count() AS total FROM ${this.table} WHERE ${since(seconds)}`,
      params: {},
    };
  }

  // About `target` events of the last `seconds`, spread evenly (a hash
  // filter instead of ORDER BY rand(), which would sort the whole range).
  ruleSamples(seconds: number, modulo: number, target: number): Query {
    return {
      sql: `SELECT toUnixTimestamp64Milli(ts) AS ts, host, method,
  path_group AS path, http_version, sni, ja4, h2_fp, pseudo_order,
  header_fp, tcp_fp, user_agent, score, class, reasons, asn, signed_agent,
  ip_prefix, action, would_action, tcp_rtt_us, handshake_us
FROM ${this.table}
WHERE ${since(seconds)}
  AND cityHash64(request_id, conn_id, seq) % {modulo:UInt64} = 0
LIMIT {target:UInt32}`,
      params: { modulo, target },
    };
  }

  refusedByLimit(seconds: number): Query {
    return {
      sql: `SELECT rate_limit AS name, count() AS requests
FROM ${this.table}
WHERE ${since(seconds)} AND rate_limit != ''
GROUP BY name`,
      params: {},
    };
  }

  consumers(seconds: number, limit: number): Query {
    return {
      sql: `SELECT ip_prefix, uniq(ip_hash) AS ip_hash_count,
  topK(1)(host)[1] AS host, count() / {seconds:Float64} AS rps,
  countIf(rate_limit != '') AS refused
FROM ${this.table}
WHERE ${since(seconds)} AND ip_prefix != ''
GROUP BY ip_prefix ORDER BY rps DESC LIMIT {limit:UInt32}`,
      params: { seconds, limit },
    };
  }

  hostStats(seconds: number): Query {
    return {
      sql: `SELECT host, count() AS requests, ${TONE_COLUMNS}
FROM ${this.table}
WHERE ${since(seconds)} AND host != ''
GROUP BY host ORDER BY requests DESC LIMIT 500`,
      params: {},
    };
  }

  impostors(seconds: number, limit: number): Query {
    return {
      sql: `SELECT substring(reason, length('fake_crawler:') + 1) AS crawler,
  ip_prefix, any(asn) AS asn, count() AS requests, any(action) AS action,
  toUnixTimestamp64Milli(max(ts)) AS last_seen
FROM ${this.table} ARRAY JOIN reasons AS reason
WHERE ${since(seconds)} AND startsWith(reason, 'fake_crawler:')
GROUP BY crawler, ip_prefix ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { limit },
    };
  }

  busiestHost(seconds: number): Query {
    return {
      sql: `SELECT host, count() / {seconds:Float64} AS rps
FROM ${this.table}
WHERE ${since(seconds)} AND host != ''
GROUP BY host ORDER BY rps DESC LIMIT 1`,
      params: { seconds },
    };
  }

  // What attack mode would leave alone: clients with a clearance token,
  // verified bots and allow-listed clients.
  attackImpact(seconds: number): Query {
    return {
      sql: `SELECT count() AS requests,
  countIf(has(reasons, 'token_valid')) AS token,
  countIf(NOT has(reasons, 'token_valid') AND (class = 'verified_bot'
    OR arrayExists(r -> startsWith(r, 'list:'), reasons))) AS verified_or_listed
FROM ${this.table}
WHERE ${since(seconds)}`,
      params: {},
    };
  }

  // Enforce readiness of one host (shared/api.ts readinessSchema).
  private legitClients(where: string): string {
    return LEGIT_CLIENTS.replace('{table}', this.table).replace(
      '{where}',
      where,
    );
  }

  readinessSummary(host: string, seconds: number): Query {
    const where = `${since(seconds)} AND host = {host:String}`;
    return {
      sql: `WITH ${this.legitClients(where)}
SELECT count() AS requests, uniq(ip_hash) AS clients,
  countIf(${ENFORCE_BLOCKS}) AS block_requests,
  uniqIf(ip_hash, ${ENFORCE_BLOCKS}) AS block_clients,
  countIf(${ENFORCE_BLOCKS} AND ${LEGIT_REQUEST}) AS legit_requests,
  uniqIf(ip_hash, ${ENFORCE_BLOCKS} AND ${LEGIT_REQUEST}) AS legit_clients,
  countIf(${ENFORCE_CHALLENGES}) AS challenge_requests,
  uniqIf(ip_hash, ${ENFORCE_CHALLENGES}) AS challenge_clients
FROM ${this.table}
WHERE ${where}`,
      params: { host },
    };
  }

  readinessReasons(host: string, seconds: number, limit: number): Query {
    const where = `${since(seconds)} AND host = {host:String}`;
    return {
      sql: `WITH ${this.legitClients(where)}
SELECT reason, count() AS requests, uniq(ip_hash) AS clients,
  uniqIf(ip_hash, ${LEGIT_REQUEST}) AS legit_clients
FROM ${this.table} ARRAY JOIN reasons AS reason
WHERE ${where} AND ${ENFORCE_BLOCKS}
GROUP BY reason ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { host, limit },
    };
  }

  readinessSuspects(host: string, seconds: number, limit: number): Query {
    return {
      sql: `SELECT ip_hash, any(ip_prefix) AS ip_prefix, any(asn) AS asn,
  anyIf(user_agent, ${ENFORCE_BLOCKS}) AS user_agent,
  countIf(${ENFORCE_BLOCKS}) AS requests,
  groupUniqArrayArrayIf(6)(reasons, ${ENFORCE_BLOCKS}) AS block_reasons,
  max(has(reasons, 'token_valid')) AS passed_challenge,
  max(class = 'verified_bot') AS verified_crawler,
  maxIf(class = 'human', ${ENFORCE_BLOCKS}) AS classed_human,
  toUnixTimestamp64Milli(maxIf(ts, ${ENFORCE_BLOCKS})) AS last_seen
FROM ${this.table}
WHERE ${since(seconds)} AND host = {host:String} AND ip_hash != ''
GROUP BY ip_hash
HAVING requests > 0 AND (passed_challenge OR verified_crawler OR classed_human)
ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { host, limit },
    };
  }

  hostsLike(q: string, limit: number): Query {
    return {
      sql: `SELECT host, count() AS requests
FROM ${this.table}
WHERE ${since(86_400)} AND positionCaseInsensitive(host, {q:String}) > 0
GROUP BY host ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { q, limit },
    };
  }

  ja4Like(q: string, limit: number): Query {
    return {
      sql: `SELECT ja4 AS value, count() AS requests
FROM ${this.table}
WHERE ${since(86_400)} AND startsWith(ja4, {q:String})
GROUP BY value ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { q, limit },
    };
  }

  ipLike(column: 'ip_prefix' | 'ip_hash', q: string, limit: number): Query {
    return {
      sql: `SELECT ${column} AS value, count() AS requests, any(asn) AS asn
FROM ${this.table}
WHERE ${since(86_400)} AND startsWith(${column}, {q:String})
GROUP BY value ORDER BY requests DESC LIMIT {limit:UInt32}`,
      params: { q, limit },
    };
  }
}
