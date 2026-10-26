// Analytics over synthetic events in memory, for development and browser
// tests: the same interface as ClickHouse, answered by scanning arrays.

import type { RequestFilterParsed } from '../../shared/api.ts';
import {
  type Action,
  BLOCKING_ACTIONS,
  CHALLENGING_ACTIONS,
  RANGE_SECONDS,
  RANGE_STEP_SECONDS,
} from '../../shared/domain.ts';
import {
  type Analytics,
  bucketStarts,
  challengeStep,
  fillSeries,
  type HostCounts,
} from '../analytics/analytics.ts';
import type { MockEvent } from './mock-data.ts';

const blocked = (e: MockEvent) => BLOCKING_ACTIONS.includes(e.action as Action);
const challenged = (e: MockEvent) =>
  CHALLENGING_ACTIONS.includes(e.action as Action);
const enforceBlocks = (e: MockEvent) =>
  BLOCKING_ACTIONS.includes(e.would_action as Action);
const enforceChallenges = (e: MockEvent) =>
  CHALLENGING_ACTIONS.includes(e.would_action as Action);
const wouldBlock = (e: MockEvent) =>
  BLOCKING_ACTIONS.includes(e.would_action as Action) && !blocked(e);

function counts(events: MockEvent[]) {
  let b = 0;
  let c = 0;
  let w = 0;
  for (const e of events) {
    if (blocked(e)) b += 1;
    else if (challenged(e)) c += 1;
    if (wouldBlock(e)) w += 1;
  }
  return {
    requests: events.length,
    blocked: b,
    challenged: c,
    allowed: events.length - b - c,
    would_block: w,
  };
}

function groupBy<K>(events: MockEvent[], key: (e: MockEvent) => K) {
  const groups = new Map<K, MockEvent[]>();
  for (const e of events) {
    const k = key(e);
    const group = groups.get(k);
    if (group) group.push(e);
    else groups.set(k, [e]);
  }
  return groups;
}

function top<T>(items: T[], by: (item: T) => number, limit: number): T[] {
  return items.sort((a, b) => by(b) - by(a)).slice(0, limit);
}

export function createMockAnalytics(
  events: MockEvent[],
  now: () => number,
): Analytics {
  const since = (seconds: number) => {
    const from = now() - seconds * 1000;
    // Events are sorted by time: binary search the start.
    let lo = 0;
    let hi = events.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if ((events[mid]?.ts ?? 0) < from) lo = mid + 1;
      else hi = mid;
    }
    return events.slice(lo);
  };
  const reasonCounts = (list: MockEvent[], prefix: string) => {
    const map = new Map<string, number>();
    for (const e of list) {
      for (const reason of e.reasons) {
        if (reason.startsWith(prefix)) {
          const name = reason.slice(prefix.length);
          map.set(name, (map.get(name) ?? 0) + 1);
        }
      }
    }
    return map;
  };
  const filtered = (
    filter: RequestFilterParsed,
    except?: 'action' | 'class' | 'host',
  ) =>
    since(RANGE_SECONDS[filter.range]).filter(
      (e) =>
        (!filter.host?.length ||
          except === 'host' ||
          filter.host.includes(e.host)) &&
        (!filter.action?.length ||
          except === 'action' ||
          (filter.action as string[]).includes(e.action)) &&
        (!filter.class?.length ||
          except === 'class' ||
          (filter.class as string[]).includes(e.class)) &&
        (!filter.reason || e.reasons.includes(filter.reason)) &&
        (filter.asn === undefined || e.asn === filter.asn) &&
        (!filter.ja4 || e.ja4.startsWith(filter.ja4)) &&
        (!filter.ip_prefix || e.ip_prefix === filter.ip_prefix) &&
        (!filter.ip_hash || e.ip_hash.startsWith(filter.ip_hash)) &&
        (!filter.path || e.path_group.startsWith(filter.path)) &&
        (filter.min_score === undefined || e.score >= filter.min_score) &&
        (filter.max_score === undefined || e.score <= filter.max_score),
    );
  const facet = (list: MockEvent[], key: (e: MockEvent) => string) =>
    top(
      [...groupBy(list, key)].map(([value, group]) => ({
        value,
        requests: group.length,
      })),
      (row) => row.requests,
      20,
    );
  const hostCounts = (list: MockEvent[]): HostCounts[] =>
    [...groupBy(list, (e) => e.host)].map(([host, group]) => ({
      host,
      ...counts(group),
    }));

  return {
    verdictSeries(range) {
      const step = RANGE_STEP_SECONDS[range] * 1000;
      const rows = [
        ...groupBy(
          since(RANGE_SECONDS[range]),
          (e) => Math.floor(e.ts / step) * step,
        ),
      ].map(([t, group]) => ({ t, ...counts(group) }));
      return Promise.resolve(fillSeries(rows, range, now()));
    },
    topHosts(range, limit) {
      const list = since(RANGE_SECONDS[range]);
      const step = RANGE_STEP_SECONDS[range];
      const starts = bucketStarts(range, now());
      return Promise.resolve(
        top(hostCounts(list), (row) => row.requests, limit).map((row) => {
          const buckets = groupBy(
            list.filter((e) => e.host === row.host),
            (e) => Math.floor(e.ts / (step * 1000)) * step * 1000,
          );
          return {
            ...row,
            spark: starts.map((t) => (buckets.get(t)?.length ?? 0) / step),
          };
        }),
      );
    },
    blockedReasons(range) {
      const map = reasonCounts(
        since(RANGE_SECONDS[range]).filter((e) => blocked(e) || wouldBlock(e)),
        '',
      );
      return Promise.resolve(
        top(
          [...map].map(([reason, requests]) => ({ reason, requests })),
          (row) => row.requests,
          8,
        ),
      );
    },
    topAsns(range) {
      return Promise.resolve(
        top(
          [
            ...groupBy(
              since(RANGE_SECONDS[range]).filter((e) => e.asn !== 0),
              (e) => e.asn,
            ),
          ].map(([asn, group]) => {
            const c = counts(group);
            return {
              asn,
              requests: c.requests,
              blocked: c.blocked,
              challenged: c.challenged,
            };
          }),
          (row) => row.requests,
          6,
        ),
      );
    },
    crawlerCounts(seconds) {
      const list = since(seconds);
      const verified = reasonCounts(list, 'verified_crawler:');
      const fake = reasonCounts(list, 'fake_crawler:');
      const ids = new Set([...verified.keys(), ...fake.keys()]);
      return Promise.resolve(
        [...ids].map((id) => ({
          id,
          verified: verified.get(id) ?? 0,
          fake: fake.get(id) ?? 0,
        })),
      );
    },
    lag() {
      const last = events[events.length - 1];
      return Promise.resolve(last ? (now() - last.ts) / 1000 : null);
    },
    requests(filter) {
      const all = filtered(filter);
      const page = all
        .filter((e) => filter.before === undefined || e.ts < filter.before)
        .slice(-filter.limit)
        .reverse();
      return Promise.resolve({
        rows: page,
        total: all.length,
        facets: {
          action: facet(filtered(filter, 'action'), (e) => e.action),
          class: facet(filtered(filter, 'class'), (e) => e.class),
          host: facet(filtered(filter, 'host'), (e) => e.host),
        },
      });
    },
    request(requestId) {
      return Promise.resolve(
        events.find((e) => e.request_id === requestId) ?? null,
      );
    },
    challengeHistory(ipHash, ts) {
      return Promise.resolve(
        events
          .filter(
            (e) =>
              e.ip_hash === ipHash &&
              e.ts >= ts - 86_400_000 &&
              e.ts <= ts + 3_600_000,
          )
          .flatMap((e) => challengeStep(e) ?? [])
          .reverse()
          .slice(0, 50),
      );
    },
    fingerprints(kind, q) {
      const list = since(86_400).filter((e) => e[kind] !== '');
      const hourMs = 3_600_000;
      const lastHour = Math.floor(now() / hourMs) * hourMs;
      const rows = [...groupBy(list, (e) => e[kind])]
        .filter(
          ([value]) => !q || value.toLowerCase().includes(q.toLowerCase()),
        )
        .map(([value, group]) => {
          const c = counts(group);
          const scores = group.map((e) => e.score).sort((a, b) => a - b);
          const hours = groupBy(
            group,
            (e) => Math.floor(e.ts / hourMs) * hourMs,
          );
          return {
            value,
            requests: c.requests,
            clients: new Set(group.map((e) => e.ip_hash)).size,
            hourly: Array.from(
              { length: 24 },
              (_, i) => hours.get(lastHour - (23 - i) * hourMs)?.length ?? 0,
            ),
            allowed: c.allowed,
            challenged: c.challenged,
            blocked: c.blocked,
            median_score: scores[Math.floor(scores.length / 2)] ?? 0,
            first_seen: group[0]?.ts ?? 0,
            last_seen: group[group.length - 1]?.ts ?? 0,
            ua_sample: group[0]?.user_agent ?? '',
          };
        });
      return Promise.resolve({
        rows: top(rows, (row) => row.requests, 100),
        kinds: (['ja4', 'h2_fp', 'header_fp', 'tcp_fp'] as const).map(
          (name) => ({
            kind: name,
            distinct: new Set(
              since(86_400)
                .map((e) => e[name])
                .filter(Boolean),
            ).size,
          }),
        ),
      });
    },
    reasonCounts(prefix, seconds) {
      return Promise.resolve(reasonCounts(since(seconds), prefix));
    },
    ruleSamples(seconds, target) {
      const list = since(seconds);
      const stride = Math.max(1, Math.floor(list.length / target));
      return Promise.resolve({
        total: list.length,
        samples: list.filter((_, i) => i % stride === 0).slice(0, target),
      });
    },
    refusedByLimit(seconds) {
      const map = new Map<string, number>();
      for (const e of since(seconds)) {
        if (e.rate_limit)
          map.set(e.rate_limit, (map.get(e.rate_limit) ?? 0) + 1);
      }
      return Promise.resolve(map);
    },
    consumers(seconds, by) {
      return Promise.resolve(
        top(
          [
            ...groupBy(
              since(seconds).filter((e) => e[by] !== ''),
              (e) => e[by],
            ),
          ].map(([key, group]) => ({
            key,
            ip_prefix: group[0]?.ip_prefix ?? '',
            ip_hash_count: new Set(group.map((e) => e.ip_hash)).size,
            host:
              top(
                [...groupBy(group, (e) => e.host)],
                ([, g]) => g.length,
                1,
              )[0]?.[0] ?? '',
            rps: group.length / seconds,
            refused: group.filter((e) => e.rate_limit !== '').length,
          })),
          (row) => row.rps,
          10,
        ),
      );
    },
    hostStats(seconds) {
      return Promise.resolve(hostCounts(since(seconds)));
    },
    impostors(seconds) {
      const list = since(seconds).filter((e) =>
        e.reasons.some((r) => r.startsWith('fake_crawler:')),
      );
      return Promise.resolve(
        top(
          [
            ...groupBy(
              list,
              (e) =>
                `${e.reasons.find((r) => r.startsWith('fake_crawler:')) ?? ''}|${e.ip_prefix}`,
            ),
          ].map(([key, group]) => ({
            crawler: (key.split('|')[0] ?? '').slice('fake_crawler:'.length),
            ip_prefix: group[0]?.ip_prefix ?? '',
            asn: group[0]?.asn ?? 0,
            requests: group.length,
            action: group[0]?.action ?? '',
            last_seen: group[group.length - 1]?.ts ?? 0,
          })),
          (row) => row.requests,
          20,
        ),
      );
    },
    busiestHost(seconds) {
      const row = top(hostCounts(since(seconds)), (r) => r.requests, 1)[0];
      return Promise.resolve(
        row ? { host: row.host, rps: row.requests / seconds } : null,
      );
    },
    libraryCandidates(seconds, minClients) {
      // The engine as sql.ts libraryCandidates derives it.
      const engine = (ua: string) =>
        /curl|wget|python|go-http|okhttp|java\/|node-fetch|axios|bot|spider|crawl/i.test(
          ua,
        )
          ? ''
          : /iPhone|iPad|iPod/.test(ua)
            ? 'webkit'
            : /(Firefox|FxiOS)\//.test(ua)
              ? 'firefox'
              : /(Chrome|Chromium|CriOS|Edg|OPR)\//.test(ua)
                ? 'chromium'
                : /Version\/\d+.*Safari\//.test(ua)
                  ? 'webkit'
                  : '';
      const groups = new Map<string, MockEvent[]>();
      for (const e of since(seconds)) {
        if (!e.ja4 || !e.reasons.includes('token_valid')) continue;
        const key = `${engine(e.user_agent)}|${e.ja4.split('_')[1] ?? ''}|${e.pseudo_order}`;
        if (key.startsWith('|') || key.split('|')[1] === '') continue;
        groups.set(key, [...(groups.get(key) ?? []), e]);
      }
      return Promise.resolve(
        top(
          [...groups]
            .map(([key, events]) => {
              const [eng = '', ciphers = '', pseudo_order = ''] =
                key.split('|');
              return {
                engine: eng,
                ciphers,
                pseudo_order,
                clients: new Set(events.map((e) => e.ip_hash)).size,
                requests: events.length,
                ua_sample: events[0]?.user_agent ?? '',
                first_seen: Math.min(...events.map((e) => e.ts)),
                last_seen: Math.max(...events.map((e) => e.ts)),
              };
            })
            .filter((row) => row.clients >= minClients),
          (row) => row.clients,
          200,
        ),
      );
    },
    readiness(host, seconds) {
      const list = since(seconds).filter((e) => e.host === host);
      const clientsOf = (events: MockEvent[]) =>
        new Set(events.map((e) => e.ip_hash)).size;
      const passed = new Set<string>();
      const verified = new Set<string>();
      for (const e of list) {
        if (e.reasons.includes('token_valid')) passed.add(e.ip_hash);
        if (e.class === 'verified_bot') verified.add(e.ip_hash);
      }
      const legit = (e: MockEvent) =>
        e.class === 'human' ||
        e.class === 'verified_bot' ||
        passed.has(e.ip_hash) ||
        verified.has(e.ip_hash);
      const blocks = list.filter(enforceBlocks);
      const challenges = list.filter(enforceChallenges);
      const byReason = new Map<string, MockEvent[]>();
      for (const e of blocks) {
        for (const reason of e.reasons) {
          byReason.set(reason, [...(byReason.get(reason) ?? []), e]);
        }
      }
      const suspects = [
        ...groupBy(
          blocks.filter((e) => e.ip_hash !== ''),
          (e) => e.ip_hash,
        ),
      ].flatMap(([ip_hash, group]) => {
        const evidence = [
          ...(passed.has(ip_hash) ? (['passed_challenge'] as const) : []),
          ...(verified.has(ip_hash) ? (['verified_crawler'] as const) : []),
          ...(group.some((e) => e.class === 'human')
            ? (['classed_human'] as const)
            : []),
        ];
        const first = group[0];
        if (!first || evidence.length === 0) return [];
        return [
          {
            ip_hash,
            ip_prefix: first.ip_prefix,
            asn: first.asn,
            user_agent: first.user_agent,
            requests: group.length,
            reasons: [...new Set(group.flatMap((e) => e.reasons))].slice(0, 6),
            evidence,
            last_seen: Math.max(...group.map((e) => e.ts)),
          },
        ];
      });
      return Promise.resolve({
        requests: list.length,
        clients: clientsOf(list),
        block: {
          requests: blocks.length,
          clients: clientsOf(blocks),
          legit_requests: blocks.filter(legit).length,
          legit_clients: clientsOf(blocks.filter(legit)),
        },
        challenge: {
          requests: challenges.length,
          clients: clientsOf(challenges),
        },
        reasons: top(
          [...byReason].map(([reason, events]) => ({
            reason,
            requests: events.length,
            clients: clientsOf(events),
            legit_clients: clientsOf(events.filter(legit)),
          })),
          (row) => row.requests,
          15,
        ),
        suspects: top(suspects, (row) => row.requests, 20),
      });
    },
    attackImpact(seconds) {
      const list = since(seconds);
      const token = list.filter((e) =>
        e.reasons.includes('token_valid'),
      ).length;
      const verified = list.filter(
        (e) =>
          !e.reasons.includes('token_valid') &&
          (e.class === 'verified_bot' ||
            e.reasons.some((r) => r.startsWith('list:'))),
      ).length;
      return Promise.resolve({
        requests: list.length,
        token,
        verified_or_listed: verified,
      });
    },
    search(kind, q) {
      const list = since(86_400);
      const field = kind === 'host' ? 'host' : kind;
      const matches = list.filter((e) =>
        kind === 'host'
          ? e.host.includes(q.toLowerCase())
          : e[field].startsWith(q),
      );
      return Promise.resolve(
        top(
          [...groupBy(matches, (e) => e[field])].map(([value, group]) => ({
            value,
            requests: group.length,
            asn: group[0]?.asn ?? 0,
          })),
          (row) => row.requests,
          5,
        ),
      );
    },
  };
}
