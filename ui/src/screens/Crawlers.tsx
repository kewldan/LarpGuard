// Crawlers: the catalog of known good bots, how each is verified (reverse
// DNS, published IP ranges, Web Bot Auth), and who passed or pretended.

import { Link, useNavigate, useSearch } from '@tanstack/react-router';

import type { Crawlers as CrawlersData } from '../../shared/api.ts';
import { ActionChip } from '../domain/verdict.tsx';
import { ago, compact } from '../lib/format.ts';
import { useCrawlers, useGatewayConfig } from '../lib/queries.ts';
import { PageHead } from '../ui/Card.tsx';
import { EmptyState, ErrorState, Skeleton } from '../ui/states.tsx';
import table from '../ui/table.module.css';
import styles from './screens.module.css';

type Crawler = CrawlersData['crawlers'][number];

function methods(crawler: Crawler, data: CrawlersData): string[] {
  const out: string[] = [];
  if (crawler.domains.length && data.verify) out.push('rDNS');
  if (crawler.ranges.length && data.ip_ranges) out.push('IP ranges');
  return out.length ? out : ['not verifiable'];
}

function Chain({ crawler, data }: { crawler: Crawler; data: CrawlersData }) {
  const steps: { step: string; detail: string; on: boolean }[] = [
    {
      step: 'User-Agent claims it',
      detail: `a ${crawler.id} token in the User-Agent; never enough on its own`,
      on: true,
    },
    {
      step: 'Reverse and forward DNS',
      detail: crawler.domains.length
        ? `PTR ends in ${crawler.domains.join(' or ')}, and that name resolves back to the address`
        : 'no published domains',
      on: crawler.domains.length > 0 && data.verify,
    },
    {
      step: 'Published IP ranges',
      detail: crawler.ranges.length
        ? `the address is in ${crawler.ranges.length} published list${crawler.ranges.length > 1 ? 's' : ''}, refreshed daily`
        : 'no published ranges',
      on: crawler.ranges.length > 0 && data.ip_ranges,
    },
    {
      step: 'Result',
      detail:
        'verified_crawler:<id> on success; fake_crawler:<id> (and its weight) when the checks say no',
      on: true,
    },
  ];
  return (
    <ol
      style={{
        listStyle: 'none',
        margin: 0,
        padding: 0,
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
      }}
    >
      {steps.map((step, i) => (
        <li
          key={step.step}
          style={{ display: 'flex', gap: 10, opacity: step.on ? 1 : 0.55 }}
        >
          <span
            className="mono"
            style={{
              flex: 'none',
              width: 20,
              height: 20,
              borderRadius: 999,
              border: `1px solid ${step.on ? 'var(--color-verified)' : 'var(--color-line-strong)'}`,
              color: step.on ? 'var(--color-verified)' : 'var(--color-text-3)',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 11,
            }}
          >
            {i + 1}
          </span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 500 }}>{step.step}</div>
            <div
              style={{
                fontSize: 12,
                color: 'var(--color-text-3)',
                lineHeight: 1.45,
              }}
            >
              {step.detail}
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function Crawlers() {
  const crawlers = useCrawlers();
  const config = useGatewayConfig().data;
  const search = useSearch({ from: '/crawlers' });
  const navigate = useNavigate({ from: '/crawlers' });

  if (crawlers.isError)
    return (
      <ErrorState
        error={crawlers.error}
        onRetry={() => void crawlers.refetch()}
      />
    );
  if (!crawlers.data)
    return <Skeleton loading rows={8} label="Loading crawlers" />;
  const data = crawlers.data;
  const current =
    data.crawlers.find((c) => c.id === search.crawler) ?? data.crawlers[0];
  const totals = {
    verified: data.crawlers.reduce((sum, c) => sum + c.verified, 0),
    fake: data.crawlers.reduce((sum, c) => sum + c.fake, 0),
    signed: data.signed_agents.reduce((sum, a) => sum + a.requests, 0),
  };
  const policy = (crawler: Crawler) =>
    crawler.ai
      ? (data.ai_action ?? 'scored')
      : (config?.policy.verified_bot_action ?? 'allow');
  const impostors = data.impostors.filter(
    (i) => !current || i.crawler === current.id,
  );

  return (
    <>
      <PageHead
        title="Crawlers"
        sub="Known good bots. A User-Agent claim alone never counts; each one has to pass verification."
      />

      <div className={styles.kpis}>
        {(
          [
            [
              'Verified · 24h',
              compact(totals.verified),
              'var(--color-verified)',
            ],
            [
              'Impostors · 24h',
              compact(totals.fake),
              totals.fake ? 'var(--color-blocked-text)' : 'var(--color-text)',
            ],
            [
              'Signed agents · 24h',
              compact(totals.signed),
              'var(--color-text)',
            ],
            [
              'In the catalog',
              String(data.crawlers.length),
              'var(--color-text)',
            ],
          ] as const
        ).map(([name, value, color]) => (
          <div key={name} className={styles.kpi}>
            <div className={styles.kpiLabel}>{name}</div>
            <div className={styles.kpiValue}>
              <span
                className={`mono ${styles.kpiNumber}`}
                style={{ color, fontSize: 26 }}
              >
                {value}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 16,
          alignItems: 'flex-start',
        }}
      >
        <section
          aria-label="Catalog"
          style={{
            flex: '999 1 560px',
            minWidth: 0,
            border: '1px solid var(--color-line)',
            borderRadius: 12,
            overflow: 'hidden',
          }}
        >
          <div className={table.wrap}>
            <table className={table.table} style={{ minWidth: 640 }}>
              <thead>
                <tr>
                  <th>Crawler</th>
                  <th>Verified by</th>
                  <th className={table.num}>Pass 24h</th>
                  <th className={table.num}>Impostors</th>
                  <th>Policy</th>
                </tr>
              </thead>
              <tbody>
                {data.crawlers.map((crawler) => (
                  <tr
                    key={crawler.id}
                    className={table.clickable}
                    aria-selected={crawler.id === current?.id}
                    tabIndex={0}
                    onClick={() =>
                      void navigate({ search: { crawler: crawler.id } })
                    }
                    onKeyDown={(event) => {
                      if (event.key === 'Enter')
                        void navigate({ search: { crawler: crawler.id } });
                    }}
                  >
                    <td>
                      <span style={{ fontWeight: 500 }}>{crawler.id}</span>{' '}
                      <span
                        style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}
                      >
                        {crawler.ai ? 'AI' : 'search'}
                      </span>
                    </td>
                    <td>
                      {methods(crawler, data).map((method) => (
                        <span
                          key={method}
                          className="mono"
                          style={{
                            fontSize: 11,
                            padding: '1px 6px',
                            marginRight: 4,
                            borderRadius: 4,
                            border: '1px solid var(--color-line-strong)',
                            color: 'var(--color-text-2)',
                          }}
                        >
                          {method}
                        </span>
                      ))}
                    </td>
                    <td className={table.num}>{compact(crawler.verified)}</td>
                    <td
                      className={table.num}
                      style={{
                        color: crawler.fake
                          ? 'var(--color-blocked-text)'
                          : 'var(--color-text-3)',
                      }}
                    >
                      {compact(crawler.fake)}
                    </td>
                    <td>
                      {policy(crawler) === 'scored' ? (
                        <span style={{ color: 'var(--color-text-3)' }}>
                          scored
                        </span>
                      ) : (
                        <ActionChip action={policy(crawler)} small />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.signed_agents.length > 0 || data.web_bot_auth.enabled ? (
            <div
              style={{
                padding: '12px 16px',
                borderTop: '1px solid var(--color-line)',
                fontSize: 12.5,
                color: 'var(--color-text-2)',
              }}
            >
              <b>Web Bot Auth</b> {data.web_bot_auth.enabled ? 'on' : 'off'} ·
              trusted{' '}
              <span className="mono">
                {data.web_bot_auth.trusted.join(', ') || 'none'}
              </span>
              {data.signed_agents.length ? (
                <>
                  {' '}
                  · seen{' '}
                  {data.signed_agents.map((agent) => (
                    <span
                      key={agent.agent}
                      className="mono"
                      style={{ marginRight: 8 }}
                    >
                      {agent.agent} {compact(agent.requests)}
                    </span>
                  ))}
                </>
              ) : null}
            </div>
          ) : null}
        </section>

        {current ? (
          <section
            aria-label={current.id}
            style={{
              flex: '1 1 340px',
              minWidth: 0,
              border: '1px solid var(--color-line)',
              borderRadius: 12,
              background: 'var(--color-surface-1)',
              padding: 18,
              display: 'flex',
              flexDirection: 'column',
              gap: 16,
            }}
          >
            <div>
              <div style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}>
                {current.ai ? 'AI crawler' : 'Search crawler'}
              </div>
              <h2 style={{ fontSize: 18, fontWeight: 600, marginTop: 2 }}>
                {current.id}
              </h2>
            </div>
            <div>
              <div className={styles.eyebrowSmall}>Verification chain</div>
              <Chain crawler={current} data={data} />
            </div>
            <div>
              <div className={styles.eyebrowSmall}>Impostors caught · 24h</div>
              {impostors.length ? (
                impostors.map((impostor) => (
                  <div
                    key={`${impostor.crawler}-${impostor.ip_prefix}`}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '6px 0',
                      borderBottom: '1px solid var(--color-line)',
                      fontSize: 12.5,
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="mono">{impostor.ip_prefix}</div>
                      <div
                        style={{ fontSize: 11.5, color: 'var(--color-text-3)' }}
                      >
                        AS{impostor.asn} · {compact(impostor.requests)} requests
                        · {ago(impostor.last_seen)}
                      </div>
                    </div>
                    <ActionChip action={impostor.action} small />
                  </div>
                ))
              ) : (
                <div style={{ fontSize: 12.5, color: 'var(--color-text-3)' }}>
                  None.
                </div>
              )}
            </div>
            <Link
              to="/requests"
              search={{
                reason: `verified_crawler:${current.id}`,
                range: '24h',
              }}
              style={{ fontSize: 13 }}
            >
              Show its requests →
            </Link>
          </section>
        ) : (
          <EmptyState title="No crawlers in the catalog" />
        )}
      </div>
    </>
  );
}
