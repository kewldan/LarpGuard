// Network stacks of clients that passed the challenge which the library
// does not know for their engine: candidates for deploy/fingerprints.yaml,
// with the YAML to add one. The library takes verified values only, so the
// operator checks a candidate before adding it.

import { useState } from 'react';

import { CANDIDATE_RANGES, type CandidateRange } from '../../shared/api.ts';
import { ApiError } from '../lib/api.ts';
import { candidateYaml } from '../lib/config-yaml.ts';
import { ago, compact } from '../lib/format.ts';
import { useCandidates, useGatewayConfig } from '../lib/queries.ts';
import { Button } from '../ui/Button.tsx';
import { Card } from '../ui/Card.tsx';
import { Segmented } from '../ui/controls.tsx';
import { EmptyState, Skeleton } from '../ui/states.tsx';
import table from '../ui/table.module.css';
import { useCopy } from '../ui/toast-context.ts';

export function LibraryCandidates() {
  const [range, setRange] = useState<CandidateRange>('7d');
  const query = useCandidates(range);
  const browsers = useGatewayConfig().data?.library.browsers ?? [];
  const copy = useCopy();
  const data = query.data;

  return (
    <Card style={{ padding: 18 }} aria-label="Library candidates">
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
        }}
      >
        <h2 style={{ fontSize: 15, fontWeight: 600 }}>Library candidates</h2>
        <Segmented
          label="Candidates window"
          options={CANDIDATE_RANGES}
          value={range}
          onChange={setRange}
        />
      </div>
      <p
        style={{
          fontSize: 12.5,
          color: 'var(--color-text-2)',
          margin: '6px 0 12px',
          lineHeight: 1.5,
        }}
      >
        TLS cipher hashes (JA4 part b) and HTTP/2 pseudo-header orders of
        clients that passed the challenge, which the library does not list for
        the engine their User-Agent implies. A real browser release is the usual
        cause; a scraper that solved the challenge is the other. Check a value
        against the browser’s published cipher list before adding it: the
        library takes verified values only.
      </p>
      {query.isError ? (
        <div style={{ fontSize: 13, color: 'var(--color-text-2)' }}>
          {query.error instanceof ApiError && query.error.status === 503
            ? 'Needs ClickHouse.'
            : query.error.message}
        </div>
      ) : !data ? (
        <Skeleton loading rows={3} label="Loading library candidates" />
      ) : data.candidates.length === 0 ? (
        <EmptyState title="Nothing new">
          Every stack seen from at least {data.min_clients} clients that passed
          the challenge is in the library.
        </EmptyState>
      ) : (
        <div className={table.wrap}>
          <table className={table.table}>
            <thead>
              <tr>
                <th>Engine</th>
                <th>Cipher hash</th>
                <th>H2 order</th>
                <th className={table.num}>Clients</th>
                <th>Last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.candidates.map((candidate) => (
                <tr
                  key={`${candidate.engine}|${candidate.ciphers}|${candidate.pseudo_order}`}
                  title={candidate.ua_sample}
                >
                  <td>{candidate.engine}</td>
                  <td
                    className={table.mono}
                    style={{
                      fontWeight: candidate.new_ciphers ? 600 : undefined,
                    }}
                  >
                    {candidate.ciphers}
                    {candidate.new_ciphers ? ' · new' : ''}
                  </td>
                  <td
                    className={table.mono}
                    style={{
                      fontWeight: candidate.new_pseudo_order ? 600 : undefined,
                    }}
                  >
                    {candidate.pseudo_order || '–'}
                    {candidate.new_pseudo_order ? ' · new' : ''}
                  </td>
                  <td className={table.num}>{compact(candidate.clients)}</td>
                  <td className={table.muted}>{ago(candidate.last_seen)}</td>
                  <td>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        copy(candidateYaml(candidate, browsers), 'YAML');
                      }}
                    >
                      Copy YAML
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
