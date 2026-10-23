import { describe, expect, it } from 'vitest';

import { diagnose, type Probe } from './connection.ts';

function probe(round_trip_ms: number, server_ms = 2, more = {}): Probe {
  return {
    round_trip_ms,
    ping: { server_ms, loop_ms: 0, gateway_ms: 1, ...more },
  };
}

describe('connection check', () => {
  it('finds nothing on a fast, steady path', () => {
    const diagnosis = diagnose([probe(42), probe(40), probe(45), probe(41)]);
    expect(diagnosis.culprit).toBe('none');
    expect(diagnosis.network_ms).toBe(39.5);
    expect(diagnosis.lost).toBe(0);
    expect(diagnosis.findings).toEqual([]);
  });

  it('blames the network for lost probes, swings and long trips', () => {
    expect(diagnose([probe(40), null, probe(42)]).culprit).toBe('network');
    const unstable = diagnose([probe(40), probe(45), probe(600), probe(42)]);
    expect(unstable.culprit).toBe('network');
    expect(unstable.findings[0]).toMatch(/swing from 38 ms to 598 ms/);
    expect(diagnose([probe(420), probe(410), probe(430)]).findings).toEqual([
      expect.stringMatching(/takes 418 ms/),
    ]);
  });

  it('takes the server time out of the round trip', () => {
    const diagnosis = diagnose([probe(900, 860), probe(910, 870)]);
    expect(diagnosis.network_ms).toBe(40);
    expect(diagnosis.culprit).toBe('server');
    expect(diagnosis.findings).toEqual([
      expect.stringMatching(/took 865 ms to answer/),
    ]);
  });

  it('blames the server for a silent gateway or a busy event loop', () => {
    expect(diagnose([probe(40, 2, { gateway_ms: null })]).findings[0]).toMatch(
      /does not answer/,
    );
    expect(diagnose([probe(40, 2, { loop_ms: 250 })]).culprit).toBe('server');
    expect(diagnose([probe(40, 2, { loop_ms: 250 }), null]).culprit).toBe(
      'both',
    );
  });

  it('says when nothing came back', () => {
    const diagnosis = diagnose([null, null]);
    expect(diagnosis.culprit).toBe('unreachable');
    expect(diagnosis.gateway_ms).toBeUndefined();
  });
});
