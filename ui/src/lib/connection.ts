// The sign-in screen's "is it me or the server" check: a few timed calls
// to /api/ping. The round trip minus the server's own answering time is
// the network (with the gateway and Traefik on the way); the answer says
// how the server side is doing.

import { type Ping, pingSchema } from '../../shared/api.ts';
import { getJson } from './api.ts';

// An answered probe: the round trip and the server's answer. A probe with
// no answer in time is null.
export interface Probe {
  round_trip_ms: number;
  ping: Ping;
}

export type Culprit = 'none' | 'network' | 'server' | 'both' | 'unreachable';

export interface Diagnosis {
  culprit: Culprit;
  // Network share of a round trip: median, fastest and slowest.
  network_ms: number | null;
  fastest_ms: number | null;
  slowest_ms: number | null;
  lost: number;
  sent: number;
  server_ms: number | null;
  loop_ms: number | null;
  // Undefined: no probe came back, so nothing is known about the gateway.
  gateway_ms: number | null | undefined;
  // Why, in order of weight, one sentence each.
  findings: string[];
}

export const kProbes = 6;
const kProbeTimeout = 4_000;
const kProbeGap = 150;

// Past these the side is called slow.
const kSlowNetwork = 300;
// Swing between the fastest and slowest round trip: more than this and
// more than the median itself is an unstable path.
const kJitter = 150;
const kSlowServer = 500;
const kSlowLoop = 100;
const kSlowGateway = 1_000;

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? (sorted[middle] ?? 0)
    : ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2;
}

function ms(value: number): string {
  return `${Math.round(value)} ms`;
}

export function diagnose(probes: (Probe | null)[]): Diagnosis {
  const answered = probes.filter((probe) => probe !== null);
  const lost = probes.length - answered.length;
  if (answered.length === 0) {
    return {
      culprit: 'unreachable',
      network_ms: null,
      fastest_ms: null,
      slowest_ms: null,
      lost,
      sent: probes.length,
      server_ms: null,
      loop_ms: null,
      gateway_ms: undefined,
      findings: [
        'Nothing came back. Check your connection or VPN; if other sites work, the console itself may be down.',
      ],
    };
  }
  const network = answered.map((probe) =>
    Math.max(0, probe.round_trip_ms - probe.ping.server_ms),
  );
  const network_ms = median(network);
  const fastest_ms = Math.min(...network);
  const slowest_ms = Math.max(...network);
  const server_ms = median(answered.map((probe) => probe.ping.server_ms));
  const loop_ms = Math.max(...answered.map((probe) => probe.ping.loop_ms));
  const last = answered[answered.length - 1];
  const gateway_ms = last ? last.ping.gateway_ms : null;

  const networkFindings: string[] = [];
  if (lost > 0) {
    networkFindings.push(
      `${lost} of ${probes.length} probes got no answer within ${kProbeTimeout / 1000} s: packets are lost on the way, often on a VPN or a weak Wi-Fi.`,
    );
  }
  const swing = slowest_ms - fastest_ms;
  if (swing > kJitter && swing > network_ms) {
    networkFindings.push(
      `Round trips swing from ${ms(fastest_ms)} to ${ms(slowest_ms)}: the path is unstable.`,
    );
  }
  if (network_ms > kSlowNetwork) {
    networkFindings.push(
      `A round trip takes ${ms(network_ms)}: a long path, often a distant VPN exit.`,
    );
  }
  const serverFindings: string[] = [];
  if (gateway_ms === null) {
    serverFindings.push("The gateway's admin API does not answer.");
  } else if (gateway_ms > kSlowGateway) {
    serverFindings.push(
      `The gateway's admin API took ${ms(gateway_ms)} to answer.`,
    );
  }
  if (loop_ms > kSlowLoop) {
    serverFindings.push(
      `The console server is busy: its work queue ran ${ms(loop_ms)} late.`,
    );
  }
  if (server_ms > kSlowServer) {
    serverFindings.push(`The console took ${ms(server_ms)} to answer.`);
  }

  const culprit: Culprit =
    networkFindings.length && serverFindings.length
      ? 'both'
      : networkFindings.length
        ? 'network'
        : serverFindings.length
          ? 'server'
          : 'none';
  return {
    culprit,
    network_ms,
    fastest_ms,
    slowest_ms,
    lost,
    sent: probes.length,
    server_ms,
    loop_ms,
    gateway_ms,
    findings: [...serverFindings, ...networkFindings],
  };
}

export const kHeadline: Record<Culprit, string> = {
  none: 'Your connection and the server both look fine.',
  network: 'The slowness is on your side of the network.',
  server: 'The server is slow, not your connection.',
  both: 'Both your connection and the server are slow.',
  unreachable: 'The console does not answer.',
};

async function probe(signal: AbortSignal | undefined): Promise<Probe | null> {
  const timeout = AbortSignal.timeout(kProbeTimeout);
  const started = performance.now();
  try {
    const ping = await getJson(
      pingSchema,
      '/api/ping',
      undefined,
      signal ? AbortSignal.any([signal, timeout]) : timeout,
    );
    return { round_trip_ms: performance.now() - started, ping };
  } catch (error) {
    // Cancelled by the caller (screen left): not a lost probe.
    if (signal?.aborted) throw error;
    return null;
  }
}

// Probes one after another, so they do not queue behind each other.
export async function checkConnection(
  signal?: AbortSignal,
  count: number = kProbes,
): Promise<Diagnosis> {
  const probes: (Probe | null)[] = [];
  for (let i = 0; i < count; i += 1) {
    if (i > 0) {
      await new Promise((resolve) => setTimeout(resolve, kProbeGap));
    }
    probes.push(await probe(signal));
  }
  return diagnose(probes);
}
