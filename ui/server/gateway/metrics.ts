// Reads the gateway's Prometheus /metrics and /health (loopback, no auth)
// for health dots and the current request rate.

export type MetricSamples = Map<string, number>;

// "name{labels} value" lines to a map keyed by "name{labels}" and summed
// by plain "name"; comments and malformed lines are skipped.
export function parsePrometheus(text: string): MetricSamples {
  const samples: MetricSamples = new Map();
  for (const line of text.split('\n')) {
    if (line.length === 0 || line.startsWith('#')) continue;
    const match = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)/.exec(line);
    if (!match?.[1] || match[3] === undefined) continue;
    const value = Number(match[3]);
    if (!Number.isFinite(value)) continue;
    const name = match[1];
    samples.set(name + (match[2] ?? ''), value);
    if (match[2] !== undefined) {
      samples.set(name, (samples.get(name) ?? 0) + value);
    }
  }
  return samples;
}

export interface GatewayHealth {
  // GET /health: 200 healthy, 503 a worker stalled, null unreachable.
  healthy: boolean | null;
  metrics: MetricSamples | null;
  // Requests per second since the previous successful read.
  rps: number | null;
}

export interface MetricsApi {
  read(): Promise<GatewayHealth>;
}

const TIMEOUT_MS = 3000;

async function fetchText(
  url: string,
): Promise<{ status: number; text: string }> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  return { status: response.status, text: await response.text() };
}

export function createMetricsClient(
  baseUrl: string,
  now: () => number = Date.now,
): MetricsApi {
  let previous: { at: number; requests: number } | null = null;
  return {
    async read() {
      const [health, metrics] = await Promise.allSettled([
        fetchText(new URL('/health', baseUrl).toString()),
        fetchText(new URL('/metrics', baseUrl).toString()),
      ]);
      const healthy =
        health.status === 'fulfilled' ? health.value.status === 200 : null;
      let samples: MetricSamples | null = null;
      let rps: number | null = null;
      if (metrics.status === 'fulfilled' && metrics.value.status === 200) {
        samples = parsePrometheus(metrics.value.text);
        const requests = samples.get('bot_shield_proxied_requests_total');
        const at = now();
        if (requests !== undefined) {
          if (previous && at > previous.at && requests >= previous.requests) {
            rps = ((requests - previous.requests) * 1000) / (at - previous.at);
          }
          // Two reads within a second give a noisy rate: keep the older base.
          if (
            !previous ||
            at - previous.at >= 1000 ||
            requests < previous.requests
          ) {
            previous = { at, requests };
          }
        }
      }
      return { healthy, metrics: samples, rps };
    },
  };
}
