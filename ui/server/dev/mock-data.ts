// Synthetic request events for development and browser tests (never used
// in production). Documentation address ranges and AS numbers only.

import type { DetailRow, SampleEvent } from '../analytics/analytics.ts';

export type MockEvent = SampleEvent & DetailRow;

export function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const MOCK_HOSTS = [
  { host: 'shop.example.com', weight: 34 },
  { host: 'api.example.com', weight: 30 },
  { host: 'auth.example.com', weight: 12 },
  { host: 'cdn.example.com', weight: 14 },
  { host: 'docs.example.com', weight: 7 },
  { host: 'status.example.com', weight: 3 },
];

export const MOCK_ASNS = [
  { asn: 64496, org: 'EXAMPLE-HOSTING-1', country: 'NL', hosting: true },
  { asn: 64497, org: 'EXAMPLE-CLOUD', country: 'US', hosting: true },
  { asn: 64498, org: 'EXAMPLE-BROADBAND', country: 'DE', hosting: false },
  { asn: 64499, org: 'EXAMPLE-MOBILE', country: 'FR', hosting: false },
  { asn: 64500, org: 'EXAMPLE-VPS', country: 'SG', hosting: true },
  { asn: 64501, org: 'EXAMPLE-FIBER', country: 'GB', hosting: false },
];

const PREFIXES = [
  '203.0.113.0/24',
  '198.51.100.0/24',
  '192.0.2.0/24',
  '2001:db8:4f::/48',
  '2001:db8:a0::/48',
];

const PATHS = [
  '/',
  '/product/:n',
  '/v1/items/:n',
  '/search',
  '/login',
  '/cart',
  '/checkout',
  '/static/:hex',
  '/sitemap.xml',
  '/.env',
];

interface Client {
  ja4: string;
  h2_fp: string;
  header_fp: string;
  tcp_fp: string;
  user_agent: string;
  class: string;
  score: [number, number];
  reasons: string[];
  weight: number;
  // Behind a TCP relay (residential proxy): the TLS handshake takes far
  // longer than the TCP round trip.
  relayed?: boolean;
}

const CHROME_JA4 = 't13d1516h2_8daaf6152771_02713d6af862';
const CHROME_H2 = '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p';

const CLIENTS: Client[] = [
  {
    ja4: CHROME_JA4,
    h2_fp: CHROME_H2,
    header_fp: 'a1f3c9e2d4b5',
    tcp_fp: '64240:2-4-8-1-3:1460:8:64',
    user_agent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    class: 'human',
    score: [0, 20],
    reasons: [],
    weight: 62,
  },
  {
    ja4: 't13d1715h2_5b57614c22b0_3d5424432f57',
    h2_fp: '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
    header_fp: 'b7e0aa1c9f02',
    tcp_fp: '65535:2-4-8-1-3:1460:7:64',
    user_agent:
      'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
    class: 'human',
    score: [0, 25],
    reasons: [],
    weight: 14,
  },
  {
    ja4: 't13d1516h2_8daaf6152771_b1ff8ab2d16f',
    h2_fp: CHROME_H2,
    header_fp: 'c4d2e8f10a77',
    tcp_fp: '64240:2-4-8-1-3:1460:7:64',
    user_agent:
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36',
    class: 'bot',
    score: [72, 95],
    reasons: ['headless_user_agent', 'hosting_network'],
    weight: 6,
  },
  {
    ja4: 't13d1312h2_f57a46bbacb6_e7c285222651',
    h2_fp: '2:0;4:4194304;6:10485760|1073741824|0|m,p,a,s',
    header_fp: 'd9a1b3c5e7f9',
    tcp_fp: '29200:2-4-8-1-3:1460:7:64',
    user_agent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    class: 'bot',
    score: [70, 100],
    reasons: [
      'ua_tls_mismatch',
      'h2_settings_mismatch',
      'hosting_network',
      'relayed_connection',
    ],
    weight: 7,
    relayed: true,
  },
  {
    ja4: 't13d3112h2_e8f1e7e78f70_6bebaf5329ac',
    h2_fp: '3:100;4:10485760;2:0|1048510465|0|m,s,a,p',
    header_fp: 'e1f2a3b4c5d6',
    tcp_fp: '64240:2-4-8-1-3:1460:7:64',
    user_agent: 'curl/8.7.1',
    class: 'suspicious',
    score: [35, 65],
    reasons: ['automation_user_agent'],
    weight: 5,
  },
  {
    ja4: 't13d1516h2_8daaf6152771_02713d6af862',
    h2_fp: CHROME_H2,
    header_fp: 'f0e1d2c3b4a5',
    tcp_fp: '64240:2-4-8-1-3:1460:8:64',
    user_agent:
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    class: 'verified_bot',
    score: [0, 0],
    reasons: ['verified_crawler:google'],
    weight: 4,
  },
  {
    ja4: 't13d1312h1_8503b0f1c0b2_bdd6a2f1e2c3',
    h2_fp: '',
    header_fp: 'aa11bb22cc33',
    tcp_fp: '29200:2-4-8-1-3:1460:7:64',
    user_agent:
      'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    class: 'bot',
    score: [80, 90],
    reasons: ['fake_crawler:bing', 'hosting_network'],
    weight: 2,
  },
];

// Policy of the mock gateway: what enforce mode does per class.
function decide(score: number, botClass: string): string {
  if (botClass === 'verified_bot' || botClass === 'human') return 'allow';
  if (score >= 70) return 'block';
  return 'challenge';
}

function clientHash(client: number): string {
  const random = mulberry32(client + 1);
  return Array.from({ length: 4 }, () =>
    Math.floor(random() * 0x10000)
      .toString(16)
      .padStart(4, '0'),
  ).join('');
}

function pick<T extends { weight: number }>(
  items: T[],
  random: () => number,
): T {
  const total = items.reduce((sum, item) => sum + item.weight, 0);
  let roll = random() * total;
  for (const item of items) {
    roll -= item.weight;
    if (roll <= 0) return item;
  }
  return items[items.length - 1] as T;
}

// Synthetic traffic: `events` covers the last 7 days up to the start
// (denser in the last 24 hours, with a burst of bad clients 40 minutes
// before it), and extend() keeps adding events up to a later time.
export class MockTraffic {
  readonly events: MockEvent[] = [];
  private readonly random: () => number;
  private readonly shadowHosts: ReadonlySet<string>;
  private readonly burstCentre: number;
  private sequence = 0;
  private until: number;

  constructor(now: number, shadowHosts: ReadonlySet<string>, seed = 7) {
    this.random = mulberry32(seed);
    this.shadowHosts = shadowHosts;
    this.burstCentre = now - 40 * 60_000;
    const day = 86_400_000;
    for (
      let ts = now - 7 * day;
      ts < now - day;
      ts += 40_000 + this.random() * 40_000
    ) {
      this.add(Math.round(ts), false);
    }
    this.until = now - day;
    this.extend(now);
  }

  // About two events a second, with a daily wave and the burst.
  extend(now: number): void {
    let ts = this.until;
    while (ts < now) {
      const hourOfDay = new Date(ts).getUTCHours();
      const wave = 1 + 0.4 * Math.sin(((hourOfDay - 6) / 24) * 2 * Math.PI);
      const burst = Math.abs(ts - this.burstCentre) < 6 * 60_000;
      const rate = 1.8 * wave * (burst ? 3.5 : 1);
      ts += Math.round(-Math.log(1 - this.random()) * (1000 / rate));
      if (ts < now) this.add(ts, burst);
    }
    this.until = now;
  }

  private add(ts: number, burst: boolean): void {
    const random = this.random;
    const shadowHosts = this.shadowHosts;
    const events = this.events;
    const client =
      burst && random() < 0.7 ? (CLIENTS[3] as Client) : pick(CLIENTS, random);
    const host = pick(MOCK_HOSTS, random).host;
    const asnInfo =
      client.class === 'bot'
        ? (MOCK_ASNS[Math.floor(random() * 2) * 4] ?? MOCK_ASNS[0])
        : MOCK_ASNS[2 + Math.floor(random() * 4)];
    const score = Math.round(
      client.score[0] + random() * (client.score[1] - client.score[0]),
    );
    let reasons = [...client.reasons];
    let path = PATHS[Math.floor(random() * (PATHS.length - 1))] ?? '/';
    if (client.class !== 'human' && random() < 0.05) {
      path = '/.env';
      reasons = [...reasons, 'honeypot'];
    }
    if (
      host === 'shop.example.com' &&
      path === '/login' &&
      client.class !== 'human'
    ) {
      reasons.push('rule:hosting_scrapers');
    }
    const would = decide(score, client.class);
    const shadow = shadowHosts.has(host);
    const action = shadow ? 'allow' : would;
    this.sequence += 1;
    const id = `mock-${(ts % 100000).toString(36)}-${this.sequence}`;
    // Round trips from the sequence number, not from random(): the other
    // synthetic values stay as they were.
    const spread = ((this.sequence * 2654435761) >>> 0) / 4294967296;
    const tcpRtt = client.relayed ? 2 + spread * 6 : 15 + spread * 65;
    const handshake = client.relayed
      ? 120 + spread * 140
      : tcpRtt + 3 + spread * 12;
    events.push({
      ts,
      request_id: id,
      host,
      method: path === '/login' ? 'POST' : 'GET',
      path_group: path,
      path,
      ip_prefix: PREFIXES[Math.floor(random() * PREFIXES.length)] ?? '',
      // A few thousand clients, so "clients" counts mean something.
      ip_hash: clientHash(Math.floor(random() * 3000)),
      asn: asnInfo?.asn ?? 0,
      score,
      class: client.class,
      reasons,
      action,
      would_action: would,
      status: action === 'block' ? 403 : action === 'challenge' ? 403 : 200,
      ja4: client.ja4,
      user_agent: client.user_agent,
      http_version: client.h2_fp ? '2' : '1.1',
      sni: host,
      header_fp: client.header_fp,
      header_names: ['host', 'user-agent', 'accept', 'accept-language'],
      pseudo_order: client.h2_fp ? (client.h2_fp.split('|')[3] ?? '') : '',
      h2_fp: client.h2_fp,
      tcp_fp: client.tcp_fp,
      ja4h: 'ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c',
      accept_language: 'en-US,en;q=0.9',
      sec_ch_ua:
        client.class === 'human'
          ? '"Chromium";v="131", "Not_A Brand";v="24"'
          : '',
      sec_ch_ua_platform: client.class === 'human' ? '"macOS"' : '',
      sec_ch_ua_mobile: client.class === 'human' ? '?0' : '',
      sec_fetch_mode: client.class === 'human' ? 'navigate' : '',
      sec_fetch_site: client.class === 'human' ? 'none' : '',
      rate_limit: '',
      duration_ms: Math.round(5 + random() * 80),
      local: action !== 'allow',
      signed_agent: '',
      client_fp: '',
      model_score: null,
      tcp_rtt_us: Math.round(tcpRtt * 1000),
      handshake_us: Math.round(handshake * 1000),
    });
  }
}

export function generateEvents(
  now: number,
  shadowHosts: ReadonlySet<string>,
  seed = 7,
): MockEvent[] {
  return new MockTraffic(now, shadowHosts, seed).events;
}
