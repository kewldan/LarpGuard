// GET /api/fingerprints?kind=&q=: client signatures of the last 24 hours.
// GET /api/fingerprints/candidates?range=: library candidates.

import type { Hono } from 'hono';

import {
  CANDIDATE_RANGES,
  type Candidates,
  candidateQuerySchema,
  candidatesSchema,
  type FingerprintKind,
  fingerprintQuerySchema,
  fingerprintsSchema,
  type GatewayConfig,
} from '../../shared/api.ts';
import type { StackRow } from '../analytics/analytics.ts';
import type { AppEnv } from '../deps.ts';
import { parseOr400, send } from '../http.ts';
import { analytics } from './common.ts';

// The library's glob: '*' matches any run of characters.
export function globMatch(pattern: string, text: string): boolean {
  const parts = pattern.split('*');
  if (parts.length === 1) return pattern === text;
  const first = parts[0] ?? '';
  const last = parts[parts.length - 1] ?? '';
  if (!text.startsWith(first) || text.length < first.length + last.length) {
    return false;
  }
  if (!text.endsWith(last)) return false;
  let at = first.length;
  for (const middle of parts.slice(1, -1)) {
    const found = text.indexOf(middle, at);
    if (found < 0 || found + middle.length > text.length - last.length) {
      return false;
    }
    at = found + middle.length;
  }
  return true;
}

// The automation signature whose pattern for this kind matches `value`
// (signatures have no TCP field).
export function knownAs(
  automation: GatewayConfig['library']['automation'],
  kind: FingerprintKind,
  value: string,
): string | null {
  if (kind === 'tcp_fp') return null;
  for (const signature of automation) {
    const pattern = signature[kind];
    if (pattern !== '' && globMatch(pattern, value)) return signature.id;
  }
  return null;
}

// Distinct clients that passed the challenge before a stack is shown: a
// handful of browsers, not one odd client.
export const MIN_CANDIDATE_CLIENTS = 3;

// The stacks the library does not know for their engine: a cipher hash
// missing from the engine's profile, or an HTTP/2 pseudo-header order
// missing from it (HTTP/1.1 stacks have none to compare).
export function libraryCandidates(
  rows: StackRow[],
  browsers: GatewayConfig['library']['browsers'],
): Candidates['candidates'] {
  const out: Candidates['candidates'] = [];
  for (const row of rows) {
    const profile = browsers.find((b) => b.engines.includes(row.engine));
    const newCiphers =
      !profile ||
      (profile.ja4_ciphers.length > 0 &&
        !profile.ja4_ciphers.includes(row.ciphers));
    const newPseudo =
      row.pseudo_order !== '' &&
      (!profile ||
        (profile.h2_pseudo_orders.length > 0 &&
          !profile.h2_pseudo_orders.includes(row.pseudo_order)));
    if (!newCiphers && !newPseudo) continue;
    out.push({
      ...row,
      profile: profile?.id ?? null,
      new_ciphers: newCiphers,
      new_pseudo_order: newPseudo,
    });
  }
  return out;
}

export function registerFingerprints(app: Hono<AppEnv>): void {
  app.get('/api/fingerprints/candidates', async (c) => {
    const deps = c.get('deps');
    const { range } = parseOr400(candidateQuerySchema, c.req.query());
    const seconds = range === CANDIDATE_RANGES[0] ? 86_400 : 7 * 86_400;
    const [rows, config] = await Promise.all([
      analytics(deps).libraryCandidates(seconds, MIN_CANDIDATE_CLIENTS),
      deps.admin.config(),
    ]);
    return send(c, candidatesSchema, {
      range,
      min_clients: MIN_CANDIDATE_CLIENTS,
      candidates: libraryCandidates(rows, config.library.browsers),
    });
  });

  app.get('/api/fingerprints', async (c) => {
    const deps = c.get('deps');
    const { kind, q } = parseOr400(fingerprintQuerySchema, c.req.query());
    const [data, config] = await Promise.all([
      analytics(deps).fingerprints(kind, q, deps.now()),
      deps.admin.config().catch(() => null),
    ]);
    const automation = config?.library.automation ?? [];
    return send(c, fingerprintsSchema, {
      kind,
      kinds: data.kinds,
      rows: data.rows.map((row) => ({
        ...row,
        known_as: knownAs(automation, kind, row.value),
      })),
    });
  });
}
