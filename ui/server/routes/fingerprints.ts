// GET /api/fingerprints?kind=&q=: client signatures of the last 24 hours.

import type { Hono } from 'hono';

import {
  type FingerprintKind,
  fingerprintQuerySchema,
  fingerprintsSchema,
  type GatewayConfig,
} from '../../shared/api.ts';
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

export function registerFingerprints(app: Hono<AppEnv>): void {
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
