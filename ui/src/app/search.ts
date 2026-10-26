// URL search parameters of each screen, validated like API input: a link
// someone pasted can only ever produce a valid filter.

import { z } from 'zod';

import { FINGERPRINT_KINDS } from '../../shared/api.ts';
import {
  BOT_CLASSES,
  LIST_KINDS,
  OUTCOMES,
  RANGES,
} from '../../shared/domain.ts';

// Comma-separated values of a fixed set ("block,challenge"); anything
// else is dropped.
const csvOf = (values: readonly string[]) =>
  z
    .string()
    .max(200)
    .transform((text) =>
      text
        .split(',')
        .filter((v) => values.includes(v))
        .join(','),
    )
    .optional()
    .catch(undefined);

export const overviewSearch = z.object({
  range: z.enum(RANGES).optional().catch(undefined),
});

export const requestsSearch = z.object({
  range: z.enum(RANGES).optional().catch(undefined),
  host: z.string().max(500).optional().catch(undefined),
  action: csvOf(OUTCOMES),
  class: csvOf(BOT_CLASSES),
  reason: z.string().max(200).optional().catch(undefined),
  asn: z.coerce.number().int().min(1).optional().catch(undefined),
  ja4: z.string().max(200).optional().catch(undefined),
  ip_prefix: z.string().max(64).optional().catch(undefined),
  ip_hash: z
    .string()
    .regex(/^[0-9a-f]{1,32}$/)
    .optional()
    .catch(undefined),
  path: z.string().max(500).optional().catch(undefined),
  min_score: z.coerce
    .number()
    .int()
    .min(0)
    .max(100)
    .optional()
    .catch(undefined),
  // Selected request: id and time (the time narrows the lookup).
  id: z.string().max(128).optional().catch(undefined),
  ts: z.coerce.number().int().optional().catch(undefined),
  live: z.coerce.boolean().optional().catch(undefined),
});
export type RequestsSearch = z.infer<typeof requestsSearch>;

export const fingerprintsSearch = z.object({
  kind: z.enum(FINGERPRINT_KINDS).optional().catch(undefined),
  q: z.string().max(200).optional().catch(undefined),
  a: z.string().max(400).optional().catch(undefined),
  b: z.string().max(400).optional().catch(undefined),
});

export const rulesSearch = z.object({
  rule: z.string().max(200).optional().catch(undefined),
});

export const listsSearch = z.object({
  tab: z.enum(['block', 'allow']).optional().catch(undefined),
  kind: z.enum(LIST_KINDS).optional().catch(undefined),
  value: z.string().max(200).optional().catch(undefined),
});

export const hostsSearch = z.object({
  host: z.string().max(253).optional().catch(undefined),
});

export const crawlersSearch = z.object({
  crawler: z.string().max(100).optional().catch(undefined),
});

export const auditSearch = z.object({
  kind: z
    .enum(['list', 'attack', 'mode', 'reload', 'settings', 'auth', 'users'])
    .optional()
    .catch(undefined),
  q: z.string().max(200).optional().catch(undefined),
  entry: z.string().max(64).optional().catch(undefined),
});

export const configSearch = z.object({
  section: z
    .string()
    .regex(/^[a-z0-9]+$/)
    .max(40)
    .optional()
    .catch(undefined),
  key: z
    .string()
    .regex(/^[a-z0-9_.]+$/)
    .max(100)
    .optional()
    .catch(undefined),
});
