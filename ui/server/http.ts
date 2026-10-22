// Small HTTP helpers shared by the routes.

import { isIP } from 'node:net';

import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { z } from 'zod';

import { AnalyticsError } from './analytics/clickhouse.ts';
import { AdminError } from './gateway/admin.ts';

export function fail(
  status: 400 | 401 | 403 | 404 | 409 | 422 | 429 | 503,
  error: string,
): never {
  throw new HTTPException(status, {
    res: new Response(JSON.stringify({ error }), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  });
}

// Validates a body or query against a schema (400 with the first problem).
export function parseOr400<T extends z.ZodType>(
  schema: T,
  value: unknown,
): z.output<T> {
  const result = schema.safeParse(value);
  if (!result.success) {
    const issue = result.error.issues[0];
    fail(
      400,
      issue
        ? `${issue.path.join('.') || 'body'}: ${issue.message}`
        : 'invalid request',
    );
  }
  return result.data;
}

export async function jsonBody(c: Context): Promise<unknown> {
  try {
    return await c.req.json();
  } catch {
    return fail(400, 'body must be JSON');
  }
}

// Validates a response before it leaves (a bug, not the client's fault).
export function send<T extends z.ZodType>(
  c: Context,
  schema: T,
  value: z.input<T>,
  status: 200 | 201 = 200,
): Response {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new Error(
      `response does not match its schema: ${result.error.issues[0]?.path.join('.') ?? ''} ${result.error.issues[0]?.message ?? ''}`,
    );
  }
  return c.json(result.data as object, status);
}

// Errors from the gateway and ClickHouse become JSON with a fitting status.
export function errorResponse(error: unknown): Response {
  if (error instanceof HTTPException) return error.getResponse();
  let status = 500;
  let body: Record<string, unknown> = { error: 'internal error' };
  if (error instanceof AdminError) {
    status =
      error.status === 503
        ? 503
        : error.status >= 400 && error.status < 500
          ? error.status
          : 502;
    body = { error: error.message };
    if (error.column !== undefined) body['column'] = error.column;
    if (error.path !== undefined) body['path'] = error.path;
  } else if (error instanceof AnalyticsError) {
    status = 503;
    body = { error: error.message };
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

// The /24 of an IPv4 or the /48 of an IPv6 address ("" if not an IP): the
// key sign-in throttling uses for a client network.
export function addressPrefix(address: string): string {
  const plain = address.replace(/^::ffff:(?=\d+\.)/, '');
  if (isIP(plain) === 4) {
    return `${plain.split('.').slice(0, 3).join('.')}.0/24`;
  }
  if (isIP(plain) === 6) {
    const groups = expandV6(plain).slice(0, 3);
    return `${groups.map((group) => group.replace(/^0+(?=.)/, '')).join(':')}::/48`;
  }
  return '';
}

function expandV6(address: string): string[] {
  const [head = '', tail = ''] = address.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const fill = address.includes('::') ? 8 - left.length - right.length : 0;
  return [...left, ...Array<string>(fill).fill('0'), ...right].map((group) =>
    group.padStart(4, '0'),
  );
}
