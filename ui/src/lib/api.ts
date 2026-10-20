// The console API from the browser: same-origin fetch with the session
// cookie, the CSRF token on changes, and every response checked against
// its schema from shared/.

import type { z } from 'zod';

import { errorSchema } from '../../shared/api.ts';

export class ApiError extends Error {
  readonly status: number;
  readonly column: number | undefined;

  constructor(status: number, message: string, column?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.column = column;
  }
}

let csrfToken = '';
const unauthorizedListeners = new Set<() => void>();

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

// Called when any request finds the session gone.
export function onUnauthorized(listener: () => void): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

type Query = Record<string, string | number | boolean | undefined | null>;

export function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value));
    }
  }
  const text = params.toString();
  return text ? `${path}?${text}` : path;
}

async function request(
  method: string,
  path: string,
  body: unknown,
  signal: AbortSignal | undefined,
): Promise<Response> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET') headers['x-csrf-token'] = csrfToken;
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      ...(signal ? { signal } : {}),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError')
      throw error;
    throw new ApiError(0, 'The console is unreachable.');
  }
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    let column: number | undefined;
    try {
      const parsed = errorSchema.safeParse(await response.json());
      if (parsed.success) {
        message = parsed.data.error;
        column = parsed.data.column;
      }
    } catch {
      // Not JSON: keep the status line.
    }
    if (response.status === 401 && path !== '/api/session') {
      for (const listener of unauthorizedListeners) listener();
    }
    throw new ApiError(response.status, message, column);
  }
  return response;
}

export async function getJson<T extends z.ZodType>(
  schema: T,
  path: string,
  query?: Query,
  signal?: AbortSignal,
): Promise<z.output<T>> {
  const response = await request(
    'GET',
    withQuery(path, query),
    undefined,
    signal,
  );
  return schema.parse(await response.json());
}

export async function sendJson<T extends z.ZodType>(
  schema: T,
  method: 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<z.output<T>> {
  const response = await request(method, path, body, undefined);
  return schema.parse(await response.json());
}

// For changes that answer 204.
export async function send(
  method: 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<void> {
  await request(method, path, body, undefined);
}
