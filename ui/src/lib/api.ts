// The console API from the browser: same-origin fetch with the session
// cookie, the CSRF token on changes, and every response checked against
// its schema from shared/.

import type { z } from 'zod';

import { errorSchema } from '../../shared/api.ts';

export class ApiError extends Error {
  readonly status: number;
  readonly column: number | undefined;
  // The settings key a refused change is about.
  readonly path: string | undefined;

  constructor(status: number, message: string, column?: number, path?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.column = column;
    this.path = path;
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

// The bot-shield gateway in front of the console answers an API call it
// wants checked (attack mode, a rule) with 403 {"error":
// "challenge_required"} instead of the BFF's answer. A fetch cannot solve
// it, so the whole page goes through the gateway's challenge and comes
// back to the same screen with a clearance cookie.
export const GATEWAY_CHALLENGE_PATH = '/__bs/challenge';

export function isGatewayChallenge(data: unknown): boolean {
  return (
    typeof data === 'object' &&
    data !== null &&
    (data as { error?: unknown }).error === 'challenge_required'
  );
}

// Where the browser goes: back to the current screen, never to the API path
// in the gateway's link (that would show JSON).
export function gatewayChallengeUrl(current: Location): string {
  const back = `${current.pathname}${current.search}`;
  return `${GATEWAY_CHALLENGE_PATH}?r=${encodeURIComponent(back)}`;
}

let challengeStarted = false;

function solveGatewayChallenge(): void {
  // Several queries fail at once; navigate once.
  if (challengeStarted) return;
  challengeStarted = true;
  window.location.assign(gatewayChallengeUrl(window.location));
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
    let key: string | undefined;
    try {
      const data: unknown = await response.json();
      if (response.status === 403 && isGatewayChallenge(data)) {
        solveGatewayChallenge();
      }
      const parsed = errorSchema.safeParse(data);
      if (parsed.success) {
        message = parsed.data.error;
        column = parsed.data.column;
        key = parsed.data.path;
      }
    } catch {
      // Not JSON: keep the status line.
    }
    // Sign-in endpoints answer 401 for wrong credentials, not a lost session.
    if (response.status === 401 && !path.startsWith('/api/session')) {
      for (const listener of unauthorizedListeners) listener();
    }
    throw new ApiError(response.status, message, column, key);
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
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<z.output<T>> {
  const response = await request(method, path, body, undefined);
  return schema.parse(await response.json());
}

// For changes that answer 204.
export async function send(
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<void> {
  await request(method, path, body, undefined);
}
