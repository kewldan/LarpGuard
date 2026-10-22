// The signed-in user. The session lives in an HttpOnly cookie; here we
// only learn who we are and the CSRF token for changes.

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, use, useEffect } from 'react';

import { type Session, sessionSchema } from '../../shared/api.ts';
import { ApiError, getJson, onUnauthorized, setCsrfToken } from '../lib/api.ts';

export const sessionKey = ['session'] as const;

export const SessionContext = createContext<Session | null>(null);

export function useSessionQuery() {
  return useQuery({
    queryKey: sessionKey,
    queryFn: async ({ signal }) => {
      try {
        const session = await getJson(
          sessionSchema,
          '/api/session',
          undefined,
          signal,
        );
        setCsrfToken(session.csrf);
        return session;
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) return null;
        throw error;
      }
    },
    staleTime: 60_000,
    retry: false,
  });
}

// Any 401 from the API means the session ended: drop it so the sign-in
// screen shows.
export function useSessionExpiry(): void {
  const client = useQueryClient();
  useEffect(
    () =>
      onUnauthorized(() => {
        client.setQueryData(sessionKey, null);
      }),
    [client],
  );
}

export function useSession(): Session {
  const session = use(SessionContext);
  if (!session) throw new Error('useSession outside SessionProvider');
  return session;
}

export function useCanOperate(): boolean {
  return useSession().user.role === 'operator';
}
