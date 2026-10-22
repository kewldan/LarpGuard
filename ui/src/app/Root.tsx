// Signed in: the shell and the screen. Signed out: the sign-in screen,
// at the same address, so signing in lands where the link pointed.

import { Login } from '../screens/Login.tsx';
import { ErrorState } from '../ui/states.tsx';
import { SessionProvider } from './SessionProvider.tsx';
import { Shell } from './Shell.tsx';
import { useSessionExpiry, useSessionQuery } from './session.ts';

export function Root() {
  const session = useSessionQuery();
  useSessionExpiry();
  if (session.isPending) return null;
  if (session.isError) {
    return (
      <div style={{ padding: 24 }}>
        <ErrorState
          error={session.error}
          onRetry={() => void session.refetch()}
        />
      </div>
    );
  }
  if (!session.data) return <Login />;
  return (
    <SessionProvider session={session.data}>
      <Shell />
    </SessionProvider>
  );
}
