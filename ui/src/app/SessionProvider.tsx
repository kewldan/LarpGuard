import type { ReactNode } from 'react';

import type { Session } from '../../shared/api.ts';
import { SessionContext } from './session.ts';

export function SessionProvider({
  session,
  children,
}: {
  session: Session;
  children: ReactNode;
}) {
  return <SessionContext value={session}>{children}</SessionContext>;
}
