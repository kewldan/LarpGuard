// Routes. Search parameters are validated per screen (search.ts).

import {
  createRootRoute,
  createRoute,
  createRouter,
  Link,
} from '@tanstack/react-router';

import { Attack } from '../screens/Attack.tsx';
import { AuditLog } from '../screens/AuditLog.tsx';
import { Crawlers } from '../screens/Crawlers.tsx';
import { Fingerprints } from '../screens/Fingerprints.tsx';
import { Hosts } from '../screens/Hosts.tsx';
import { Lists } from '../screens/Lists.tsx';
import { Overview } from '../screens/Overview.tsx';
import { RateLimits } from '../screens/RateLimits.tsx';
import { Requests } from '../screens/Requests.tsx';
import { Rules } from '../screens/Rules.tsx';
import { Settings } from '../screens/Settings.tsx';
import { EmptyState } from '../ui/states.tsx';
import { Root } from './Root.tsx';
import {
  auditSearch,
  crawlersSearch,
  fingerprintsSearch,
  hostsSearch,
  listsSearch,
  overviewSearch,
  requestsSearch,
  rulesSearch,
} from './search.ts';

const rootRoute = createRootRoute({
  component: Root,
  notFoundComponent: () => (
    <EmptyState
      title="Nothing here"
      actions={
        <Link to="/" search={{}}>
          Back to the overview
        </Link>
      }
    >
      This address is not a screen of the console.
    </EmptyState>
  ),
});

const routes = [
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    validateSearch: overviewSearch,
    component: Overview,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/requests',
    validateSearch: requestsSearch,
    component: Requests,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/fingerprints',
    validateSearch: fingerprintsSearch,
    component: Fingerprints,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/rules',
    validateSearch: rulesSearch,
    component: Rules,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/lists',
    validateSearch: listsSearch,
    component: Lists,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/limits',
    component: RateLimits,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/hosts',
    validateSearch: hostsSearch,
    component: Hosts,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/crawlers',
    validateSearch: crawlersSearch,
    component: Crawlers,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/attack',
    component: Attack,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/log',
    validateSearch: auditSearch,
    component: AuditLog,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/settings',
    component: Settings,
  }),
] as const;

export const routeTree = rootRoute.addChildren([...routes]);

export const router = createRouter({ routeTree, defaultPreload: 'intent' });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
