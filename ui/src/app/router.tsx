// Routes. Search parameters are validated per screen (search.ts); each
// screen is its own chunk, loaded on first visit (and on link hover).

import {
  createRootRoute,
  createRoute,
  createRouter,
  Link,
  lazyRouteComponent,
} from '@tanstack/react-router';

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
    component: lazyRouteComponent(
      () => import('../screens/Overview.tsx'),
      'Overview',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/requests',
    validateSearch: requestsSearch,
    component: lazyRouteComponent(
      () => import('../screens/Requests.tsx'),
      'Requests',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/fingerprints',
    validateSearch: fingerprintsSearch,
    component: lazyRouteComponent(
      () => import('../screens/Fingerprints.tsx'),
      'Fingerprints',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/rules',
    validateSearch: rulesSearch,
    component: lazyRouteComponent(
      () => import('../screens/Rules.tsx'),
      'Rules',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/lists',
    validateSearch: listsSearch,
    component: lazyRouteComponent(
      () => import('../screens/Lists.tsx'),
      'Lists',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/limits',
    component: lazyRouteComponent(
      () => import('../screens/RateLimits.tsx'),
      'RateLimits',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/hosts',
    validateSearch: hostsSearch,
    component: lazyRouteComponent(
      () => import('../screens/Hosts.tsx'),
      'Hosts',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/crawlers',
    validateSearch: crawlersSearch,
    component: lazyRouteComponent(
      () => import('../screens/Crawlers.tsx'),
      'Crawlers',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/attack',
    component: lazyRouteComponent(
      () => import('../screens/Attack.tsx'),
      'Attack',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/log',
    validateSearch: auditSearch,
    component: lazyRouteComponent(
      () => import('../screens/AuditLog.tsx'),
      'AuditLog',
    ),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/settings',
    component: lazyRouteComponent(
      () => import('../screens/Settings.tsx'),
      'Settings',
    ),
  }),
] as const;

export const routeTree = rootRoute.addChildren([...routes]);

export const router = createRouter({ routeTree, defaultPreload: 'intent' });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
