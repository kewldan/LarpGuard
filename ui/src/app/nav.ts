// The screens, in the order of the sidebar.

import type { IconName } from '../ui/icons.ts';

export interface NavItem {
  to: string;
  name: string;
  icon: IconName;
  // On the phone tab bar (the rest are in the menu).
  tab?: string;
}

export const NAV: NavItem[] = [
  { to: '/', name: 'Overview', icon: 'overview', tab: 'Overview' },
  { to: '/requests', name: 'Requests', icon: 'requests', tab: 'Requests' },
  { to: '/fingerprints', name: 'Fingerprints', icon: 'fingerprints' },
  { to: '/rules', name: 'Rules', icon: 'rules', tab: 'Rules' },
  { to: '/lists', name: 'Lists', icon: 'lists', tab: 'Lists' },
  { to: '/limits', name: 'Rate limits', icon: 'limits' },
  { to: '/hosts', name: 'Hosts & policy', icon: 'hosts', tab: 'Hosts' },
  { to: '/crawlers', name: 'Crawlers', icon: 'crawlers' },
  { to: '/attack', name: 'Attack mode', icon: 'attack' },
  { to: '/config', name: 'Configuration', icon: 'config' },
  { to: '/log', name: 'Decision log', icon: 'log' },
];
