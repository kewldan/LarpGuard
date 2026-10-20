// Stroke icon paths from the design (16×16 grid, drawn in currentColor).

export const ICON_PATHS = {
  overview: 'M2 2h5v5H2zM9 2h5v3H9zM9 7h5v7H9zM2 9h5v5H2z',
  requests: 'M2 4h12M2 8h12M2 12h8',
  fingerprints:
    'M4 13c-1-1.5-1.5-3-1.5-5a5.5 5.5 0 0 1 11 0M8 8v3c0 1 .5 2 1 3M5.5 11c.3-1 .5-2 .5-3a2 2 0 0 1 4 0',
  rules: 'M5 3L2 8l3 5M11 3l3 5-3 5M9 3L7 13',
  lists: 'M2 4h1M2 8h1M2 12h1M6 4h8M6 8h8M6 12h8',
  limits: 'M8 14A6 6 0 1 1 8 2a6 6 0 0 1 0 12zM8 8l3-3',
  hosts: 'M2 3h12v4H2zM2 9h12v4H2zM5 5h.01M5 11h.01',
  crawlers:
    'M8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6M2 4l3 2M14 4l-3 2M2 12l3-2M14 12l-3-2',
  attack: 'M8 2l6 11H2zM8 6v3.5M8 11.5h.01',
  log: 'M3 2h7l3 3v9H3zM6 7h4M6 10h4',
  moon: 'M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7z',
  sun: 'M8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3 3l1 1M12 12l1 1M3 13l1-1M12 4l1-1',
  back: 'M10 3L5 8l5 5',
  forward: 'M6 3l5 5-5 5',
  close: 'M4 4l8 8M12 4l-8 8',
  check: 'M3 8.5l3 3L13 4.5',
  plus: 'M8 3v10M3 8h10',
  menu: 'M2 4h12M2 8h12M2 12h12',
  copy: 'M5.5 5.5h7v7h-7zM3.5 10.5v-7h7',
  search: 'M7 2.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM10.5 10.5L14 14',
  settings:
    'M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4',
  signOut: 'M6 2H3v12h3M10 5l3 3-3 3M13 8H6',
  external: 'M9 3h4v4M13 3L7 9M11 9v4H3V5h4',
} as const;

export type IconName = keyof typeof ICON_PATHS;
