// Design tokens of the LarpGuard console: the single source of truth.
//
// Every value comes from the Claude Design canvas "LarpGuard Console"
// (artboards "Design system" and "Motion system"; screen artboards where the
// system board is silent, noted per token). `tokens.css` is generated from
// this file by `npm run tokens` and checked by `tokens.test.ts`; components
// use the CSS custom properties, TypeScript reads the same values here (charts
// that need numbers, motion timings in JS).

export type Theme = 'dark' | 'light';

// A color that differs per theme. Dark is the default (dark-first design).
export interface ThemedColor {
  readonly dark: string;
  readonly light: string;
}

const both = (value: string): ThemedColor => ({ dark: value, light: value });

// Colors. Design names in comments (`--s1` etc.) for cross-reference.
export const color = {
  // Surfaces and lines: five greys build every surface.
  bg: { dark: '#0f0f0f', light: '#ffffff' }, // --bg, Canvas: page ground
  surface1: { dark: '#151515', light: '#fafafa' }, // --s1, Panel: cards, sidebar
  surface2: { dark: '#1b1b1b', light: '#f4f4f4' }, // --s2, Raised: hover, pills
  surface3: { dark: '#242424', light: '#ececec' }, // --s3, Recessed: tracks, code
  line: { dark: '#262626', light: '#e5e5e5' }, // --ln, Hairline: dividers
  lineStrong: { dark: '#363636', light: '#d4d4d4' }, // --ln2: inputs, outlines

  // Text.
  text: { dark: '#ededed', light: '#1f1f1f' }, // --tx
  text2: { dark: '#a8a8a8', light: '#525252' }, // --tx2: body copy
  text3: { dark: '#8c8c8c', light: '#6b6b6b' }, // --tx3: labels, meta

  // Verdicts. Orange is the only accent and always means blocked.
  // block, decoy, bad_bot.
  blocked: both('#ff5e1f'), // --blk
  blockedText: { dark: '#ff7a45', light: '#c23d00' }, // --blkT
  blockedSoft: { dark: 'rgba(255,94,31,.14)', light: 'rgba(255,94,31,.11)' }, // --blkS
  // Text on a filled orange surface: buttons, the attack hero ("Block ASN",
  // "Enable attack mode": #140700 in both themes).
  onBlocked: both('#140700'),
  // Text of a filled `block` chip (--onBlk on the screen boards).
  onBlockedChip: { dark: '#140700', light: '#ffffff' },

  // challenge, captcha, throttle, tarpit.
  challenged: { dark: '#f5b301', light: '#ffac00' }, // --chl
  challengedText: { dark: '#f7c23a', light: '#8f5c00' }, // --chlT
  challengedSoft: { dark: 'rgba(245,179,1,.13)', light: 'rgba(255,172,0,.16)' }, // --chlS

  // allow, human: deliberately quiet.
  allowed: { dark: '#5c5c5c', light: '#cfcfcf' }, // --alw
  allowedText: { dark: '#c4c4c4', light: '#404040' }, // --alwT
  allowedSoft: { dark: 'rgba(255,255,255,.07)', light: 'rgba(0,0,0,.05)' }, // --alwS
  // Allowed area of the stacked verdict chart (--alw on Overview, States).
  allowedChart: { dark: '#4a4a4a', light: '#d6d6d6' },

  // good_bot, signed agents, links and focus.
  verified: { dark: '#7b9cff', light: '#3557d6' }, // --vfy
  verifiedSoft: { dark: 'rgba(123,156,255,.14)', light: 'rgba(53,87,214,.10)' }, // --vfyS

  // Gateway health only: workers, NATS, ClickHouse.
  healthy: { dark: '#2fb8a6', light: '#058378' }, // --ok
  healthySoft: { dark: 'rgba(47,184,166,.14)', light: 'rgba(5,131,120,.10)' }, // --okS

  // Inverted primary button (never orange).
  inverse: { dark: '#ededed', light: '#1f1f1f' }, // --inv
  onInverse: { dark: '#0f0f0f', light: '#ffffff' }, // --onInv

  // Shadow mode is a hatch, not a hue.
  hatch: { dark: 'rgba(255,255,255,.11)', light: 'rgba(0,0,0,.10)' }, // --hatch
  // Attack-mode stripes over orange (Attack artboards).
  stripes: both('rgba(0,0,0,.10)'),
  // Backdrop behind phone sheets (Requests, Lists, Hosts phone boards).
  scrim: both('rgba(0,0,0,.5)'),
} as const satisfies Record<string, ThemedColor>;

export type ColorToken = keyof typeof color;

export const font = {
  // Interface.
  sans: "'Schibsted Grotesk', system-ui, sans-serif",
  // Anything a machine produced: IPs, hashes, fingerprints, rule code,
  // counts in tables. Slashed zero and tabular figures on (`.mono`).
  mono: "'JetBrains Mono', ui-monospace, monospace",
} as const;

export const fontWeight = {
  regular: 400,
  medium: 500,
  semibold: 600,
  bold: 700,
} as const;

// Sizes used across the boards, in px. Dense UI: half steps are deliberate.
export const fontSize = {
  '2xs': 10, // Mode badge (Overview phone 9.5, rounded up to the desktop 10)
  xs: 10.5, // Eyebrow in tables, chart axes, kind labels
  sm: 11, // Eyebrow, kbd, mono meta
  'sm+': 11.5, // Secondary meta lines
  md: 12, // Label
  'md+': 12.5, // Mono table cells
  base: 13, // Table text, controls
  'base+': 13.5, // Phone list titles
  lg: 14, // Body
  xl: 15, // Section titles (h2 on screens), app name
  '2xl': 17, // Phone screen titles
  '3xl': 18, // H2 on the system board
  '4xl': 22, // Board section headings
  '5xl': 24, // Phone KPI
  '6xl': 28, // H1: screen title
  '7xl': 30, // Desktop KPI
  '8xl': 40, // Phone attack counter
  '9xl': 44, // Score composer
  display: 56, // Display, attack "On"
} as const;

// Named type roles from the system board ("02 Type").
export const typeRole = {
  display: { size: 56, weight: 500, tracking: '-0.03em', leading: 1.2 },
  h1: { size: 28, weight: 500, tracking: '-0.015em', leading: 1.2 },
  h2: { size: 18, weight: 600, tracking: '0', leading: 1.2 },
  section: { size: 15, weight: 600, tracking: '0', leading: 1.2 },
  body: { size: 14, weight: 400, tracking: '0', leading: 1.55 },
  label: { size: 12, weight: 500, tracking: '0', leading: 1.2 },
  eyebrow: { size: 11, weight: 600, tracking: '0.08em', leading: 1.2 },
  mono: { size: 13, weight: 400, tracking: '0', leading: 1.2 },
} as const;

export const tracking = {
  tightest: '-0.045em', // Phone attack title
  tighter: '-0.03em', // Display, KPIs
  tight: '-0.015em', // H1
  snug: '-0.01em', // Headings
  normal: '0',
  wide: '0.06em', // Mode badge, palette kind
  wider: '0.08em', // Eyebrow
} as const;

// "Spacing 4 · 8 · 12 · 16 · 24 · 32 · 48 · 64" (system board footer) plus
// the half steps the screens use for dense rows (2, 6, 10, 14, 18, 20).
export const space = {
  0: 0,
  0.5: 2,
  1: 4,
  1.5: 6,
  2: 8,
  2.5: 10,
  3: 12,
  3.5: 14,
  4: 16,
  4.5: 18,
  5: 20,
  6: 24,
  8: 32,
  12: 48,
  16: 64,
} as const;

// "Radius 4 data · 6 chips · 8 inputs · 12 cards · pill actions", plus the
// in-between values the screens use.
export const radius = {
  dot: 2, // Legend swatches
  bar: 3, // Bars in reason lists
  data: 4, // Data cells, kbd
  badge: 5, // Mode badge
  chip: 6, // Action chips, fingerprint pills
  input: 8, // Inputs, nav items
  banner: 10, // Banners, tooltips, phone inputs
  card: 12, // Cards
  overlay: 14, // Command palette, dialogs
  sheet: 16, // Phone bottom sheets (top corners)
  pill: 999, // Actions, segmented controls
} as const;

export const shadow = {
  // Floating piece on a track (captcha puzzle).
  raised: '0 6px 16px -6px rgba(0,0,0,.35)',
  // Chart tooltip.
  tooltip: '0 12px 24px -8px rgba(0,0,0,.4)',
  // Floating action button.
  fab: '0 12px 24px -8px rgba(0,0,0,.5)',
  // Command palette on the system board.
  palette: '0 24px 48px -16px rgba(0,0,0,.45)',
  // Palette on screens, dialogs.
  overlay: '0 24px 48px -12px rgba(0,0,0,.5)',
  // Phone bottom sheet.
  sheet: '0 -24px 48px -12px rgba(0,0,0,.5)',
  // Side detail panel.
  panel: '-16px 0 32px -16px rgba(0,0,0,.4)',
  // Full-screen phone detail sliding over a list.
  panelFull: '-24px 0 48px -24px rgba(0,0,0,.5)',
} as const;

// Layers. The boards use 3 (toast) and 5 (palette); the rest are ordered
// around them.
export const zIndex = {
  base: 0,
  sticky: 2,
  toast: 3,
  sheet: 4,
  overlay: 5,
} as const;

// Motion system board: "Motion explains state. It never decorates."
export const duration = {
  instant: 80, // Hover, press, row highlight
  fast: 140, // Chips, toggles, palette, colour changes
  base: 220, // Panels, toasts, badges, list inserts
  slow: 360, // Attack mode, page enter
  data: 420, // Chart paths morphing between ranges
  live: 1400, // Pulse period, stream cadence
  // Leaving is shorter so the next state arrives fast.
  exit: 160, // Panel close, toast out
  remove: 200, // List item removal
  reduced: 120, // Reduced-motion fades
} as const;

export const ease = {
  out: 'cubic-bezier(.16,1,.3,1)', // Everything entering
  in: 'cubic-bezier(.7,0,.84,0)', // Things leaving
  inOut: 'cubic-bezier(.65,0,.35,1)', // State changes in place
  linear: 'linear', // Progress, shimmer, playheads, streams
} as const;

// The only breakpoint of the desktop boards: below it the sidebar becomes a
// horizontal bar. Phone boards are 390 wide; desktop boards 1440.
export const breakpoint = {
  compact: 760,
  phone: 390,
  desktop: 1440,
} as const;

export const layout = {
  sidebarWidth: 232,
  sidebarMinWidth: 220,
  contentMaxWidth: 1440,
  rowHeight: 36, // Dense table row
  headerHeight: 56, // Phone header
  tabBarHeight: 64, // Phone tab bar
  touchTarget: 44,
} as const;

// Score ramp 0–100 with ticks at challenge (40) and block (70); the fill
// takes the tone of the resulting action. The gateway's own thresholds come
// from its policy; these are the design defaults.
export const scoreThreshold = {
  challenge: 40,
  block: 70,
} as const;

export type Tone = 'allowed' | 'challenged' | 'blocked';

export function scoreTone(
  score: number,
  thresholds: { challenge: number; block: number } = scoreThreshold,
): Tone {
  if (score >= thresholds.block) return 'blocked';
  if (score >= thresholds.challenge) return 'challenged';
  return 'allowed';
}
