// Renders tokens.ts as CSS custom properties (tokens.css).
//
// Theme selection: dark by default (the design is dark-first), light when the
// system asks for it, and an explicit `data-theme` on <html> wins over both.

import {
  breakpoint,
  color,
  duration,
  ease,
  font,
  fontSize,
  fontWeight,
  layout,
  radius,
  scoreThreshold,
  shadow,
  space,
  type Theme,
  tracking,
  zIndex,
} from './tokens.ts';

// `surface1` → `surface-1`, `onBlockedChip` → `on-blocked-chip`.
export function kebab(name: string): string {
  return name
    .replace(/([a-z])([A-Z0-9])/g, '$1-$2')
    .replace(/\+/g, '-plus')
    .replace(/\./g, '_')
    .toLowerCase();
}

export function cssVar(group: string, name: string): string {
  return `--${group}-${kebab(name)}`;
}

function colorBlock(theme: Theme, indent: string): string {
  return Object.entries(color)
    .map(
      ([name, value]) => `${indent}${cssVar('color', name)}: ${value[theme]};`,
    )
    .join('\n');
}

function px(value: number): string {
  return value === 0 ? '0' : `${value}px`;
}

function staticBlock(): string {
  const lines: string[] = [];
  const add = (group: string, entries: Record<string, string | number>) => {
    for (const [name, value] of Object.entries(entries)) {
      lines.push(`  ${cssVar(group, name)}: ${value};`);
    }
  };
  add('font', font);
  add('weight', fontWeight);
  add(
    'text',
    Object.fromEntries(Object.entries(fontSize).map(([k, v]) => [k, px(v)])),
  );
  add('tracking', tracking);
  add(
    'space',
    Object.fromEntries(Object.entries(space).map(([k, v]) => [k, px(v)])),
  );
  add(
    'radius',
    Object.fromEntries(Object.entries(radius).map(([k, v]) => [k, px(v)])),
  );
  add('shadow', shadow);
  add('z', zIndex);
  add(
    'duration',
    Object.fromEntries(Object.entries(duration).map(([k, v]) => [k, `${v}ms`])),
  );
  add('ease', ease);
  add(
    'layout',
    Object.fromEntries(Object.entries(layout).map(([k, v]) => [k, px(v)])),
  );
  add('score', scoreThreshold);
  return lines.join('\n');
}

export function renderTokensCss(): string {
  return `/* Generated from tokens.ts by \`npm run tokens\`. Do not edit. */
/* Breakpoints (media queries cannot use custom properties):
   compact ${breakpoint.compact}px, phone ${breakpoint.phone}px, desktop ${breakpoint.desktop}px. */

:root {
  color-scheme: dark;
${colorBlock('dark', '  ')}
${staticBlock()}
}

@media (prefers-color-scheme: light) {
  :root:not([data-theme='dark']) {
    color-scheme: light;
${colorBlock('light', '    ')}
  }
}

:root[data-theme='light'] {
  color-scheme: light;
${colorBlock('light', '  ')}
}
`;
}
