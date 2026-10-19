// Writes src/design/tokens.css from src/design/tokens.ts.

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { renderTokensCss } from '../src/design/tokens-css.ts';

const target = fileURLToPath(
  new URL('../src/design/tokens.css', import.meta.url),
);
writeFileSync(target, renderTokensCss());
console.log(`wrote ${target}`);
