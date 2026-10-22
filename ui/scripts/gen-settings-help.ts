// Writes shared/settings-help.ts from the comments of deploy/bot-shield.yaml.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { extractSettingsHelp, renderSettingsHelp } from './settings-help.ts';

const source = fileURLToPath(
  new URL('../../deploy/bot-shield.yaml', import.meta.url),
);
const target = fileURLToPath(
  new URL('../shared/settings-help.ts', import.meta.url),
);
writeFileSync(
  target,
  renderSettingsHelp(extractSettingsHelp(readFileSync(source, 'utf8'))),
);
console.log(`wrote ${target}`);
