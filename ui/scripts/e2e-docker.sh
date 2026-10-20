#!/bin/sh
# Runs the browser tests in the Playwright image CI uses, so screenshots
# match: `npm run e2e:docker` compares, `npm run e2e:docker -- --update-snapshots`
# writes new baselines into tests/e2e/__screenshots__.
set -eu
cd "$(dirname "$0")/.."
version=$(node -p "require('./package.json').devDependencies['@playwright/test']")
mkdir -p tests/e2e/__screenshots__
docker run --rm --ipc=host \
  -v "$PWD:/src:ro" \
  -v "$PWD/tests/e2e/__screenshots__:/screenshots" \
  "mcr.microsoft.com/playwright:v${version}-noble" \
  sh -c '
    set -e
    mkdir /work && cd /src
    tar --exclude=./node_modules --exclude=./dist --exclude=./test-results -cf - . | tar -xf - -C /work
    cd /work && npm ci --no-audit --no-fund >/dev/null && npm run build:web >/dev/null
    rm -rf tests/e2e/__screenshots__ && ln -s /screenshots tests/e2e/__screenshots__
    CI=1 npx playwright test "$@"
  ' e2e "$@"
