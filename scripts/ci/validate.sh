#!/usr/bin/env bash
# Validate offline fixtures only; never dispatch the diagnostic experiments.
set -euo pipefail

python3 -m json.tool renovate.json >/dev/null
node --test scripts/runner-probe/screen.test.cjs vendor/network-probe/capture.test.cjs
sha256sum -c vendor/SHA256SUMS
