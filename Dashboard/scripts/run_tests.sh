#!/usr/bin/env sh
set -eu
python -m pytest python_gateway/tests
node --test tests/rendered-html.test.mjs
