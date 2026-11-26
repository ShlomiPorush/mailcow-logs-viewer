#!/usr/bin/env bash
# Rebuild frontend/assets/css/utilities.css from the markup. Tailwind comes from
# .github/node-tools/package-lock.json (npm ci: exact versions, integrity-checked,
# no install scripts), the same tools CI uses to check the committed file.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && (pwd -W 2>/dev/null || pwd))"
MSYS_NO_PATHCONV=1 docker run --rm -v "${ROOT}:/repo" -w /repo \
    node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 sh -c "
    mkdir -p /tmp/tools &&
    cp .github/node-tools/package.json .github/node-tools/package-lock.json /tmp/tools/ &&
    npm ci --silent --prefix /tmp/tools --ignore-scripts --no-audit --no-fund >/dev/null &&
    printf '@tailwind base;\n@tailwind components;\n@tailwind utilities;\n' > /tmp/in.css &&
    /tmp/tools/node_modules/.bin/tailwindcss -c .github/tailwind/tailwind.config.cjs -i /tmp/in.css -o frontend/assets/css/utilities.css --minify"
echo "built frontend/assets/css/utilities.css"
