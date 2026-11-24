#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && (pwd -W 2>/dev/null || pwd))"
MSYS_NO_PATHCONV=1 docker run --rm -v "${ROOT}:/repo" -w /repo node:20-alpine sh -c "
    npm install --silent --no-save --prefix /tmp/tw tailwindcss@3.4.17 >/dev/null &&
    printf '@tailwind base;\n@tailwind components;\n@tailwind utilities;\n' > /tmp/in.css &&
    /tmp/tw/node_modules/.bin/tailwindcss -c .github/tailwind/tailwind.config.cjs -i /tmp/in.css -o frontend/assets/css/utilities.css --minify"
echo "built frontend/assets/css/utilities.css"
