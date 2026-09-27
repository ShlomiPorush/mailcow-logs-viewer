#!/bin/bash
set -e

# APP_MODULE and UVICORN_LOOP are set only by the demo image (see Dockerfile);
# the regular image runs app.main on uvicorn's default event loop.
set -- uvicorn "${APP_MODULE:-app.main:app}" --host 0.0.0.0 --port 8080 --workers 1 --loop "${UVICORN_LOOP:-auto}"

if [ "$(id -u)" = "0" ]; then
    # Running as root — fix host bind-mount permissions and drop to appuser
    mkdir -p /app/data
    # Ensure container.log exists so chown covers it too
    touch /app/data/container.log
    chown -R 1000:1000 /app/data
    exec gosu appuser "$@"
else
    # Already running as non-root — just start the app
    exec "$@"
fi
