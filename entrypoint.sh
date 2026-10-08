#!/bin/bash
set -e

# APP_MODULE and UVICORN_LOOP are set only by the demo image (see Dockerfile);
# the regular image runs app.main on uvicorn's default event loop.
set -- uvicorn "${APP_MODULE:-app.main:app}" --host 0.0.0.0 --port 8080 --workers 1 --loop "${UVICORN_LOOP:-auto}"

if [ "$(id -u)" = "0" ]; then
    # Running as root — fix host bind-mount permissions and drop to appuser
    mkdir -p /app/data
    chown -R 1000:1000 /app/data
    # Create container.log as appuser, not as root: a symlink planted in the
    # data directory must not make root create or touch a file elsewhere
    gosu appuser touch /app/data/container.log
    exec gosu appuser "$@"
else
    # Already running as non-root — just start the app
    exec "$@"
fi
