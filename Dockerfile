FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    postgresql-client \
    curl \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools==83.0.0 && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY backend/app/ /app/app/

# Copy Alembic migrations (applied on startup; CLI usable inside the container)
COPY backend/alembic.ini /app/alembic.ini
COPY backend/alembic/ /app/alembic/

# Copy frontend files
COPY frontend/ /app/frontend/

# Copy VERSION file
COPY VERSION /app/VERSION

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

ENTRYPOINT ["./entrypoint.sh"]

# Public demo image (tag `demo`): the same application plus the demo package,
# which cuts every outbound connection and serves fictional data. Only this
# stage copies backend/demo, so the regular image never contains it.
FROM base AS demo
COPY --chown=appuser:appuser backend/demo/ /app/demo/
# Help panels normally fetch these from GitHub; the demo serves them locally
COPY --chown=appuser:appuser documentation/HelpDocs/ /app/demo/HelpDocs/
# The asyncio loop matters: uvloop connects in C and would bypass the
# Python-level network guard in demo/network_guard.py.
ENV DEMO_MODE=true \
    APP_MODULE=demo.main:app \
    UVICORN_LOOP=asyncio \
    MAILCOW_URL=https://mail.example.com \
    MAILCOW_API_KEY=demo \
    MAILCOW_API_KEY_RW=demo \
    RSPAMD_PASSWORD=demo \
    SETTINGS_EDIT_VIA_UI_ENABLED=true
# Settings set in ENV cannot be changed from the UI. Visitors can change
# everything else; these would lock every other visitor out, load other
# visitors' browsers with an outside image, or let one visitor slow down or
# empty the demo for everyone until the nightly reset. RAW_LOGS_SERVICES is
# free text the Logs page builds its service buttons from.
ENV BASIC_AUTH_ENABLED=false \
    RAW_LOGS_SERVICES=acme,api,autodiscover,dovecot,netfilter,postfix,ratelimited,rspamd-history,sogo,watchdog \
    OAUTH2_ENABLED=false \
    APP_LOGO_URL= \
    LOG_LEVEL=WARNING \
    RETENTION_DAYS=7 \
    RAW_LOGS_RETENTION_DAYS=2 \
    DMARC_RETENTION_DAYS=60 \
    FETCH_INTERVAL=60 \
    FETCH_COUNT_POSTFIX=2000 \
    FETCH_COUNT_RSPAMD=500 \
    FETCH_COUNT_NETFILTER=500 \
    FETCH_MAX_PAGES=50 \
    RAW_LOGS_FETCH_INTERVAL=30 \
    RAW_LOGS_FETCH_COUNT=1000 \
    MAX_CORRELATION_AGE_MINUTES=10 \
    CORRELATION_CHECK_INTERVAL=120 \
    SCHEDULER_WORKERS=4 \
    MAX_SEARCH_RESULTS=1000 \
    CSV_EXPORT_LIMIT=10000

# The regular image. Kept last so a plain `docker build` produces it.
FROM base AS app
