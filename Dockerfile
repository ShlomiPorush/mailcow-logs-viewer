# The base image is pinned by digest, so a rebuild of the same commit starts
# from the same bytes. The tag stays readable; Dependabot moves the digest.
FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c

WORKDIR /app

# Install system dependencies. No compiler: every Python package is installed
# from a wheel (see below), and psycopg2-binary bundles its own libpq.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    postgresql-client \
    curl \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Install the Python dependencies from the lock file (backend/requirements.txt,
# generated from backend/requirements.in). --require-hashes refuses any package
# that is not pinned in it or whose download does not match a recorded hash,
# --no-deps stops pip from resolving anything beyond the lock, and
# --only-binary means no sdist, and so no build backend, is ever downloaded or
# run. pip and setuptools are upgraded from the same lock file.
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --no-deps --only-binary=:all: \
        -r requirements.txt && \
    pip check

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