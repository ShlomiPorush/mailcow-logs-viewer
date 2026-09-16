FROM python:3.11-slim

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