# ── DarkPulse — Dockerfile ────────────────────────────────────────────────────
# Serves the FastAPI ui_server.py on port 8000.
# Build:  docker build -t darkpulse-api .
# Run:    docker-compose up

FROM python:3.11-slim-bookworm

ARG TRIVY_VERSION=0.70.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System deps (for Playwright, lxml, etc.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    trivy --version

WORKDIR /app

# Install crawler/API runtime dependencies first (leverages Docker layer cache)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install --with-deps chromium

# Copy the full project
COPY . .

# Create logs directory
RUN mkdir -p logs

# Non-root user for security
RUN useradd -m -u 1000 darkpulse && chown -R darkpulse:darkpulse /app
USER darkpulse

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "ui_server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
