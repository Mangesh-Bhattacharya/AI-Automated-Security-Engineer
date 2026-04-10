# ============================================================
# AI Automated Security Engineer - Dockerfile
# Multi-stage build for production deployment
# ============================================================

# Stage 1: Python dependencies builder
FROM python:3.11-slim AS builder

WORKDIR /build

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    gcc \
    g++ \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Security tools installer
FROM python:3.11-slim AS security-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    nikto \
    sqlmap \
    hydra \
    john \
    hashcat \
    wireshark-common \
    tcpdump \
    netcat-openbsd \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (container vulnerability scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Nuclei (fast vulnerability scanner)
RUN curl -L https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip

# Stage 3: Production image
FROM python:3.11-slim AS production

LABEL maintainer="AI Security Engineer Platform" \
      version="1.0.0" \
      description="Self-hosted AI Automated Security Engineer"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libpq5 \
    nmap \
    curl \
    wget \
    git \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy security tools
COPY --from=security-tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=security-tools /usr/local/bin/nuclei /usr/local/bin/nuclei

# Create non-root user for security
RUN groupadd -r aase && useradd -r -g aase -d /app -s /bin/bash aase

# Create application directories
RUN mkdir -p /app /app/logs /app/data /app/models /app/reports /app/tmp \
    && chown -R aase:aase /app

WORKDIR /app

# Copy application source
COPY --chown=aase:aase . .

# Set environment variables
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production \
    PORT=8443

# Security hardening
RUN chmod -R 750 /app \
    && find /app -name "*.py" -exec chmod 640 {} \;

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f https://localhost:8443/health --insecure || exit 1

# Switch to non-root user
USER aase

EXPOSE 8443

# Start the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8443", \
     "--ssl-keyfile", "/app/certs/server.key", \
     "--ssl-certfile", "/app/certs/server.crt", \
     "--workers", "4", \
     "--access-log", \
     "--log-level", "info"]
