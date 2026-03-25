
# Use an official Python runtime as a parent image
FROM python:3.14-alpine AS builder

# Set work directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache build-base

# Install uv for fast package management and upgrade wheel to patch CVE-2026-24049
RUN pip install "uv>=0.5.1" "wheel>=0.46.2" "setuptools>=78.1.1"

# Copy project files (dependencies only to optimize layer caching)
COPY pyproject.toml .
COPY README.md .

# Create virtual environment
RUN uv venv /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Now copy source code and install the package
COPY src/ src/
RUN uv pip install .

# Runtime stage
FROM python:3.14-alpine

WORKDIR /app

# Patch system-level vulnerabilities and log upgraded packages for AI-BOM audit trail
RUN apk update && apk upgrade && \
    apk info -v > /var/log/apk-upgraded-packages.txt

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
# Prevent python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1

# Create a non-root user
RUN adduser -D -u 1000 qweduser
USER qweduser

# Expose stdio (not a network port, as MCP uses stdio)
# But strictly speaking we don't EXPOSE for stdio.

# Entrypoint
ENTRYPOINT ["qwed-mcp"]
