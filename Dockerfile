
# Use an official Python runtime as a parent image
FROM python:3.14-slim-bookworm AS builder

# Set work directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

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
FROM python:3.14-slim-bookworm

WORKDIR /app

# Patch system-level vulnerabilities and log upgraded packages for AI-BOM audit trail
RUN apt-get update && apt-get upgrade -y && \
    dpkg-query -W -f='${Package} ${Version}\n' > /var/log/apt-upgraded-packages.txt && \
    rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
# Prevent python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1

# Create a non-root user
RUN useradd -m -u 1000 qweduser
USER qweduser

# Expose stdio (not a network port, as MCP uses stdio)
# But strictly speaking we don't EXPOSE for stdio.

# Entrypoint
ENTRYPOINT ["qwed-mcp"]
