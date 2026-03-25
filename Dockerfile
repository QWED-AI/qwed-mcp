
# Use Ubuntu 24.04 to bypass Debian 12 Zlib vulnerabilities while keeping glibc for fast z3-solver wheel installations
FROM ubuntu:24.04 AS builder

WORKDIR /app

# Install Python 3.14 from Deadsnakes PPA to satisfy the 3.14 requirement on a safe OS
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common curl build-essential && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.14 python3.14-venv && \
    rm -rf /var/lib/apt/lists/*

# Install uv for fast package management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Install wheel patches
RUN uv pip install --python 3.14 "uv>=0.5.1" "wheel>=0.46.2" "setuptools>=78.1.1"

COPY pyproject.toml .
COPY README.md .

RUN uv venv --python 3.14 /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY src/ src/
RUN uv pip install .

# Runtime stage
FROM ubuntu:24.04

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# Install Python 3.14 runtime on pristine Ubuntu 24.04 and log packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.14 && \
    dpkg-query -W -f='${Package} ${Version}\n' > /var/log/apt-upgraded-packages.txt && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN useradd -m -u 1000 qweduser
USER qweduser

ENTRYPOINT ["qwed-mcp"]
