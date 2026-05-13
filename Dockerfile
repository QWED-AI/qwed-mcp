
# ubuntu:24.04 (noble-20260410)
FROM ubuntu@sha256:cdb5fd928fced577cfecf12c8966e830fcdf42ee481fb0b91904eeddc2fe5eff AS builder

WORKDIR /app

# Install Python 3.14 from Deadsnakes PPA on a safe OS (bypasses Debian 12 zlib CVEs).
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common build-essential && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.14 python3.14-venv && \
    rm -rf /var/lib/apt/lists/*

# Copy uv binary from official image — avoids pipe-to-shell (QWED shell_safety)
COPY --from=ghcr.io/astral-sh/uv:0.11.3 /uv /usr/local/bin/uv

RUN uv venv --python 3.14 /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy manifests first for cache-friendly dependency layer
COPY pyproject.toml .
COPY uv.lock .
COPY README.md .

# Install locked dependencies first (no project sources yet) — maximises cache reuse
RUN UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --locked --no-dev --no-install-project

# Now copy source and install the project itself
COPY src/ src/
RUN UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --locked --no-dev

# ubuntu:24.04 (noble-20260410) — same digest as builder
FROM ubuntu@sha256:cdb5fd928fced577cfecf12c8966e830fcdf42ee481fb0b91904eeddc2fe5eff

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# Install Python 3.14 runtime on pristine Ubuntu 24.04.
# software-properties-common is needed only for add-apt-repository; purge it
# afterwards to remove transitive system python3-cryptography (41.0.7) and
# python3-jwt (2.7.0) that Docker Scout flags as vulnerable.
# Our app uses venv-installed cryptography>=48.0.0 and PyJWT>=2.12.0.
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.14 && \
    dpkg-query -W -f='${Package} ${Version}\n' > /var/log/apt-upgraded-packages.txt && \
    apt-get purge -y --auto-remove software-properties-common && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN useradd -m qweduser
USER qweduser

ENTRYPOINT ["qwed-mcp"]
