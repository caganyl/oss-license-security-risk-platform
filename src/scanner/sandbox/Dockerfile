# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# OSS Risk Platform — Sandbox Scanner Image
#
# Purpose: isolated, ephemeral container for cloning repositories and parsing
# OSS dependencies. Runs as a non-root user; workspace is wiped on exit.
#
# MVP ecosystems: Node.js (npm/yarn) and Python (pip/poetry/uv).
# ---------------------------------------------------------------------------

FROM debian:12-slim AS base

# ----------------------------------
# System packages
# ----------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
        gnupg \
        jq \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------
# Node.js 20 LTS (via NodeSource)
# ----------------------------------
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version && npm --version

# ----------------------------------
# Python 3.11 + pip
# ----------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 --version

# ----------------------------------
# Scanning & SBOM tools
# ----------------------------------

# Python: pip-audit (CVE detection) + cyclonedx-bom (SBOM generation)
RUN pip3 install --no-cache-dir --break-system-packages \
    pip-audit==2.7.3 \
    cyclonedx-bom==4.4.3

# Node.js: CycloneDX npm plugin + license extractor
RUN npm install --global --no-fund --no-audit \
        @cyclonedx/cyclonedx-npm@1.19.3 \
        license-checker-rseidelsohn@4.4.2 \
    && npm cache clean --force

# ----------------------------------
# Non-root scanner user
# ----------------------------------
RUN groupadd --gid 10001 scanner \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --home-dir /home/scanner \
        --create-home \
        --shell /usr/sbin/nologin \
        scanner \
    && mkdir -p /workspace \
    && chown scanner:scanner /workspace \
    && chmod 700 /workspace

# Pre-populate known_hosts so git doesn't prompt on first connect
# (network is restricted during scans, but clone happens before that layer)
RUN mkdir -p /home/scanner/.ssh \
    && ssh-keyscan -H github.com gitlab.com ssh.dev.azure.com 2>/dev/null \
        >> /home/scanner/.ssh/known_hosts \
    && chown -R scanner:scanner /home/scanner/.ssh \
    && chmod 700 /home/scanner/.ssh \
    && chmod 600 /home/scanner/.ssh/known_hosts

# ----------------------------------
# Entrypoint
# ----------------------------------
COPY --chown=scanner:scanner entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 550 /usr/local/bin/entrypoint.sh

USER scanner
WORKDIR /workspace

# Scan result is written to stdout as a single JSON object.
# The calling worker reads it on container exit.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
