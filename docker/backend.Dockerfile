# ---------------------------------------------------------------------------
# Backend image for the Secure AI Tool Execution & Permission Sandbox.
#
# The image runs the trusted control plane only.  It talks to the Docker
# daemon through the socket mounted by Compose; the socket is never exposed
# to a sandbox worker.
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# The Docker client is required: the broker uses it to start the hardened
# sandbox containers.  The static binary is used so that no daemon or
# container runtime is pulled into this image.
ARG DOCKER_CLI_VERSION=27.3.1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) darch=x86_64 ;; \
        arm64) darch=aarch64 ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${darch}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker /tmp/docker.tgz; \
    docker --version; \
    groupadd --gid 10001 app; \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app
COPY backend/policies ./policies
COPY backend/attack_lab ./attack_lab

# The hardened seccomp profile that the broker applies to every container.
COPY docker/seccomp/sandbox.json ./docker/seccomp/sandbox.json

ENV SAXIS_SANDBOX_SECCOMP_PROFILE_PATH=/app/docker/seccomp/sandbox.json

RUN mkdir -p /app/data/artifacts && chown -R 10001:10001 /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
