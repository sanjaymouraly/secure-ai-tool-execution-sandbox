# Hardened image used for every sandboxed execution.
#
# The image is intentionally minimal: a Python 3.12 runtime plus the coreutils
# that ship with the Debian slim base.  No package manager state, no
# compilers, no shell entry point of its own (the broker drives
# /sandbox/entrypoint.py) and it always runs as a dedicated unprivileged uid.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="secure-ai-sandbox-runner" \
      org.opencontainers.image.description="Hardened execution image for the Secure AI Tool Execution & Permission Sandbox" \
      org.opencontainers.image.licenses="MIT"

RUN set -eux; \
    groupadd --gid 10001 sandbox; \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin sandbox; \
    mkdir -p /workspace /sandbox; \
    chmod 1777 /tmp; \
    chown 10001:10001 /workspace

COPY docker/sandbox/entrypoint.py /sandbox/entrypoint.py
RUN chmod 0555 /sandbox/entrypoint.py

ENV PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    HOME=/tmp

WORKDIR /workspace
USER 10001:10001

ENTRYPOINT ["/usr/local/bin/python3", "/sandbox/entrypoint.py"]
