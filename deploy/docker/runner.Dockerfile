# BraimSec scan-runner service image.
#
# The narrow scan-only API in front of the Docker daemon (runner/runner.py,
# stdlib only — no pip dependencies). This is the ONLY service that may
# spawn sandbox containers; the Celery worker talks to it over HTTP and
# holds no Docker access at all.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# --- Docker CLI (client only, no daemon) --------------------------------
# Pinned version + sha256 of the official static build (same pin as
# deploy/Dockerfile.prod — keep the two in sync).
ARG DOCKER_VERSION=27.3.1
ARG DOCKER_SHA256=9b4f6fe406e50f9085ee474c451e2bb5adb119a03591f467922d3b4e2ddf31d3
RUN curl -sSL -o /tmp/docker.tgz \
        https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz \
    && echo "${DOCKER_SHA256}  /tmp/docker.tgz" | sha256sum -c - \
    && tar -xzf /tmp/docker.tgz -C /tmp docker/docker \
    && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker.tgz /tmp/docker \
    && docker --version

WORKDIR /srv/runner
COPY runner/runner.py ./runner.py

# Internal compose network only — never published, no Caddy route.
EXPOSE 8001

CMD ["python", "runner.py"]
