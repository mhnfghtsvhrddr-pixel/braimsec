# BraimSec scan-runner: sandboxed engine image.
# Runs semgrep + gitleaks on /target (mounted read-only, --network none)
# and writes normalized findings to /out/findings.json.
# Built on the Hetzner host (needs registry access); never built in CI
# without network, because the semgrep ruleset is vendored at build time.
FROM python:3.12-slim-bookworm AS rules
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates && rm -rf /var/lib/apt/lists/*
# Pinned snapshot of the registry ruleset ("auto" needs the network, so we
# freeze it into the image). Sparse checkout keeps the layer small.
# NOTE 2026-10-02: upstream renamed the default branch main -> develop.
ARG SEMGREP_RULES_REF=develop
RUN git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/semgrep/semgrep-rules.git /opt/rules && \
    cd /opt/rules && \
    git sparse-checkout set \
        python javascript typescript go java ruby php csharp \
        kotlin swift scala rust c cpp bash dockerfile yaml json \
        generic secrets && \
    git checkout ${SEMGREP_RULES_REF} && \
    rm -rf /opt/rules/.git && \
    find /opt/rules -maxdepth 1 -type f -delete && \
    echo "vendored rules: $(find /opt/rules -name '*.yaml' -o -name '*.yml' | wc -l) files"

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl && rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir "semgrep==1.178.0"
# Gitleaks static binary (pinned version + sha256 of the release tarball;
# same version as deploy/Dockerfile.prod).
ARG GITLEAKS_VERSION=8.28.0
ARG GITLEAKS_SHA256=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
RUN curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" && \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks && \
    mkdir -p /opt/engines/bin && \
    install -m 0755 /tmp/gitleaks /opt/engines/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz /tmp/gitleaks && \
    cp -a /usr/local/bin/semgrep /opt/engines/bin/semgrep && \
    /opt/engines/bin/semgrep --version
COPY --from=rules /opt/rules /opt/rules
# Fail the build if any vendored rule file is unparsable: a broken ruleset
# must never ship (semgrep aborts the whole scan on one invalid config).
# NOTES:
# - `python3 -m semgrep` is a hard-deprecated stub since 1.38 (prints a
#   warning and exits 2 without running anything) -- always use the real
#   console script /opt/engines/bin/semgrep.
# - No `| tail`: a pipe would hide a failing validate behind tail's exit
#   code and the build would NOT fail.
RUN SEMGREP_SEND_METRICS=off /opt/engines/bin/semgrep --validate \
        --config /opt/rules
# BraimSec's own scanner code + custom rules.
COPY scanner/ /opt/scanner/
COPY scanner/rules/ /opt/rules-braimsec/
COPY deploy/docker/runner-entrypoint.py /opt/runner-entrypoint.py
# Validate BraimSec's own packs as well: one broken custom rule aborts the
# whole scan (fail closed), so a bad pack must never ship either. This runs
# at build time because --validate needs the network.
RUN SEMGREP_SEND_METRICS=off /opt/engines/bin/semgrep --validate \
        --config /opt/rules-braimsec
ENV SEMGREP_BIN=/opt/engines/bin/semgrep \
    GITLEAKS_BIN=/opt/engines/bin/gitleaks
ENTRYPOINT ["python3", "/opt/runner-entrypoint.py"]
