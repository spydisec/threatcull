# syntax=docker/dockerfile:1
# SPDX-License-Identifier: AGPL-3.0-only
# ThreatCull: one container, data on the /data volume. The image holds the software
# and the Catalog only: no threat data, database, session secret or configuration.

# Docker Hardened Images (https://docs.docker.com/dhi/): the -dev variant has a shell
# and package tools for the build stage; the runtime variant has neither, runs no
# shell and ships signed SBOMs, provenance and VEX. Pulling needs `docker login dhi.io`
# (a free Docker account); ThreatCull users pull the finished image from ghcr.io.
# Building without a Docker account: pass python:3.13-slim for both build arguments;
# BuildKit then skips the dhi-* stages and never contacts dhi.io.
# The DHI images sit in plain FROM lines, pinned by multi-arch digest, so Dependabot can
# see and update them (it does not follow FROM ${ARG}).
ARG PYTHON_BUILD_IMAGE=dhi-build
ARG PYTHON_RUNTIME_IMAGE=dhi-runtime

FROM dhi.io/python:3.13-dev@sha256:d13087cbaf5f8c68c4baac88ea22e4a5f87ac179a9e7004f3484558154b2e344 AS dhi-build
FROM dhi.io/python:3.13@sha256:be3c790e05dd0a4b9f15c76846a2146a75833b3ed4d1fe11e7828fd27446cedd AS dhi-runtime

FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv

FROM ${PYTHON_BUILD_IMAGE} AS build
COPY --link --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first, so a source-only change reuses this layer.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable
# The runtime image has no shell: prepare the data directory here and copy it over.
RUN install -d -m 0700 /rootfs/data

FROM ${PYTHON_RUNTIME_IMAGE} AS runtime
ARG VERSION=dev
LABEL org.opencontainers.image.title="ThreatCull" \
      org.opencontainers.image.description="Self-hosted threat-feed compiler" \
      org.opencontainers.image.source="https://github.com/spydisec/threatcull" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"
# uid 10001, as in 1.x and 2.0 images, so existing /data volumes stay writable. The
# hardened image's own non-root user is 65532; any numeric uid works without an
# /etc/passwd entry.
COPY --link --from=build --chown=10001:10001 /rootfs/data /data
# Root owns the code: the app user can read it but not change it.
COPY --link --from=build /app/.venv /app/.venv
WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
VOLUME ["/data"]
EXPOSE 6969
USER 10001:10001
# The healthcheck assumes the default port. To use another host port, change the host
# side of the port mapping (for example "8080:6969") rather than serve --port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:6969/healthz', timeout=4).status == 200 else 1)"]
# The CLI is the entrypoint: `docker compose run --rm threatcull user create admin` works.
# Inside the container serve binds all interfaces of its own network namespace; the
# compose file decides which host address publishes the port.
ENTRYPOINT ["threatcull", "--data-dir", "/data"]
CMD ["serve", "--host", "0.0.0.0", "--port", "6969"]
