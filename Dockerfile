# syntax=docker/dockerfile:1
# SPDX-License-Identifier: AGPL-3.0-only
# ThreatCull: one container, data on the /data volume. The image holds the software
# and the Catalog only: no threat data, database, session secret or configuration.

# Docker Hardened Images (https://docs.docker.com/dhi/): the -dev variant has a shell
# and package tools for the build stage; the runtime variant has neither, runs no
# shell and ships signed SBOMs, provenance and VEX. Pulling needs `docker login dhi.io`
# (a free Docker account); ThreatCull users pull the finished image from ghcr.io.
# Building without a Docker account: pass python:3.14-slim for both build arguments;
# BuildKit then skips the dhi-* stages and never contacts dhi.io.
# The DHI images sit in plain FROM lines, pinned by multi-arch digest, so Dependabot can
# see and update them (it does not follow FROM ${ARG}).
ARG PYTHON_BUILD_IMAGE=dhi-build
ARG PYTHON_RUNTIME_IMAGE=dhi-runtime

FROM dhi.io/python:3.14-dev@sha256:8592b76e5f4433ba868e2f6804789c27332dc8bb0ee3fe5c9e9fee304154461c AS dhi-build
FROM dhi.io/python:3.14@sha256:1d19cb038f46dcc8cfe6fdff21fe70d32787e7cfea220cb131f340fa37cece08 AS dhi-runtime

FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

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
# THREATCULL_DATA_DIR is the CLI's default --data-dir, so
# `docker exec threatcull threatcull <command>` works without --data-dir.
# SQLITE_TMPDIR and TMPDIR put SQLite's temporary files (millions of rows during a
# Fetch or Compile) and spooled downloads on the data volume, not in /tmp, which
# may be a tmpfs counted as RAM.
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    THREATCULL_DATA_DIR=/data \
    SQLITE_TMPDIR=/data \
    TMPDIR=/data
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
