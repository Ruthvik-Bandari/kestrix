# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
#
# Production image for Kestrix hosted mode (ADR 0004, slice H3). See docs/deploy.md.
#
# Every base image is pinned by its multi-arch index digest. To update one, run
#   docker buildx imagetools inspect <name>:<tag>
# and replace the digest after "@sha256:" (keep the tag beside it for readability).
#
# Runtime contract: runs as uid 10001, works with a read-only root filesystem, and writes
# only to /data (the SQLite volume) and /tmp (mount a tmpfs; large uploads spill there from
# SpooledTemporaryFile and are never kept).

# Stage 1: build the dashboard into src/kestrix/server/static (vite.config.ts sets outDir).
# The bundle is platform independent, so this stage runs on the build machine's architecture.
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS dashboard
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
# --ignore-scripts: no dependency install hooks run; the lockfile pins every package.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Stage 2: build the wheel and a virtual environment holding only the locked runtime dependencies
# (no dev or gpu groups, no ai or exif extras).
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.16@sha256:440fd6477af86a2f1b38080c539f1672cd22acb1b1a47e321dba5158ab08864d /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file /build/requirements.txt \
 && uv venv /opt/kestrix --python /usr/local/bin/python3.12 \
 && uv pip install --python /opt/kestrix/bin/python --require-hashes --no-deps -r /build/requirements.txt
COPY src/kestrix ./src/kestrix
COPY --from=dashboard /build/src/kestrix/server/static ./src/kestrix/server/static
# The build backend is uv_build, which the pinned uv binary above implements itself, so nothing is
# downloaded for the build; --offline makes the build fail rather than fetch a backend if that changes.
RUN test -f src/kestrix/server/static/index.html \
 && uv build --offline --wheel --out-dir /build/dist \
 && uv pip install --python /opt/kestrix/bin/python --no-deps /build/dist/kestrix-*.whl

# Final stage: the same Python base, the venv, and nothing else.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
LABEL org.opencontainers.image.title="kestrix" \
      org.opencontainers.image.description="Kestrix hosted mode: website check, forensics and email check with sign-in" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/Ruthvik-Bandari/kestrix"
# The base image's pip is not needed at runtime. The service account has no home and no login shell.
RUN python -m pip uninstall --yes --quiet pip \
 && groupadd --system --gid 10001 kestrix \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin kestrix \
 && mkdir -p /data \
 && chown 10001:10001 /data \
 && chmod 0700 /data
COPY --from=builder /opt/kestrix /opt/kestrix
ENV PATH="/opt/kestrix/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KESTRIX_MODE=hosted \
    KESTRIX_DB=/data/kestrix.db \
    KESTRIX_HOME=/data \
    PORT=8000
VOLUME ["/data"]
EXPOSE 8000
USER 10001:10001
# Docker and Compose use this; Fly.io ignores it and uses the checks in fly.toml. The Host
# allowlist only accepts the public host, so the probe sends it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,urllib.parse as p,urllib.request as r; r.urlopen(r.Request('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '8000'), headers={'Host': p.urlsplit(os.environ['KESTRIX_PUBLIC_ORIGIN']).netloc}), timeout=4)"]
ENTRYPOINT ["kestrix", "serve-hosted"]
