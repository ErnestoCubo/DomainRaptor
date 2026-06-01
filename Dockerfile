# DomainRaptor — multi-stage build
# Pinned base by digest per HARD RULE 18 (see security.instructions.md).
# Replace the digest when bumping Python; verify via `docker pull`.

# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12
ARG PYTHON_DIGEST=sha256:placeholder-replace-on-first-release

############################
# Stage 1 — builder
############################
FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

# Install uv (pinned)
COPY --from=ghcr.io/astral-sh/uv:0.10.12 /uv /usr/local/bin/uv

WORKDIR /build

# Lockfile-first for cache friendliness
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# Build into a venv we can copy to the runtime stage
RUN uv sync --frozen --no-dev --extra postgres --extra mysql

############################
# Stage 2 — runtime
############################
FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

# Non-root user
RUN groupadd --system --gid 1001 dr \
 && useradd --system --uid 1001 --gid dr --create-home --shell /usr/sbin/nologin dr

WORKDIR /app

COPY --from=builder --chown=dr:dr /build/.venv /app/.venv
COPY --from=builder --chown=dr:dr /build/src /app/src
COPY --chown=dr:dr pyproject.toml README.md /app/

USER dr

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD dr --version || exit 1

ENTRYPOINT ["dr"]
CMD ["--help"]
