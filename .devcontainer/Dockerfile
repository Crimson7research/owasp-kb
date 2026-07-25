FROM python:3.13-slim

ARG USER_UID=1000
ARG USER_GID=1000

RUN apt-get update && apt-get install -y --no-install-recommends \
        git make curl ca-certificates build-essential sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# UID/GID must match the host user so bind-mounted files are not root-owned.
RUN groupadd --gid ${USER_GID} dev \
    && useradd --uid ${USER_UID} --gid ${USER_GID} --create-home --shell /bin/bash dev

USER dev
ENV PATH=/home/dev/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /workspace
