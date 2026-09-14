# syntax=docker/dockerfile:1

# ---------- shared base ----------
# Pinned by digest rather than by tag. `python:3.13-slim` moves, so two builds of
# identical source produced different images -- the same hole one layer down that
# the plugin's own image digest exists to close, and it undercuts the immutable
# content tag's reproducibility claim. The cost is that this no longer picks up
# security updates on its own, which is what .github/dependabot.yml is for.
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    OWASP_KB_INDEX=/opt/owasp-kb/owasp-kb.sqlite
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p /opt/owasp-kb \
    && useradd --create-home --uid 10001 owasp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ---------- lite: BM25 only ----------
FROM base AS lite
RUN pip install --no-cache-dir .
COPY dist/owasp-kb-lite.sqlite /opt/owasp-kb/owasp-kb.sqlite
COPY LICENSE licenses/LICENSE-OWASP-ASVS licenses/LICENSE-OWASP-CHEATSHEET licenses/LICENSE-OWASP-MASVS licenses/LICENSE-CWE licenses/NOTICE /opt/owasp-kb/licenses/
USER owasp
LABEL org.opencontainers.image.title="owasp-kb (lite)" \
      org.opencontainers.image.description="OWASP ASVS and Cheat Sheets MCP server, BM25 retrieval" \
      org.opencontainers.image.licenses="MIT AND CC-BY-SA-4.0 AND LicenseRef-CWE-TOU"

# ---------- full: hybrid BM25 + vector ----------
FROM base AS full
RUN pip install --no-cache-dir '.[embed]'
COPY dist/owasp-kb-full.sqlite /opt/owasp-kb/owasp-kb.sqlite
COPY models/bge-small-en-v1.5 /opt/owasp-kb/models/bge-small-en-v1.5
COPY LICENSE licenses/LICENSE-OWASP-ASVS licenses/LICENSE-OWASP-CHEATSHEET licenses/LICENSE-OWASP-MASVS licenses/LICENSE-CWE licenses/NOTICE /opt/owasp-kb/licenses/
ENV OWASP_KB_MODEL_DIR=/opt/owasp-kb/models/bge-small-en-v1.5
USER owasp
LABEL org.opencontainers.image.title="owasp-kb (full)" \
      org.opencontainers.image.description="OWASP ASVS and Cheat Sheets MCP server, hybrid retrieval" \
      org.opencontainers.image.licenses="MIT AND CC-BY-SA-4.0 AND LicenseRef-CWE-TOU"
