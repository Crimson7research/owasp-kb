.PHONY: help fetch model index index-full test test-quality lint serve clean build build-lite build-full docker-smoke

CONTAINER ?= owasp-kb-dev
EXEC      := docker exec -u 1000:1000 $(CONTAINER)
SOURCES   ?= data
DIST      ?= dist

help: ## Show available targets
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

fetch: ## Download pinned upstream sources into data/
	$(EXEC) python -c "from pathlib import Path; \
	from owasp_kb.ingest.lock import load_lock; from owasp_kb.ingest.fetch import fetch_all; \
	print(fetch_all(load_lock('sources.lock.yml'), Path('$(SOURCES)')))"

model: ## Download the embedding model into models/
	$(EXEC) python scripts/download_model.py

index: ## Build the lite index (BM25 only)
	$(EXEC) python -m owasp_kb.ingest.build --sources $(SOURCES) \
		--out $(DIST)/owasp-kb-lite.sqlite

index-full: model ## Build the full index (hybrid)
	$(EXEC) python -m owasp_kb.ingest.build --sources $(SOURCES) \
		--out $(DIST)/owasp-kb-full.sqlite --with-vectors

test: ## Run unit tests
	# Bare pytest, as CI runs it. `python -m pytest` adds the working directory
	# to the import path, so a test importing repository tooling passes here and
	# fails there -- which happened once and cost a red CI run.
	$(EXEC) pytest -q

test-quality: ## Run the retrieval quality gate against built indexes
	$(EXEC) python -m pytest tests/test_retrieval_quality.py -v -s

lint: ## Lint and format-check
	$(EXEC) python -m ruff check .
	$(EXEC) python -m ruff format --check .

plugin-digest: ## Record the plugin content digest after bumping the version
	$(EXEC) python scripts/plugin_digest.py --write

serve: ## Run the MCP server against the full index (for manual stdio testing)
	$(EXEC) python -m owasp_kb.server.app --index $(DIST)/owasp-kb-full.sqlite

IMAGE ?= owasp-kb
ASVS_VERSION ?= $(shell $(EXEC) python -c "import yaml;print(yaml.safe_load(open('sources.lock.yml'))['packs']['asvs']['version'])" | tr -d '\r')
CS_DATE ?= $(shell $(EXEC) python -c "import yaml;print(yaml.safe_load(open('sources.lock.yml'))['packs']['cheatsheets']['version'])" | tr -d '\r')
CWE_VERSION ?= $(shell $(EXEC) python -c "import yaml;print(yaml.safe_load(open('sources.lock.yml'))['packs']['cwe']['version'])" | tr -d '\r')

# The immutable tag names every pack in the index. It named two of three until the
# CWE pack shipped, at which point a CWE release bump -- which deprecates ids and
# renumbers others -- would have produced a byte-different index under an identical
# tag. cwe_get makes CWE ids directly citable, so they are part of what the
# reproducible-citation promise covers, and the tag has to be able to distinguish
# them. Keep this in step with .github/workflows/release.yml.
PINNED_TAG := asvs$(ASVS_VERSION)-cs$(CS_DATE)-cwe$(CWE_VERSION)

build-lite: index ## Build the lite image
	docker build -f docker/Dockerfile --target lite \
		-t $(IMAGE):lite \
		-t $(IMAGE):lite-$(PINNED_TAG) .

build-full: index-full ## Build the full image
	docker build -f docker/Dockerfile --target full \
		-t $(IMAGE):full \
		-t $(IMAGE):full-$(PINNED_TAG) .

build: build-lite build-full ## Build both images

docker-smoke: ## Verify both images serve MCP with no network
	./scripts/docker_smoke.sh $(IMAGE):lite lexical
	./scripts/docker_smoke.sh $(IMAGE):full hybrid

clean: ## Remove build artefacts
	$(EXEC) rm -rf $(DIST) $(SOURCES) models .pytest_cache .ruff_cache
