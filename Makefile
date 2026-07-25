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
	$(EXEC) python -m pytest -q

test-quality: ## Run the retrieval quality gate against built indexes
	$(EXEC) python -m pytest tests/test_retrieval_quality.py -v -s

lint: ## Lint and format-check
	$(EXEC) python -m ruff check .
	$(EXEC) python -m ruff format --check .

serve: ## Run the MCP server against the full index (for manual stdio testing)
	$(EXEC) python -m owasp_kb.server.app --index $(DIST)/owasp-kb-full.sqlite

IMAGE ?= owasp-kb
ASVS_VERSION ?= $(shell $(EXEC) python -c "import yaml;print(yaml.safe_load(open('sources.lock.yml'))['packs']['asvs']['version'])" | tr -d '\r')
CS_DATE ?= $(shell $(EXEC) python -c "import yaml;print(yaml.safe_load(open('sources.lock.yml'))['packs']['cheatsheets']['version'])" | tr -d '\r')

build-lite: index ## Build the lite image
	docker build -f docker/Dockerfile --target lite \
		-t $(IMAGE):lite \
		-t $(IMAGE):lite-asvs$(ASVS_VERSION)-cs$(CS_DATE) .

build-full: index-full ## Build the full image
	docker build -f docker/Dockerfile --target full \
		-t $(IMAGE):full \
		-t $(IMAGE):full-asvs$(ASVS_VERSION)-cs$(CS_DATE) .

build: build-lite build-full ## Build both images

docker-smoke: ## Verify both images serve MCP with no network
	./scripts/docker_smoke.sh $(IMAGE):lite lexical
	./scripts/docker_smoke.sh $(IMAGE):full hybrid

clean: ## Remove build artefacts
	$(EXEC) rm -rf $(DIST) $(SOURCES) models .pytest_cache .ruff_cache
