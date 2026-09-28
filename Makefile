.DEFAULT_GOAL := help
.PHONY: help setup lint format types test security audit prose catalog-docs ui ui-check check

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

setup: ## Install dependencies and git hooks (pre-commit + commit-msg)
	uv sync
	uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
	uvx vale sync

lint: ## Ruff lint and format check
	uv run ruff check .
	uv run ruff format --check .

prose: ## Vale prose lint on pushed Markdown
	uvx vale sync >/dev/null
	uvx vale README.md SECURITY.md CONTRIBUTING.md CHANGELOG.md docs/CATALOG.md .github
	uv run python scripts/catalog_docs.py --check

catalog-docs: ## Rewrite the Source tables in docs/CATALOG.md from catalog.yaml
	uv run python scripts/catalog_docs.py

format: ## Apply Ruff formatting and safe fixes
	uv run ruff format .
	uv run ruff check --fix .

types: ## mypy --strict (src, plus tests/ when it exists locally)
	@if [ -d tests ]; then uv run mypy; else uv run mypy src; fi

test: ## Tests with coverage (offline); tests/ lives on the maintainer's machine only
	@if [ -d tests ]; then uv run pytest --cov --cov-report=term-missing; \
	else echo "no tests/ directory: tests run on the maintainer's machine"; fi

audit: ## Vulnerability audit of runtime dependencies
	@tmp=$$(mktemp); \
	uv export --frozen --no-dev --no-emit-project --format requirements-txt -o $$tmp >/dev/null && \
	uvx pip-audit --strict --disable-pip -r $$tmp; status=$$?; rm -f $$tmp; exit $$status

security: audit ## bandit, semgrep, pip-audit, gitleaks
	uv run bandit -q -r src
	uvx semgrep scan --config p/python --config .semgrep.yml --error --metrics off --quiet src
	uv run pre-commit run gitleaks --all-files

ui: ## Rebuild the TypeScript islands bundle (needs Node)
	cd frontend && npm ci --silent --ignore-scripts && npm run -s typecheck && npm run -s build

ui-check: ui ## Fail if the committed islands bundle is out of date
	@git diff --quiet -- src/threatcull/web/static/islands.js || { echo "islands.js is out of date: run make ui and stage it"; exit 1; }

check: lint prose types ui-check test security ## CI checks plus the local tests
