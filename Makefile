.DEFAULT_GOAL := help
.PHONY: help setup lint format types test security audit prose ui ui-check check

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
	uvx vale README.md .github

format: ## Apply Ruff formatting and safe fixes
	uv run ruff format .
	uv run ruff check --fix .

types: ## mypy --strict
	uv run mypy

test: ## Tests with coverage (offline)
	uv run pytest --cov --cov-report=term-missing

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
	git diff --exit-code -- src/threatcull/web/static/islands.js

check: lint prose types ui-check test security ## Everything CI runs
