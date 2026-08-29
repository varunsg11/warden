.DEFAULT_GOAL := help
PY ?= python

.PHONY: help install format lint typecheck test cov check demo eval docker clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev extras
	$(PY) -m pip install -e ".[dev]"

format: ## Auto-format the code
	ruff format .

lint: ## Lint (ruff)
	ruff check .

typecheck: ## Type-check (mypy)
	mypy

test: ## Run the test suite
	pytest

cov: ## Run tests with coverage report
	pytest --cov

check: lint typecheck test ## Run lint + type-check + tests

demo: ## Run the governed demo offline
	warden governed --fake

eval: ## Print the containment / false-quarantine numbers
	warden eval

docker: ## Build the Docker image
	docker build -t warden .

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage \
		dist build **/__pycache__ *.egg-info src/*.egg-info audit
