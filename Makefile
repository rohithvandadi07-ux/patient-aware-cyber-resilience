# Patient-Aware Cyber-Resilience - developer entry points
.DEFAULT_GOAL := help
PY ?= python3

.PHONY: help install install-dev lint format typecheck test test-unit test-scenarios \
        test-e2e coverage api sim demo experiments up down clean

help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime dependencies
	$(PY) -m pip install -e .

install-dev: ## Install runtime + dev + ml dependencies and git hooks
	$(PY) -m pip install -e ".[dev,ml]"
	pre-commit install

lint: ## Run ruff lint
	ruff check .

format: ## Auto-format with ruff
	ruff format .
	ruff check . --fix

typecheck: ## Run mypy
	mypy backend iomt_simulator cybersecurity risk_engine agents response_engine recovery blockchain

test: ## Run the full test suite
	pytest

test-unit: ## Run unit tests only
	pytest -m unit

test-scenarios: ## Run the three mandated research scenarios
	pytest -m scenario -v

test-e2e: ## Run end-to-end closed-loop tests
	pytest -m e2e -v

coverage: ## Run tests with coverage report
	pytest --cov=. --cov-report=term-missing --cov-report=html

api: ## Start the FastAPI backend (reload)
	uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

sim: ## Run the IoMT simulator standalone
	$(PY) -m iomt_simulator.cli run --scenario configs/scenarios/baseline_normal.yaml

demo: ## Run the full closed-loop demonstration
	$(PY) scripts/run_demo.py

experiments: ## Run the reproducible experiment suite
	$(PY) scripts/run_experiments.py --all

up: ## Start the full stack with Docker Compose
	docker compose up --build -d

down: ## Stop the Docker Compose stack
	docker compose down -v

clean: ## Remove caches and build artifacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage build dist *.egg-info
