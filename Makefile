PYTHON ?= python3
PIP ?= pip

.PHONY: setup format lint typecheck test test-cov check

setup:
	$(PIP) install -e .[dev]

format:
	$(PYTHON) -m ruff format src tests

lint:
	$(PYTHON) -m ruff check src tests

typecheck:
	$(PYTHON) -m mypy src

test:
	$(PYTHON) -m pytest -q

test-cov:
	$(PYTHON) -m pytest --cov=cp_review --cov-report=term-missing --cov-fail-under=60

check: lint typecheck test-cov
