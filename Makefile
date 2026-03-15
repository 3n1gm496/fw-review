PYTHON ?= python3
PIP ?= pip
XDG_CACHE_HOME ?= ./.cache

.PHONY: setup format lint typecheck test test-cov sbom audit benchmark check

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

sbom:
	mkdir -p output
	$(PYTHON) -m cyclonedx_py environment -o output/sbom.cdx.json --of JSON

audit:
	mkdir -p $(XDG_CACHE_HOME)/pip-audit
	$(PYTHON) -m pip freeze | rg -v '^(cp-review==|-e )' > $(XDG_CACHE_HOME)/pip-audit/requirements-audit.txt
	XDG_CACHE_HOME=$(XDG_CACHE_HOME) $(PYTHON) -m pip_audit --strict --cache-dir $(XDG_CACHE_HOME)/pip-audit -r $(XDG_CACHE_HOME)/pip-audit/requirements-audit.txt

benchmark:
	$(PYTHON) scripts/benchmark_flatten.py

check: lint typecheck test-cov
