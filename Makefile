.PHONY: test parity runtime-doctor plugin-validate build-smoke verify clean

PYTHON ?= .venv/bin/python

test:
	$(PYTHON) -m pytest -q

parity:
	$(PYTHON) -m agentic_fuzz_engine.cli parity-full --strict

runtime-doctor:
	$(PYTHON) -m agentic_fuzz_engine.cli runtime-doctor

plugin-validate:
	claude plugin validate --strict claude-plugin/agentic-fuzz-engine

build-smoke:
	uv build
	uv run --isolated --no-project --with dist/*.whl agentic-fuzz-engine --help >/dev/null

verify: test parity runtime-doctor plugin-validate build-smoke

clean:
	find src tests -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf src/*.egg-info
