.PHONY: test architecture-audit parity-audit inventory-audit doctor-real live-readiness live-readiness-smoke dev-stack target-sync fuzzml-images agent-session-smoke agent-session-suite list-prompts plugin-validate verify clean

PYTHON ?= .venv/bin/python

test:
	$(PYTHON) -m pytest -q

architecture-audit:
	$(PYTHON) -m agentic_fuzz_control_plane.cli architecture-audit

parity-audit:
	$(PYTHON) -m agentic_fuzz_control_plane.cli parity-audit

inventory-audit:
	$(PYTHON) -m agentic_fuzz_control_plane.cli inventory-audit

doctor-real:
	$(PYTHON) -m agentic_fuzz_control_plane.cli doctor-real

live-readiness:
	$(PYTHON) -m agentic_fuzz_control_plane.cli live-readiness

live-readiness-smoke:
	$(PYTHON) -m agentic_fuzz_control_plane.cli live-readiness --smoke

dev-stack:
	$(PYTHON) -m agentic_fuzz_control_plane.cli dev-stack plan

target-sync:
	$(PYTHON) -m agentic_fuzz_control_plane.cli target-sync plan

fuzzml-images:
	$(PYTHON) -m agentic_fuzz_control_plane.cli fuzzml-images plan

agent-session-smoke:
	$(PYTHON) -m agentic_fuzz_control_plane.cli agent-session-smoke

agent-session-suite:
	$(PYTHON) -m agentic_fuzz_control_plane.cli agent-session-suite

list-prompts:
	$(PYTHON) -m agentic_fuzz_control_plane.cli list-prompts

plugin-validate:
	claude plugin validate claude-plugin/reference-agentic-fuzz

verify: test architecture-audit parity-audit inventory-audit live-readiness-smoke dev-stack target-sync fuzzml-images agent-session-smoke agent-session-suite plugin-validate doctor-real

clean:
	find src tests -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf src/*.egg-info
