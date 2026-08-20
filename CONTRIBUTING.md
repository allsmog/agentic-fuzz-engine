# Contributing

Thanks for improving Agentic Fuzz Engine.

## Before opening a change

- Keep each change focused and include tests for behavior changes.
- Run `pytest -q` after installing `.[runtime,test]`.
- Run `agentic-fuzz-engine parity-full --strict` and `claude plugin validate --strict claude-plugin/agentic-fuzz-engine` when the plugin surface changes.
- Do not commit fixture outputs, local run artifacts, or credentials.

## Pull requests

Describe the problem, the implementation, and how you verified it. Keep generated artifacts out of the change unless they are intentionally versioned. Review feedback and CI must be resolved before merge.

For a suspected vulnerability, use the private reporting channel described in [SECURITY.md](SECURITY.md) instead of a public issue.
