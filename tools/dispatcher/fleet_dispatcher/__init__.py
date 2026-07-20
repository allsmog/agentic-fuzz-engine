"""Fleet dispatcher: drains the engine's typed job queue with bounded,
headless ``claude -p`` workers.

The dispatcher is a *client* of the engine CLI — exactly like the interactive
session. It composes a small prompt per job (paths-only evidence), spawns a
budget- and wall-clock-bounded worker, saves the full transcript, then asks
the engine's deterministic predicate whether the job succeeded. The engine
never knows an LLM exists; the dispatcher never judges success itself.
"""

__all__ = ["config", "prompts", "runner", "governor", "cli"]
