"""Trust-boundary (entry-class) map for sink ranking.

Every campaign so far has confirmed the same shape: the findings that
matter come from a small set of trust boundaries (stored data a tamperer
can reach, bytes a compromised peer returns), while primitive-only
ranking spreads effort evenly across internal parsers nobody hostile can
feed. The judgment of *which paths sit on which boundary* cannot be
derived from the code — so it is an authored input, applied
deterministically:

``work/boundaries.json``::

    {"classes": {"external-data": 5, "stored-data": 4,
                 "peer-service": 3, "config": 2, "internal": 1},
     "globs": [{"glob": "pkgstore/*", "class": "stored-data"},
               {"glob": "nas/smb/*", "class": "peer-service"}],
     "default_class": "internal"}

Glob semantics are ``fnmatch`` against the repo-relative path (``*``
crosses directory separators, so ``pkgstore/*`` covers the whole
subtree). First matching glob wins. A missing map means every path
classifies to weight 1 — identical ranking to the pre-boundary engine.
"""

from __future__ import annotations

import json
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

BOUNDARIES_RELATIVE = Path("work/boundaries.json")
DEFAULT_CLASS = "internal"
DEFAULT_WEIGHT = 1


def load_boundaries(root: Path | None) -> dict[str, Any] | None:
    if root is None:
        return None
    path = root / BOUNDARIES_RELATIVE
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload.get("classes"), dict) or not isinstance(payload.get("globs"), list):
        return None
    return payload


def classify_path(rel_path: str, boundaries: dict[str, Any] | None) -> tuple[str, int]:
    """(entry_class, weight) for a repo-relative path; first glob wins."""
    if not boundaries:
        return DEFAULT_CLASS, DEFAULT_WEIGHT
    classes = boundaries.get("classes") or {}
    for rule in boundaries.get("globs") or []:
        pattern = str(rule.get("glob") or "")
        if pattern and fnmatch(rel_path, pattern):
            entry_class = str(rule.get("class") or DEFAULT_CLASS)
            return entry_class, _weight(classes, entry_class)
    entry_class = str(boundaries.get("default_class") or DEFAULT_CLASS)
    return entry_class, _weight(classes, entry_class)


def _weight(classes: dict[str, Any], entry_class: str) -> int:
    try:
        return max(1, int(classes.get(entry_class, DEFAULT_WEIGHT)))
    except (TypeError, ValueError):
        return DEFAULT_WEIGHT
