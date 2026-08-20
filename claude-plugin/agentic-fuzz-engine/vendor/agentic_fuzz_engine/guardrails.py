from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


FORBIDDEN_RUNTIME_REFERENCES = (
    "RealReferenceExecutionPlane",
    "real_execution.py",
    "REFERENCE_REPO_ROOT",
    "native-harness/docker-run.py",
    "input-generator/run.py",
)
EXECUTABLE_SUFFIXES = {".py", ".sh", ".json"}
DEFAULT_EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".claude-plugin",
}
DEFAULT_EXCLUDED_FILES = {
    "guardrails.py",
}


@dataclass(frozen=True, slots=True)
class AuditFinding:
    path: str
    line: int
    pattern: str
    text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def audit_runtime_guard_runtime_calls(
    roots: Iterable[str | Path],
    *,
    forbidden: tuple[str, ...] = FORBIDDEN_RUNTIME_REFERENCES,
) -> tuple[AuditFinding, ...]:
    findings: list[AuditFinding] = []
    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        files = [base] if base.is_file() else sorted(path for path in base.rglob("*") if path.is_file())
        for path in files:
            if _excluded(path) or path.suffix not in EXECUTABLE_SUFFIXES:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(lines, start=1):
                for pattern in forbidden:
                    if pattern in line:
                        findings.append(
                            AuditFinding(path=str(path), line=number, pattern=pattern, text=line.strip()[:240])
                        )
    return tuple(findings)


def _excluded(path: Path) -> bool:
    if path.name in DEFAULT_EXCLUDED_FILES:
        return True
    return bool(DEFAULT_EXCLUDED_PARTS.intersection(path.parts))
