from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from .dedupe import finding_quality, finding_signature

UTC = timezone.utc


@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    target: str
    harness: str
    sanitizer: str
    error_token: str
    poc_artifact: str | None
    crash_output: str
    signature: str
    created_at: str
    reproductions: int | None = None
    verified: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EngineState:
    def __init__(self, data_root: str | Path) -> None:
        self.data_root = Path(data_root).expanduser().resolve()
        self.data_root.mkdir(parents=True, exist_ok=True)

    def campaign_start(self, target: str, *, name: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        run_id = name or f"{_slug(target)}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "run_id": run_id,
            "target": target,
            "status": "started",
            "created_at": _now(),
            "metadata": metadata or {},
        }
        self._write_json(run_dir / "campaign.json", state)
        self.event_append(run_id, "campaign_started", state)
        return state

    def campaign_status(self, run_id: str) -> dict[str, Any]:
        run_dir = self._run_dir(run_id)
        campaign = self._read_json(run_dir / "campaign.json")
        return {
            "campaign": campaign,
            "events": self._read_jsonl(run_dir / "events.jsonl")[-20:],
            "checkpoints": self._read_jsonl(run_dir / "checkpoints.jsonl")[-20:],
            "artifacts": [path.name for path in (run_dir / "artifacts").glob("*")] if (run_dir / "artifacts").exists() else [],
            "findings": self._read_jsonl(run_dir / "findings.jsonl"),
        }

    def event_append(self, run_id: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        event = {"ts": _now(), "type": event_type, "payload": payload}
        path = self._run_dir(run_id) / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        return event

    def artifact_put(self, run_id: str, name: str, content_b64: str) -> dict[str, Any]:
        data = base64.b64decode(content_b64.encode("ascii"))
        artifact_name = _safe_name(name)
        path = self._run_dir(run_id) / "artifacts" / artifact_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        result = {"name": artifact_name, "path": str(path), "sha256": sha256(data).hexdigest(), "size": len(data)}
        self.event_append(run_id, "artifact_put", result)
        return result

    def artifact_get(self, run_id: str, name: str) -> dict[str, Any]:
        path = self._run_dir(run_id) / "artifacts" / _safe_name(name)
        data = path.read_bytes()
        return {
            "name": path.name,
            "path": str(path),
            "sha256": sha256(data).hexdigest(),
            "size": len(data),
            "content_b64": base64.b64encode(data).decode("ascii"),
        }

    def artifact_list(self, run_id: str) -> dict[str, Any]:
        artifact_dir = self._run_dir(run_id) / "artifacts"
        artifacts = []
        if artifact_dir.exists():
            for path in sorted(artifact_dir.iterdir()):
                if path.is_file():
                    data = path.read_bytes()
                    artifacts.append({"name": path.name, "sha256": sha256(data).hexdigest(), "size": len(data)})
        return {"run_id": run_id, "artifacts": artifacts}

    def checkpoint_record(self, run_id: str, checkpoint: dict[str, Any]) -> dict[str, Any]:
        record = {
            "checkpoint_id": f"checkpoint-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}",
            "created_at": _now(),
            **checkpoint,
        }
        path = self._run_dir(run_id) / "checkpoints.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self.event_append(
            run_id,
            "campaign_checkpoint_recorded",
            {
                "checkpoint_id": record["checkpoint_id"],
                "phase": record["phase"],
                "harness": record["harness"],
                "blocked": record["blocked"],
            },
        )
        return record

    def checkpoint_list(self, run_id: str) -> dict[str, Any]:
        return {"run_id": run_id, "checkpoints": self._read_jsonl(self._run_dir(run_id) / "checkpoints.jsonl")}

    def finding_record(
        self,
        run_id: str,
        *,
        target: str,
        harness: str,
        sanitizer: str,
        error_token: str,
        crash_output: str,
        poc_artifact: str | None = None,
        reproductions: int | None = None,
        verified: bool | None = None,
    ) -> dict[str, Any]:
        signature = finding_signature(
            target=target,
            harness=harness,
            sanitizer=sanitizer,
            error_token=error_token,
            crash_output=crash_output,
        )
        finding = FindingRecord(
            finding_id=f"finding-{signature}",
            target=target,
            harness=harness,
            sanitizer=sanitizer,
            error_token=error_token,
            poc_artifact=poc_artifact,
            crash_output=crash_output,
            signature=signature,
            created_at=_now(),
            reproductions=reproductions,
            verified=verified,
        )
        path = self._run_dir(run_id) / "findings.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(finding.to_dict(), sort_keys=True) + "\n")
        self.event_append(run_id, "finding_recorded", finding.to_dict())
        return finding.to_dict()

    def finding_dedupe(self, run_id: str) -> dict[str, Any]:
        findings = self._read_jsonl(self._run_dir(run_id) / "findings.jsonl")
        artifact_sizes = {str(item["name"]): int(item["size"]) for item in self.artifact_list(run_id)["artifacts"]}
        groups: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            groups.setdefault(str(finding["signature"]), []).append(finding)
        ranked_groups = []
        for signature, items in sorted(groups.items()):
            ranked = sorted(
                items,
                key=lambda item: finding_quality(item, artifact_sizes=artifact_sizes)["score"],
                reverse=True,
            )
            representative = ranked[0]
            ranked_groups.append(
                {
                    "signature": signature,
                    "count": len(items),
                    "representative": representative,
                    "representative_quality": finding_quality(representative, artifact_sizes=artifact_sizes),
                    "duplicates": ranked[1:],
                    "duplicate_qualities": [
                        finding_quality(item, artifact_sizes=artifact_sizes)
                        for item in ranked[1:]
                    ],
                }
            )
        return {"run_id": run_id, "groups": ranked_groups}

    def finding_list(self, run_id: str) -> list[dict[str, Any]]:
        return self._read_jsonl(self._run_dir(run_id) / "findings.jsonl")

    def event_list(self, run_id: str) -> list[dict[str, Any]]:
        return self._read_jsonl(self._run_dir(run_id) / "events.jsonl")

    def worktree_dir(self, run_id: str, name: str) -> Path:
        path = self._run_dir(run_id) / "worktrees" / _safe_name(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _run_dir(self, run_id: str) -> Path:
        return self.data_root / "runs" / _safe_name(run_id)

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _read_jsonl(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)[:180] or "item"


def _slug(value: str) -> str:
    return _safe_name(value.replace("/", "_"))
