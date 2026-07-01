from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from .engine import AgenticFuzzEngine


MCP_PROTOCOL_VERSION = "2025-06-18"


class AgenticFuzzMcpServer:
    def __init__(
        self,
        *,
        data_root: str | Path,
        reference_root: str | Path | None = None,
        audit_roots: tuple[str | Path, ...] = (),
    ) -> None:
        self.engine = AgenticFuzzEngine(data_root=data_root, reference_root=reference_root, audit_roots=audit_roots)

    def serve(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
        for line in stdin:
            if not line.strip():
                continue
            response = self.handle(json.loads(line))
            if response is not None:
                stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                stdout.flush()

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        msg_id = message.get("id")
        if isinstance(method, str) and method.startswith("notifications/"):
            return None
        try:
            result = self._dispatch(str(method), message.get("params") if isinstance(message.get("params"), dict) else {})
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32000, "message": str(exc)},
            }

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "agentic-fuzz-engine", "version": "0.1.0"},
            }
        if method == "tools/list":
            return {"tools": self.engine.tool_specs()}
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if not isinstance(name, str) or not name:
                raise ValueError("tools/call requires params.name")
            payload = self.engine.call_tool(name, arguments)
            return {
                "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
                "isError": False,
            }
        if method == "resources/list":
            return {
                "resources": [
                    {
                        "uri": "agentic-fuzz://fidelity/fixtures",
                        "name": "C/C++ fidelity fixtures",
                        "mimeType": "application/json",
                    }
                ]
            }
        if method == "resources/read":
            uri = params.get("uri")
            if uri != "agentic-fuzz://fidelity/fixtures":
                raise ValueError(f"unknown resource: {uri}")
            payload = self.engine.call_tool("fidelity_list_fixtures", {"include_disabled": True})
            return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(payload, sort_keys=True)}]}
        raise ValueError(f"unsupported MCP method: {method}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agentic Fuzz Engine MCP stdio server")
    parser.add_argument("--data-root", default=os.environ.get("CLAUDE_PLUGIN_DATA", "runs/agentic-fuzz-engine"))
    parser.add_argument(
        "--reference-root",
        default=os.environ.get("AGENTIC_FUZZ_REFERENCE_ROOT"),
    )
    parser.add_argument("--audit-root", action="append", default=[])
    args = parser.parse_args(argv)
    server = AgenticFuzzMcpServer(
        data_root=args.data_root,
        reference_root=args.reference_root,
        audit_roots=tuple(args.audit_root),
    )
    server.serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
