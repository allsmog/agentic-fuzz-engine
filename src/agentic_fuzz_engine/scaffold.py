"""Generate target scaffolding inside the workspace from a sink inventory.

``target-select`` ranks sink-inventory vectors (JSONL rows tagged per vector)
against the targets that already exist in the workspace, so campaign effort
goes to unharnessed attack surface first.

``target-scaffold`` generates the per-target skeleton the rest of the engine
already understands: ``benchmark/projects/<name>/project.yaml`` +
``targets/c/<name>/.localfuzz/config.yaml`` (both parsed by :mod:`fidelity` /
:mod:`discovery`), a harness source skeleton, a seeds dir, a dictionary stub,
and a ``.localfuzz/build.json`` command list for ``target-build``.

The harness body is intentionally left to a human: the skeleton compiles but
drives nothing until the ``TODO(human)`` block is filled in.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .workspace import resolve_workspace_root

MAX_SINK_ROWS = 200_000
MAX_SINK_REFS = 50
TARGETS_RELATIVE = Path("targets/c")
PROJECTS_RELATIVE = Path("benchmark/projects")


def select_targets(
    *,
    sinks_jsonl: str | Path,
    workspace_root: str | Path | None = None,
    top: int = 25,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    sinks_path = Path(sinks_jsonl).expanduser().resolve()
    if not sinks_path.is_file():
        raise FileNotFoundError(f"sinks_jsonl is not a file: {sinks_jsonl}")
    rows = _load_sink_rows(sinks_path)
    existing = _existing_targets(root)

    from .boundaries import classify_path, load_boundaries
    from .sink_scan import PRIMITIVE_WEIGHT

    boundaries = load_boundaries(root)

    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        tag = str(row.get("tag") or "untagged")
        group = groups.setdefault(
            tag,
            {"tag": tag, "sink_count": 0, "files": set(), "sample": None,
             "boundary_weight": 0, "entry_classes": {}},
        )
        group["sink_count"] += 1
        entry_class = row.get("entry_class")
        if not isinstance(entry_class, str) or not entry_class:
            entry_class, class_weight = classify_path(str(row.get("file") or ""), boundaries)
        else:
            _, class_weight = classify_path(str(row.get("file") or ""), boundaries)
        group["entry_classes"][entry_class] = group["entry_classes"].get(entry_class, 0) + 1
        group["boundary_weight"] += PRIMITIVE_WEIGHT.get(str(row.get("primitive") or ""), 1) * class_weight
        if row.get("file"):
            group["files"].add(str(row["file"]))
        if group["sample"] is None:
            group["sample"] = {key: row.get(key) for key in ("file", "line", "method", "callee")}

    vectors = []
    for group in groups.values():
        slug = _slugify(group["tag"])
        vectors.append(
            {
                "tag": group["tag"],
                "suggested_name": slug,
                "sink_count": group["sink_count"],
                "file_count": len(group["files"]),
                "harnessed": slug in existing,
                "sample_sink": group["sample"],
                "boundary_weight": group["boundary_weight"],
                "entry_classes": group["entry_classes"],
            }
        )
    # boundary_weight degenerates to a sink-count-proportional score when no
    # boundaries map exists, so pre-boundary workspaces rank as before.
    vectors.sort(key=lambda item: (item["harnessed"], -item["boundary_weight"], -item["sink_count"]))
    return {
        "ok": True,
        "sinks_jsonl": str(sinks_path),
        "rows_scanned": len(rows),
        "existing_targets": sorted(existing),
        "vectors": vectors[: max(1, top)],
        "unharnessed": [item["suggested_name"] for item in vectors if not item["harnessed"]][: max(1, top)],
    }


def scaffold_target(
    *,
    name: str,
    workspace_root: str | Path | None = None,
    sinks_jsonl: str | Path | None = None,
    sink_tag: str | None = None,
    max_sink_refs: int = 20,
    force: bool = False,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
        raise ValueError("name must be a lowercase slug ([a-z0-9][a-z0-9_-]*)")
    root = resolve_workspace_root(workspace_root, env=env)
    target_dir = root / TARGETS_RELATIVE / name
    project_dir = root / PROJECTS_RELATIVE / name
    if target_dir.exists() and not force:
        raise FileExistsError(f"target already scaffolded (use force to overwrite skeleton files): {target_dir}")

    sink_refs: list[dict[str, Any]] = []
    if sinks_jsonl is not None:
        rows = _load_sink_rows(Path(sinks_jsonl).expanduser().resolve())
        wanted = sink_tag or name
        sink_refs = [
            {key: row.get(key) for key in ("file", "line", "method", "callee", "code")}
            for row in rows
            if _slugify(str(row.get("tag") or "")) == _slugify(wanted) or str(row.get("tag") or "") == wanted
        ][: max(1, min(max_sink_refs, MAX_SINK_REFS))]

    (target_dir / ".localfuzz").mkdir(parents=True, exist_ok=True)
    (target_dir / "seeds").mkdir(parents=True, exist_ok=True)
    project_dir.mkdir(parents=True, exist_ok=True)

    written = []
    written.append(_write(project_dir / "project.yaml", _render_project_yaml(name)))
    written.append(_write(target_dir / ".localfuzz" / "config.yaml", _render_localfuzz_config(name)))
    written.append(_write(target_dir / ".localfuzz" / "build.json", _render_build_json(name)))
    written.append(_write(target_dir / "harness.cpp", _render_harness(name, sink_refs)))
    from .flag_profiles import PRELUDE_NAME, render_flag_prelude

    prelude_path = target_dir / PRELUDE_NAME
    if not prelude_path.exists():
        written.append(_write(prelude_path, render_flag_prelude(None)))
    dict_path = target_dir / f"{name}.dict"
    if not dict_path.exists():
        written.append(_write(dict_path, "# tokens for {name}: one quoted token per line\n".format(name=name)))

    return {
        "ok": True,
        "name": name,
        "target": f"localfuzz/c/{name}",
        "target_dir": str(target_dir),
        "project_dir": str(project_dir),
        "sink_refs": len(sink_refs),
        "written": written,
        "next_steps": [
            f"fill in the TODO(human) block in {target_dir / 'harness.cpp'}",
            f"adjust build commands in {target_dir / '.localfuzz' / 'build.json'}",
            f"add seeds under {target_dir / 'seeds'}",
            f"run: target-build localfuzz/c/{name}",
        ],
    }


def _load_sink_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= MAX_SINK_ROWS:
                break
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def _existing_targets(root: Path) -> set[str]:
    targets_dir = root / TARGETS_RELATIVE
    if not targets_dir.is_dir():
        return set()
    return {
        entry.name
        for entry in targets_dir.iterdir()
        if entry.is_dir() and not entry.name.startswith((".", "_"))
    }


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "untagged"


def _write(path: Path, content: str) -> str:
    path.write_text(content, encoding="utf-8")
    return str(path)


def _render_project_yaml(name: str) -> str:
    return (
        f"# Generated by target-scaffold for {name}.\n"
        "language: c++\n"
        "sanitizers:\n"
        "  - address\n"
        "  - undefined\n"
        "fuzzing_engines:\n"
        "  - libfuzzer\n"
        "  - symcc\n"
        "  - klee\n"
    )


def _render_localfuzz_config(name: str) -> str:
    return (
        "harness_files:\n"
        f"  - name: {name}\n"
        "    path: harness.cpp\n"
    )


def _render_build_json(name: str) -> str:
    payload = {
        "notes": [
            "Ordered bounded build steps run by target-build.",
            "Placeholders: {target_dir} {bin_dir} {workspace_root} {source_dir}.",
            "Adjust includes/libs per target; these defaults mirror the known-good local harness builds.",
        ],
        "steps": [
            {
                "name": "libfuzzer",
                "argv": [
                    "clang++",
                    "-std=c++17", "-g", "-O1",
                    "-fsanitize=fuzzer,address,undefined",
                    "-fno-sanitize-recover=undefined",
                    "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
                    "-I{source_dir}",
                    "{target_dir}/harness.cpp",
                    "-o", "{bin_dir}/fuzzer",
                ],
                "env": {},
            },
            {
                "name": "symcc",
                "argv": [
                    "sym++",
                    "-std=c++17", "-g", "-O1",
                    "-DFUZZ_MAIN",
                    "-I{source_dir}",
                    "{target_dir}/harness.cpp",
                    "-o", "{bin_dir}/symcc_bin",
                ],
                "env": {"SYMCC_REGULAR_LIBCXX": "1"},
            },
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _render_harness(name: str, sink_refs: list[dict[str, Any]]) -> str:
    lines = [
        f"// Harness skeleton for target '{name}' (generated by target-scaffold).",
        "//",
        "// Build modes:",
        "//   libFuzzer: clang++ -fsanitize=fuzzer,address ... harness.cpp",
        "//   file-mode (SymCC/KLEE): sym++ -DFUZZ_MAIN ... harness.cpp",
    ]
    if sink_refs:
        lines.append("//")
        lines.append("// Sink sites this harness should reach:")
        for ref in sink_refs:
            location = f"{ref.get('file')}:{ref.get('line')}"
            lines.append(f"//   {location}  {ref.get('method')} -> {ref.get('callee')}")
    lines += [
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "// TODO(human): include the target headers needed to reach the sinks above.",
        "// Then include the generated flag prelude AFTER them (it assigns FLAGS_*):",
        "// #include \"flag_profile.inc\"",
        "// extern \"C\" int LLVMFuzzerInitialize(int *, char ***) { apply_flag_profile(); return 0; }",
        "",
        "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
        "  if (size == 0) {",
        "    return 0;",
        "  }",
        "  // TODO(human): decode `data` and drive the target sink(s).",
        "  return 0;",
        "}",
        "",
        "#ifdef FUZZ_MAIN",
        "#include <cstdio>",
        "#include <cstdlib>",
        "#include <vector>",
        "",
        "int main(int argc, char **argv) {",
        "  if (argc < 2) {",
        "    std::fprintf(stderr, \"usage: %s <input-file>\\n\", argv[0]);",
        "    return 1;",
        "  }",
        "  std::FILE *file = std::fopen(argv[1], \"rb\");",
        "  if (file == nullptr) {",
        "    return 1;",
        "  }",
        "  std::vector<uint8_t> data;",
        "  uint8_t chunk[4096];",
        "  size_t got = 0;",
        "  while ((got = std::fread(chunk, 1, sizeof(chunk), file)) > 0) {",
        "    data.insert(data.end(), chunk, chunk + got);",
        "  }",
        "  std::fclose(file);",
        "  return LLVMFuzzerTestOneInput(data.data(), data.size());",
        "}",
        "#endif  // FUZZ_MAIN",
        "",
    ]
    return "\n".join(lines)
