"""Bounded inventory of vendor-patched binary packages.

This scanner reports *candidates*: a package marker, build target, and
first-party consumer are evidence worth investigating, not proof that a
particular input reaches the packaged code.
"""
from __future__ import annotations

import ast
import heapq
import io
import json
import os
import re
import secrets
import stat
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .workspace import load_policy, load_workspace, resolve_workspace_root

MAX_MANIFEST_FILES = 400
MAX_MANIFEST_GLOBS = 24
MAX_MANIFEST_BYTES = 1_000_000
MAX_BAZEL_FILES = 400
MAX_BAZEL_BYTES = 1_000_000
MAX_CONSUMER_BUILD_FILES = 8_000
MAX_ROWS_TOTAL = 2_000
MAX_INSTALLED_LIST_FILES = 8
MAX_INSTALLED_LIBS = 16
MAX_MARKERS = 32
MAX_TREE_ENTRIES = 100_000
MAX_TREE_DIRECTORIES = 20_000
DEFAULT_DPKG_INFO_DIR = "/var/lib/dpkg/info"
DEFAULT_MANIFEST_GLOBS = (
    "deployment/**/*.yml",
    "deployment/**/*.yaml",
    "deployment/**/*.sh",
    "**/packages*.txt",
)

_APT_PIN_RE = re.compile(r"^\s*-?\s*([A-Za-z0-9][\w.+-]*)=(\S+?)\s*$")
_DEB_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][\w.+-]*)_(\S+?)_[\w]+\.deb\s*$")
_BAZEL_NAME_RE = re.compile(r"\bname\s*=\s*[\"']([\w.-]+)[\"']")
_CC_IMPORT_RE = re.compile(r"\bcc_import\s*\((.*?)\)", re.DOTALL)
_VERSION_RE = re.compile(r"^\d[\w.:~%+-]*$")
_MARKER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_LABEL_RE = re.compile(r"[\"']((?:@[A-Za-z0-9_.-]+)?//[A-Za-z0-9_./-]*(?::[A-Za-z0-9_.-]+)?|:[A-Za-z0-9_.-]+)[\"']")
_REPOSITORY_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")


@dataclass(frozen=True)
class _AnchoredSource:
    path: Path
    relative: Path
    expected: os.stat_result


class _BoundedTree:
    """Deterministic, bounded traversal anchored to one no-follow root fd."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root_fd = -1
        self.root_info: os.stat_result | None = None

    def __enter__(self) -> "_BoundedTree":
        try:
            expected = self.root.lstat()
        except OSError as exc:
            raise ValueError(f"unable to inspect scan root: {self.root}") from exc
        if not stat.S_ISDIR(expected.st_mode) or stat.S_ISLNK(expected.st_mode):
            raise ValueError(f"scan root must be a regular directory: {self.root}")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.root, flags)
        except OSError as exc:
            raise ValueError(f"unable to open scan root safely: {self.root}") from exc
        actual = os.fstat(descriptor)
        if not _same_identity(expected, actual):
            os.close(descriptor)
            raise ValueError(f"scan root changed while opening: {self.root}")
        self.root_fd = descriptor
        self.root_info = actual
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        identity_error: ValueError | None = None
        try:
            if self.root_fd >= 0 and self.root_info is not None:
                _verify_directory_path(self.root, self.root_fd, self.root_info)
        except ValueError as caught:
            identity_error = caught
        finally:
            if self.root_fd >= 0:
                os.close(self.root_fd)
                self.root_fd = -1
        if exc_type is None and identity_error is not None:
            raise identity_error

    def regular_files(
        self, *, max_entries: int = MAX_TREE_ENTRIES,
        max_directories: int = MAX_TREE_DIRECTORIES,
    ) -> Iterator[_AnchoredSource]:
        if self.root_fd < 0:
            raise RuntimeError("bounded tree is not open")
        if max_entries < 1 or max_directories < 1:
            raise ValueError("tree traversal caps must be positive")
        pending: list[tuple[str, Path]] = [("", Path())]
        entries_seen = 0
        directories_seen = 0
        while pending:
            _key, relative_dir = heapq.heappop(pending)
            directories_seen += 1
            if directories_seen > max_directories:
                raise ValueError(f"source tree exceeds {max_directories} directories")
            directory_fd = _open_relative_directory(self.root_fd, relative_dir)
            try:
                children: list[tuple[str, bool, os.stat_result]] = []
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        entries_seen += 1
                        if entries_seen > max_entries:
                            raise ValueError(f"source tree exceeds {max_entries} entries")
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise ValueError(f"source entry changed during traversal: {entry.name}") from exc
                        if stat.S_ISLNK(info.st_mode):
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            children.append((entry.name, True, info))
                        elif stat.S_ISREG(info.st_mode):
                            children.append((entry.name, False, info))
                for name, is_directory, info in sorted(children, key=lambda item: item[0]):
                    relative = relative_dir / name
                    if is_directory:
                        heapq.heappush(pending, (relative.as_posix(), relative))
                    else:
                        yield _AnchoredSource(self.root / relative, relative, info)
            finally:
                os.close(directory_fd)

    def read_text(self, source: _AnchoredSource, *, max_bytes: int) -> str:
        if self.root_fd < 0:
            raise RuntimeError("bounded tree is not open")
        return _read_regular_text_at(self.root_fd, source, max_bytes=max_bytes)


def _same_identity(expected: os.stat_result, actual: os.stat_result) -> bool:
    return (
        expected.st_dev == actual.st_dev
        and expected.st_ino == actual.st_ino
        and stat.S_IFMT(expected.st_mode) == stat.S_IFMT(actual.st_mode)
    )


def _same_snapshot(expected: os.stat_result, actual: os.stat_result) -> bool:
    return (
        _same_identity(expected, actual)
        and expected.st_size == actual.st_size
        and expected.st_mtime_ns == actual.st_mtime_ns
        and expected.st_ctime_ns == actual.st_ctime_ns
    )


def _open_relative_directory(root_fd: int, relative: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.dup(root_fd)
    try:
        for part in relative.parts:
            if part in {"", "."}:
                continue
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise ValueError(f"source directory changed during traversal: {relative}") from exc


def _read_regular_text_at(root_fd: int, source: _AnchoredSource, *, max_bytes: int) -> str:
    if source.expected.st_size > max_bytes:
        raise ValueError(f"source file exceeds {max_bytes} bytes: {source.path}")
    parent_fd = _open_relative_directory(root_fd, source.relative.parent)
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        try:
            descriptor = os.open(source.relative.name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError(f"source file changed before opening: {source.path}") from exc
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_snapshot(source.expected, opened):
            raise ValueError(f"source file changed before opening: {source.path}")
        remaining = opened.st_size
        payload = bytearray()
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise ValueError(f"source file shrank while reading: {source.path}")
            payload.extend(chunk)
            remaining -= len(chunk)
        finished = os.fstat(descriptor)
        if len(payload) != opened.st_size or not _same_snapshot(opened, finished):
            raise ValueError(f"source file changed while reading: {source.path}")
        return payload.decode("utf-8", errors="replace")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _verify_directory_path(path: Path, descriptor: int, expected: os.stat_result) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    check = -1
    try:
        check = os.open(path, flags)
        if not _same_identity(expected, os.fstat(check)) or not _same_identity(expected, os.fstat(descriptor)):
            raise ValueError(f"directory identity changed during operation: {path}")
    except OSError as exc:
        raise ValueError(f"directory identity changed during operation: {path}") from exc
    finally:
        if check >= 0:
            os.close(check)


def _read_named_regular_text(path: Path, *, anchor: Path, max_bytes: int) -> str | None:
    try:
        expected = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"unable to inspect source file: {path}") from exc
    if not stat.S_ISREG(expected.st_mode):
        return None
    relative = path.relative_to(anchor)
    with _BoundedTree(anchor) as tree:
        return tree.read_text(_AnchoredSource(path, relative, expected), max_bytes=max_bytes)


def run_fork_scan(
    *,
    source_root: str | Path | None = None,
    out_path: str | Path | None = None,
    workspace_root: str | Path | None = None,
    vendor_markers: Sequence[str] | None = None,
    manifest_globs: Sequence[str] | None = None,
    consumer_root: str | Path | None = None,
    dpkg_info_dir: str | Path | None = None,
    repository_alias: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    root: Path | None = None
    workspace: dict[str, Any] = {}
    try:
        root = resolve_workspace_root(workspace_root, env=environment)
        workspace = load_workspace(root, env=environment)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        root = None

    policy: Mapping[str, Any] = {}
    if root is not None:
        candidate = load_policy(root, env=environment).get("fork_scan") or {}
        if isinstance(candidate, Mapping):
            policy = candidate
    try:
        markers = _validate_markers(vendor_markers if vendor_markers is not None else policy.get("vendor_markers", []))
        globs = _validate_globs(manifest_globs if manifest_globs is not None else policy.get("manifest_globs", DEFAULT_MANIFEST_GLOBS))
        alias = _validate_repository_alias(
            repository_alias if repository_alias is not None else policy.get("repository_alias")
        )
    except ValueError as exc:
        return _blocked(str(exc))
    if not markers:
        return _blocked("vendor_markers required (flag or policy fork_scan.vendor_markers)")

    source_root = source_root or policy.get("repo_root") or _repo_root_of(workspace.get("source_dir"))
    if not source_root:
        return _blocked("source_root required (repository holding package manifests)")
    repo = Path(source_root).expanduser().resolve()
    if not repo.is_dir():
        return _blocked(f"source_root is not a directory: {repo}")
    consumer_value = consumer_root or policy.get("consumer_root") or workspace.get("source_dir") or repo
    consumers_dir = Path(str(consumer_value)).expanduser().resolve()

    if out_path is None:
        if root is None:
            return _blocked("out_path required when no initialized workspace is available")
        out = root / "data" / "fork-inventory.jsonl"
    else:
        out = Path(out_path).expanduser()
    try:
        out = _validate_output(out, root)
    except ValueError as exc:
        return _blocked(str(exc))

    info_value = dpkg_info_dir or policy.get("dpkg_info_dir") or DEFAULT_DPKG_INFO_DIR
    info_dir = Path(str(info_value)).expanduser().resolve()
    try:
        packages = _scan_manifests(repo, globs, markers)
        bazel_rules = _scan_bazel_external_libs(repo, repository_alias=alias)
        consumers = _scan_consumers(consumers_dir, bazel_rules, repo_root=repo)
    except ValueError as exc:
        return _blocked(f"unable to scan source trees safely: {exc}")

    from .boundaries import classify_path, load_boundaries

    boundaries = load_boundaries(root)
    rows: list[dict[str, Any]] = []
    for package in packages.values():
        if len(rows) >= MAX_ROWS_TOTAL:
            break
        matches, match_kind = _match_bazel_rules(package["package"], bazel_rules)
        selected = matches[0] if len(matches) == 1 else None
        consumer_files = sorted(consumers.get(selected["identity"], [])) if selected else []
        entry_class, class_weight = _best_consumer_class(consumer_files, boundaries, classify_path)
        installed = _installed_libs(package["package"], info_dir)
        revision = re.search(re.escape(package["marker"]) + r"[._-]?(\d+)", package["version"].lower())
        rows.append({
            "tag": f"fork_{_slug(selected['name'] if selected else package['package'])}",
            "file": package["file"], "line": package["line"],
            "method": package["package"], "callee": "fork-package",
            "code": package["code"][:200], "kind": "fork", "primitive": None,
            "via": "fork-inventory", "candidate_evidence": "version-marker",
            "package": package["package"], "version": package["version"],
            "vendor_marker": package["marker"],
            "fork_rev": int(revision.group(1)) if revision else None,
            "bazel_lib": selected["name"] if selected else None,
            "bazel_label": selected["label"] if selected else None,
            "bazel_repository": selected["repository"] if selected else None,
            "bazel_package": selected["package"] if selected else None,
            "bazel_build_file": selected["file"] if selected else None,
            "bazel_label_confidence": selected["identity_confidence"] if selected else None,
            "bazel_lib_candidates": [rule.get("label") or rule["identity"] for rule in matches],
            "bazel_match": match_kind,
            "consumer_files": consumer_files,
            "consumer_modules": sorted({path.split("/")[0] for path in consumer_files}),
            "consumer_match_confidence": "exact-canonical-bazel-label" if consumer_files else None,
            "installed_libs": installed,
            "has_static": any(path.endswith(".a") for path in installed),
            "entry_class": entry_class, "boundary_weight": class_weight,
        })
    rows.sort(key=lambda row: (-int(row["boundary_weight"] or 0), -int(row["fork_rev"] or 0), row["tag"], row["package"]))
    try:
        _atomic_jsonl(out, rows)
    except (OSError, ValueError) as exc:
        return _blocked(f"unable to write inventory: {exc}")
    return {
        "ok": True, "mode": "fork-scan", "source_root": str(repo),
        "consumer_root": str(consumers_dir), "out": str(out),
        "vendor_markers": markers, "packages_found": len(packages),
        "bazel_libs_found": len(bazel_rules), "rows_written": len(rows),
        "installed_packages": sum(bool(row["installed_libs"]) for row in rows),
        "static_lib_packages": sum(bool(row["has_static"]) for row in rows),
        "ambiguous_mappings": sum(len(row["bazel_lib_candidates"]) > 1 for row in rows),
        "blockers": [],
    }


def _blocked(message: str) -> dict[str, Any]:
    return {"ok": False, "mode": "fork-scan", "rows_written": 0, "blockers": [message]}


def _validate_markers(values: Any) -> list[str]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError("vendor_markers must be a list of marker strings")
    if len(values) > MAX_MARKERS:
        raise ValueError(f"vendor_markers exceeds {MAX_MARKERS} entries")
    markers: set[str] = set()
    for value in values:
        marker = str(value).lower().strip()
        if not _MARKER_RE.fullmatch(marker):
            raise ValueError(f"invalid vendor marker: {value!r}")
        markers.add(marker)
    return sorted(markers)


def _validate_globs(values: Any) -> list[str]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError("manifest_globs must be a list")
    if len(values) > MAX_MANIFEST_GLOBS:
        raise ValueError(f"manifest_globs exceeds {MAX_MANIFEST_GLOBS} entries")
    result = []
    for value in values:
        pattern = str(value)
        if not pattern or len(pattern) > 256 or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ValueError(f"unsafe manifest glob: {pattern!r}")
        result.append(pattern)
    return result


def _validate_repository_alias(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _REPOSITORY_NAME_RE.fullmatch(value):
        raise ValueError(f"invalid Bazel repository alias: {value!r}")
    return value


def _repo_root_of(source_dir: Any) -> str | None:
    if not source_dir:
        return None
    current = Path(str(source_dir)).expanduser().resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists() or (candidate / "WORKSPACE").is_file() or (candidate / "WORKSPACE.bazel").is_file():
            return str(candidate)
    return None


def _scan_manifests(repo: Path, globs: Sequence[str], markers: Sequence[str]) -> dict[str, dict[str, Any]]:
    packages: dict[str, dict[str, Any]] = {}
    matched = 0
    with _BoundedTree(repo) as tree:
        for source in tree.regular_files(
            max_entries=MAX_TREE_ENTRIES, max_directories=MAX_TREE_DIRECTORIES
        ):
            if not any(_manifest_glob_matches(source.relative, pattern) for pattern in globs):
                continue
            matched += 1
            if matched > MAX_MANIFEST_FILES:
                raise ValueError(f"manifest file count exceeds {MAX_MANIFEST_FILES}")
            if source.expected.st_size > MAX_MANIFEST_BYTES:
                continue
            text = tree.read_text(source, max_bytes=MAX_MANIFEST_BYTES)
            for line_number, line in enumerate(text.splitlines(), 1):
                stripped = line.split("#", 1)[0]
                match = _APT_PIN_RE.match(stripped) or _DEB_NAME_RE.match(stripped)
                if not match or not _VERSION_RE.fullmatch(match.group(2)):
                    continue
                package, version = match.group(1), match.group(2)
                lowered_version = version.lower()
                # A marker in the package name alone is not evidence of a patched version.
                marker = next((item for item in markers if item in lowered_version), None)
                if marker:
                    packages.setdefault(package, {"package": package, "version": version, "marker": marker,
                        "file": source.relative.as_posix(), "line": line_number, "code": stripped.strip()})
    return packages


def _manifest_glob_matches(relative: Path, pattern: str) -> bool:
    variants = {pattern}
    reduced = pattern
    while "/**/" in reduced:
        reduced = reduced.replace("/**/", "/")
        variants.add(reduced)
    if reduced.startswith("**/"):
        variants.add(reduced[3:])
    return any(relative.match(item) for item in variants)


def _is_bazel_build(path: Path) -> bool:
    return path.name in {"BUILD", "BUILD.bazel"} or (path.name.startswith("BUILD.") and path.name.endswith(".bazel"))


def _scan_bazel_external_libs(
    repo: Path, *, repository_alias: str | None = None
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    repository_name = _declared_repository_name(repo, explicit_alias=repository_alias)
    scanned = 0
    with _BoundedTree(repo) as tree:
        for source in tree.regular_files(
            max_entries=MAX_TREE_ENTRIES, max_directories=MAX_TREE_DIRECTORIES
        ):
            path = source.path
            if not _is_bazel_build(path):
                continue
            scanned += 1
            if scanned > MAX_BAZEL_FILES:
                raise ValueError(f"Bazel rule file count exceeds {MAX_BAZEL_FILES}")
            if source.expected.st_size > MAX_BAZEL_BYTES:
                continue
            text = tree.read_text(source, max_bytes=MAX_BAZEL_BYTES)
            relative = source.relative
            rel = relative.as_posix()
            active_build = path.name in {"BUILD", "BUILD.bazel"}
            package = relative.parent.as_posix() if relative.parent != Path(".") else ""
            for rule in _CC_IMPORT_RE.finditer(text):
                name = _BAZEL_NAME_RE.search(rule.group(1))
                if name:
                    target = name.group(1)
                    local_label = f"//{package}:{target}" if package else f"//:{target}"
                    identity = local_label if active_build else f"unbound:{rel}#{target}"
                    labels = [local_label] if active_build else []
                    if active_build and repository_name:
                        labels.append(f"@{repository_name}{local_label}")
                    rules.append({
                        "file": rel, "repository": repository_name if active_build else None,
                        "package": package, "name": target,
                        "label": local_label if active_build else None,
                        "identity": identity,
                        "labels": labels,
                        "identity_confidence": (
                            "active-build-local-label" if active_build else "alternate-build-file-unbound"
                        ),
                    })
    return rules


def _scan_consumers(
    root: Path, rules: Sequence[Mapping[str, Any]], *, repo_root: Path | None = None
) -> dict[str, list[str]]:
    label_identities: dict[str, set[str]] = {}
    for rule in rules:
        for label in rule.get("labels", []) or []:
            label_identities.setdefault(str(label), set()).add(str(rule["identity"]))
    if not root.is_dir() or not label_identities:
        return {}
    result: dict[str, set[str]] = {}
    scanned = 0
    with _BoundedTree(root) as tree:
        for source in tree.regular_files(
            max_entries=MAX_TREE_ENTRIES, max_directories=MAX_TREE_DIRECTORIES
        ):
            path = source.path
            if not _is_bazel_build(path):
                continue
            scanned += 1
            if scanned > MAX_CONSUMER_BUILD_FILES:
                raise ValueError(f"consumer BUILD file count exceeds {MAX_CONSUMER_BUILD_FILES}")
            if source.expected.st_size > MAX_BAZEL_BYTES:
                continue
            text = tree.read_text(source, max_bytes=MAX_BAZEL_BYTES)
            rel = source.relative.as_posix()
            relative = source.relative
            try:
                label_relative = path.relative_to(repo_root) if repo_root is not None else relative
            except ValueError:
                label_relative = relative
            package = label_relative.parent.as_posix() if label_relative.parent != Path(".") else ""
            for match in _LABEL_RE.finditer(text):
                canonical = _canonical_consumer_label(match.group(1), package=package)
                identities = label_identities.get(canonical, set())
                if len(identities) == 1:
                    result.setdefault(next(iter(identities)), set()).add(rel)
    return {identity: sorted(paths) for identity, paths in result.items()}


def _normalize_pkg(name: str) -> str:
    value = re.sub(r"^lib", "", name.lower())
    value = re.sub(r"(t64|-dev|-static|-tools|-utils)$", "", value)
    value = re.sub(r"[\d.]+$", "", value)
    return re.sub(r"[^a-z0-9]+", "", value)


def _match_bazel_rules(
    package: str, bazel_rules: Sequence[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], str]:
    normalized = _normalize_pkg(package)
    candidates = sorted((dict(rule) for rule in bazel_rules), key=lambda rule: str(rule["identity"]))
    exact = [rule for rule in candidates if _normalize_pkg(str(rule["name"])) == normalized]
    if exact:
        return exact, "normalized-exact" if len(exact) == 1 else "ambiguous-exact"
    partial = [rule for rule in candidates if len(_normalize_pkg(str(rule["name"]))) >= 3 and len(normalized) >= 3
               and (_normalize_pkg(str(rule["name"])) in normalized or normalized in _normalize_pkg(str(rule["name"])))]
    return partial, "normalized-partial" if len(partial) == 1 else ("ambiguous-partial" if partial else "unmatched")


def _match_bazel_lib(package: str, bazel_libs: Sequence[Any]) -> str | None:
    """Compatibility helper: return a mapping only when it is unambiguous."""
    rules = [
        dict(item) if isinstance(item, Mapping) else
        {"file": str(item[0]), "repository": None, "package": "", "name": str(item[1]),
         "label": f"//:{item[1]}", "identity": f"//:{item[1]}", "labels": [f"//:{item[1]}"],
         "identity_confidence": "compatibility-local-label"}
        for item in bazel_libs
    ]
    matches, _ = _match_bazel_rules(package, rules)
    return str(matches[0]["name"]) if len(matches) == 1 else None


def _declared_repository_name(repo: Path, *, explicit_alias: str | None = None) -> str | None:
    """Return one evidenced self-repository alias, or reject conflicting evidence."""
    declarations: dict[str, set[str]] = {}
    for filename, call_name in (
        ("MODULE.bazel", "module"),
        ("WORKSPACE.bazel", "workspace"),
        ("WORKSPACE", "workspace"),
    ):
        path = repo / filename
        try:
            text = _read_named_regular_text(path, anchor=repo, max_bytes=MAX_BAZEL_BYTES)
            if text is None:
                continue
        except ValueError as exc:
            raise ValueError(f"unable to read Bazel repository declaration in {filename}: {exc}") from exc
        try:
            calls = _top_level_call_keywords(text, call_name)
        except (IndentationError, tokenize.TokenError) as exc:
            raise ValueError(f"unable to lex Bazel repository declaration in {filename}: {exc}") from exc
        for keywords in calls:
            if call_name == "module":
                candidate = keywords.get("repo_name") or keywords.get("name")
            else:
                candidate = keywords.get("name")
            if candidate is None:
                continue
            alias = _validate_repository_alias(candidate)
            assert alias is not None
            declarations.setdefault(alias, set()).add(filename)

    if explicit_alias is not None:
        return explicit_alias
    if len(declarations) > 1:
        evidence = ", ".join(
            f"{alias} ({'/'.join(sorted(files))})"
            for alias, files in sorted(declarations.items())
        )
        raise ValueError(
            "conflicting Bazel self-repository aliases: "
            f"{evidence}; configure fork_scan.repository_alias explicitly"
        )
    return next(iter(declarations), None)


def _top_level_call_keywords(text: str, call_name: str) -> list[dict[str, str]]:
    """Lex keyword string arguments from real, unindented top-level calls."""
    tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    calls: list[dict[str, str]] = []
    statement_start = True
    indent = 0
    index = 0
    while index < len(tokens):
        item = tokens[index]
        if item.type == tokenize.INDENT:
            indent += 1
            index += 1
            continue
        if item.type == tokenize.DEDENT:
            indent = max(0, indent - 1)
            index += 1
            continue
        if item.type == tokenize.NEWLINE:
            statement_start = True
            index += 1
            continue
        if item.type in {tokenize.COMMENT, tokenize.NL, tokenize.ENCODING}:
            index += 1
            continue
        if item.type == tokenize.OP and item.string == ";":
            statement_start = True
            index += 1
            continue
        if (
            statement_start
            and indent == 0
            and item.type == tokenize.NAME
            and item.string == call_name
        ):
            opening = _next_significant_token(tokens, index + 1)
            if opening is not None and tokens[opening].type == tokenize.OP and tokens[opening].string == "(":
                arguments, closing = _parenthesized_tokens(tokens, opening)
                calls.append(_keyword_string_arguments(arguments))
                index = closing + 1
                statement_start = False
                continue
        if item.type != tokenize.ENDMARKER:
            statement_start = False
        index += 1
    return calls


def _next_significant_token(tokens: Sequence[tokenize.TokenInfo], start: int) -> int | None:
    ignored = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}
    for index in range(start, len(tokens)):
        if tokens[index].type not in ignored:
            return index
    return None


def _parenthesized_tokens(
    tokens: Sequence[tokenize.TokenInfo], opening: int
) -> tuple[list[tokenize.TokenInfo], int]:
    depth = 0
    arguments: list[tokenize.TokenInfo] = []
    for index in range(opening, len(tokens)):
        item = tokens[index]
        if item.type == tokenize.OP and item.string in "([{":
            depth += 1
        elif item.type == tokenize.OP and item.string in ")]}":
            depth -= 1
            if depth == 0:
                return arguments, index
        if index > opening:
            arguments.append(item)
    raise tokenize.TokenError("unterminated top-level call", tokens[opening].start)


def _keyword_string_arguments(tokens: Sequence[tokenize.TokenInfo]) -> dict[str, str]:
    ignored = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}
    significant = [item for item in tokens if item.type not in ignored]
    segments: list[list[tokenize.TokenInfo]] = [[]]
    depth = 0
    for item in significant:
        if item.type == tokenize.OP and item.string in "([{":
            depth += 1
        elif item.type == tokenize.OP and item.string in ")]}":
            depth -= 1
        if item.type == tokenize.OP and item.string == "," and depth == 0:
            segments.append([])
        else:
            segments[-1].append(item)

    result: dict[str, str] = {}
    for segment in segments:
        if not (
            len(segment) == 3
            and segment[0].type == tokenize.NAME
            and segment[1].type == tokenize.OP
            and segment[1].string == "="
            and segment[2].type == tokenize.STRING
        ):
            continue
        try:
            value = ast.literal_eval(segment[2].string)
        except (SyntaxError, ValueError):
            continue
        if isinstance(value, str):
            result[segment[0].string] = value
    return result


def _canonical_consumer_label(label: str, *, package: str) -> str:
    if label.startswith(":"):
        return f"//{package}{label}" if package else f"//{label}"
    label_body = label.split("//", 1)[1] if "//" in label else label
    if "//" in label and ":" not in label_body:
        target = label_body.rsplit("/", 1)[-1]
        return f"{label}:{target}"
    return label


def _installed_libs(package: str, info_dir: Path) -> list[str]:
    if not info_dir.is_dir() or info_dir.is_symlink():
        return []
    libs: set[str] = set()
    try:
        with _BoundedTree(info_dir) as tree:
            matched = 0
            for source in tree.regular_files(
                max_entries=MAX_TREE_ENTRIES, max_directories=MAX_TREE_DIRECTORIES
            ):
                if source.relative.parent != Path(".") or not (
                    source.relative.name == f"{package}.list"
                    or (source.relative.name.startswith(f"{package}:") and source.relative.name.endswith(".list"))
                ):
                    continue
                matched += 1
                if matched > MAX_INSTALLED_LIST_FILES:
                    break
                if source.expected.st_size > MAX_MANIFEST_BYTES:
                    continue
                text = tree.read_text(source, max_bytes=MAX_MANIFEST_BYTES)
                for line in text.splitlines():
                    item = line.strip()
                    if not (item.endswith(".a") or ".so" in Path(item).name):
                        continue
                    path = Path(item)
                    try:
                        mode = path.lstat().st_mode
                    except OSError:
                        continue
                    if stat.S_ISREG(mode):
                        libs.add(item)
    except ValueError:
        return []
    return sorted(libs)[:MAX_INSTALLED_LIBS]


def _best_consumer_class(files: Sequence[str], boundaries: dict[str, Any] | None, classify: Any) -> tuple[str, int]:
    best: tuple[str, int] = ("internal", 1)
    for rel in files:
        candidate = classify(rel, boundaries)
        if candidate[1] > best[1]:
            best = candidate
    return best


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "unknown"


def _validate_output(path: Path, root: Path | None) -> Path:
    expanded = path.expanduser()
    if ".." in expanded.parts:
        raise ValueError(f"output path may not contain parent traversal: {path}")
    path = expanded.absolute()
    canonical_parent = path.parent.resolve(strict=False)
    canonical = canonical_parent / path.name
    if root is not None:
        try:
            canonical.relative_to(root.resolve())
        except ValueError as exc:
            raise ValueError(f"output must remain inside workspace: {canonical}") from exc
    parent = path.parent
    existing = parent
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    if existing.is_symlink():
        raise ValueError(f"refusing symlinked output parent: {existing}")
    current = existing
    for part in parent.relative_to(existing).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"refusing symlinked output parent: {current}")
    if path.is_symlink():
        raise ValueError(f"refusing symlinked output: {path}")
    return canonical


def _atomic_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path = _validate_output(path, None)
    ancestor, ancestor_expected, missing_parts = _snapshot_output_parent(path.parent)
    if missing_parts:
        raise ValueError(f"output parent must already exist: {path.parent}")
    parent_fd, parent_info = _open_output_parent(
        path.parent,
        ancestor=ancestor,
        ancestor_expected=ancestor_expected,
        missing_parts=missing_parts,
    )
    temporary = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(12)}"
    descriptor = -1
    try:
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValueError(f"refusing non-regular output: {path}")
        _verify_directory_path(path.parent, parent_fd, parent_info)
        os.replace(
            temporary,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary = ""
        os.fsync(parent_fd)
        _verify_directory_path(path.parent, parent_fd, parent_info)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _snapshot_output_parent(
    parent: Path,
) -> tuple[Path, os.stat_result, tuple[str, ...]]:
    """Remember the deepest existing parent and every absent suffix component."""
    if not parent.is_absolute():
        raise ValueError(f"output parent must be absolute: {parent}")
    current = Path(parent.anchor or "/")
    try:
        expected = current.lstat()
    except OSError as exc:
        raise ValueError(f"unable to inspect output parent anchor: {current}") from exc
    relative_parts = parent.parts[1:]
    for index, part in enumerate(relative_parts):
        candidate = current / part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            return current, expected, tuple(relative_parts[index:])
        except OSError as exc:
            raise ValueError(f"unable to inspect output parent: {candidate}") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError(f"refusing non-directory output parent: {candidate}")
        current = candidate
        expected = info
    return current, expected, ()


def _open_output_parent(
    parent: Path,
    *,
    ancestor: Path,
    ancestor_expected: os.stat_result,
    missing_parts: tuple[str, ...],
) -> tuple[int, os.stat_result]:
    """Open/create an absolute output parent without following any symlink."""
    if not parent.is_absolute():
        raise ValueError(f"output parent must be absolute: {parent}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if ancestor.joinpath(*missing_parts) != parent:
        raise ValueError("output parent snapshot does not match requested path")
    descriptor = os.open(parent.anchor or "/", flags)
    try:
        for part in ancestor.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if not _same_identity(ancestor_expected, os.fstat(descriptor)):
            raise ValueError(f"output parent ancestor changed before opening: {ancestor}")
        if missing_parts:
            raise ValueError(f"output parent must already exist: {parent}")
        info = os.fstat(descriptor)
        _verify_directory_path(parent, descriptor, info)
        return descriptor, info
    except BaseException:
        os.close(descriptor)
        raise
