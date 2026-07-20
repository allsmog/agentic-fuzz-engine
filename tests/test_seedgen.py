import json
from pathlib import Path

from agentic_fuzz_engine.seedgen import run_seedgen


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_seedgen_writes_deduped_blobs_with_provenance(tmp_path):
    script = _write(
        tmp_path / "gen.py",
        "def generate(rnd):\n"
        "    return b'HDR' + bytes([rnd.randrange(4)])\n",
    )
    result = run_seedgen(
        target="localfuzz/c/demo",
        script_path=str(script),
        count=64,
        max_seconds=30,
        workspace_root=str(tmp_path / "ws"),
        env={},
    )
    assert result["ok"], result
    seeds = list(Path(result["seeds_dir"]).iterdir())
    assert 1 <= len(seeds) <= 4  # only 4 distinct blobs possible
    assert all(entry.name.startswith("seedgen-") for entry in seeds)
    provenance_path = tmp_path / "ws" / "work" / "demo" / "seedgen.jsonl"
    record = json.loads(provenance_path.read_text().splitlines()[-1])
    assert record["merged_new"] == len(seeds)
    assert record["script_sha256"]
    # second run merges nothing new
    again = run_seedgen(
        target="localfuzz/c/demo",
        script_path=str(script),
        count=64,
        max_seconds=30,
        workspace_root=str(tmp_path / "ws"),
        env={},
    )
    assert again["provenance"]["merged_new"] == 0


def test_seedgen_counts_errors_and_truncates_oversize(tmp_path):
    script = _write(
        tmp_path / "gen.py",
        "def generate(rnd):\n"
        "    n = rnd.randrange(3)\n"
        "    if n == 0:\n"
        "        raise ValueError('boom')\n"
        "    if n == 1:\n"
        "        return b'A' * 4096\n"
        "    return b'B' * 8\n",
    )
    result = run_seedgen(
        target="demo2",
        script_path=str(script),
        count=32,
        max_seconds=30,
        max_blob_bytes=1024,
        workspace_root=str(tmp_path / "ws"),
        env={},
    )
    assert result["ok"], result
    assert result["provenance"]["errors"] > 0
    assert result["provenance"]["oversize_truncated"] > 0
    sizes = {entry.stat().st_size for entry in Path(result["seeds_dir"]).iterdir()}
    assert sizes <= {8, 1024}


def test_seedgen_missing_generate_is_blocker(tmp_path):
    script = _write(tmp_path / "gen.py", "VALUE = 1\n")
    result = run_seedgen(
        target="demo3",
        script_path=str(script),
        count=8,
        workspace_root=str(tmp_path / "ws"),
        env={},
    )
    assert not result["ok"]
    assert any("generate" in blocker for blocker in result["blockers"])


def test_seedgen_timeout_keeps_partial_blobs(tmp_path):
    script = _write(
        tmp_path / "gen.py",
        "import time\n"
        "CALLS = {'n': 0}\n"
        "def generate(rnd):\n"
        "    CALLS['n'] += 1\n"
        "    if CALLS['n'] > 2:\n"
        "        time.sleep(60)\n"
        "    return bytes([CALLS['n']]) * 4\n",
    )
    result = run_seedgen(
        target="demo4",
        script_path=str(script),
        count=100,
        max_seconds=2,
        workspace_root=str(tmp_path / "ws"),
        env={},
    )
    assert not result["ok"]
    assert any("wall clock" in blocker for blocker in result["blockers"])


def test_seedgen_missing_script_is_blocker(tmp_path):
    result = run_seedgen(
        target="demo5",
        script_path=str(tmp_path / "nope.py"),
        workspace_root=str(tmp_path / "ws"),
        env={},
    )
    assert not result["ok"]
    assert any("not found" in blocker for blocker in result["blockers"])


def test_seedgen_mutate_mode_riffs_on_corpus(tmp_path):
    ws = tmp_path / "ws"
    seeds_dir = ws / "work" / "demo" / "seeds"
    seeds_dir.mkdir(parents=True)
    (seeds_dir / "corpus-a").write_bytes(b"HDR-AAAA")
    (seeds_dir / "corpus-b").write_bytes(b"HDR-BBBB")
    script = _write(
        tmp_path / "mut.py",
        "def mutate(rnd, seed):\n"
        "    body = bytearray(seed)\n"
        "    body[rnd.randrange(len(body))] ^= 0xFF\n"
        "    return bytes(body)\n",
    )
    result = run_seedgen(
        target="demo",
        script_path=str(script),
        count=16,
        max_seconds=30,
        mode="mutate",
        sample_max=8,
        workspace_root=str(ws),
        env={},
    )
    assert result["ok"], result
    assert result["provenance"]["mode"] == "mutate"
    assert result["provenance"]["samples_used"] == 2
    merged = [e for e in seeds_dir.iterdir() if e.name.startswith("seedgen-")]
    assert merged, "mutated blobs should merge into the corpus"
    # every mutated blob is one byte-flip away from a corpus parent
    for entry in merged:
        blob = entry.read_bytes()
        assert len(blob) == 8 and blob != b"HDR-AAAA" and blob != b"HDR-BBBB"
    # the staging samples dir is cleaned up
    assert not (ws / "work" / "demo" / "seedgen-samples").exists()


def test_seedgen_mutate_requires_mutate_function(tmp_path):
    ws = tmp_path / "ws"
    seeds_dir = ws / "work" / "demo" / "seeds"
    seeds_dir.mkdir(parents=True)
    (seeds_dir / "corpus-a").write_bytes(b"X")
    script = _write(tmp_path / "gen.py", "def generate(rnd):\n    return b'A'\n")
    result = run_seedgen(
        target="demo", script_path=str(script), mode="mutate",
        workspace_root=str(ws), env={},
    )
    assert not result["ok"]
    assert any("mutate(rnd, seed)" in blocker for blocker in result["blockers"])


def test_seedgen_mutate_requires_corpus(tmp_path):
    ws = tmp_path / "ws"
    script = _write(tmp_path / "mut.py", "def mutate(rnd, seed):\n    return seed\n")
    result = run_seedgen(
        target="demo", script_path=str(script), mode="mutate",
        workspace_root=str(ws), env={},
    )
    assert not result["ok"]
    assert any("non-empty corpus" in blocker for blocker in result["blockers"])


def test_seedgen_provenance_records_blob_names(tmp_path):
    script = _write(tmp_path / "gen.py", "def generate(rnd):\n    return bytes([rnd.randrange(8)])\n")
    result = run_seedgen(
        target="demo", script_path=str(script), count=32,
        workspace_root=str(tmp_path / "ws"), env={},
    )
    assert result["ok"], result
    blobs = result["provenance"]["blobs"]
    assert blobs and all(name.startswith("seedgen-") for name in blobs)
    assert result["provenance"]["blobs_truncated"] is False
