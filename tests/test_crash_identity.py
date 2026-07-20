from __future__ import annotations

from agentic_fuzz_engine.crash_identity import (
    compute_crash_state,
    consolidate_signature_groups,
    crash_states_similar,
    extract_dedup_tokens,
    parse_crash_output,
    root_signature,
)
from agentic_fuzz_engine.dedupe import dedupe_findings, finding_signature

ASAN_WRITE = """\
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x400b12
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x4a12b3 in __interceptor_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63
    #1 0x51fa22 in CopyBlock /work/src/codec/block.cpp:88
    #2 0x51fb44 in DecodeExtent /work/src/codec/extent.cpp:141
    #3 0x520000 in ParseHeader /work/src/codec/header.cpp:52
    #4 0x521111 in LLVMFuzzerTestOneInput /work/fuzz/harness.cpp:20
"""

# Same root cause, but the sanitizer runtime contributed a different
# interceptor frame at the top — v1 signatures split on this, v2 must not.
ASAN_WRITE_VARIANT = ASAN_WRITE.replace(
    "__interceptor_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp",
    "__asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp",
)

ASAN_INLINE_FLAP = ASAN_WRITE.replace(
    "#1 0x51fa22 in CopyBlock /work/src/codec/block.cpp:88\n    ",
    "",
)

ASAN_UNRELATED = """\
==99==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000020 at pc 0x400c44
READ of size 4 at 0x603000000020 thread T0
    #0 0x600100 in TailerPeek /work/src/oplog/tailer.cpp:300
    #1 0x600200 in TailerLoop /work/src/oplog/tailer.cpp:410
    #2 0x600300 in RunService /work/src/oplog/service.cpp:77
"""


class TestParsing:
    def test_interceptor_frames_dropped_from_crash_state(self):
        signal = parse_crash_output(ASAN_WRITE)
        assert signal is not None
        assert signal.crash_type == "heap-buffer-overflow"
        assert signal.sanitizer_family == "address"
        assert signal.crash_state == ("CopyBlock", "DecodeExtent", "ParseHeader")
        assert signal.top_function == "CopyBlock"
        assert signal.access == "WRITE"
        assert signal.access_size == 8

    def test_all_blacklisted_falls_back_to_raw_frames(self):
        output = """\
==5==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x1 in __interceptor_strlen /src/llvm-project/compiler-rt/lib/asan/x.cpp:1
    #1 0x2 in __libc_start_main libc-start.c:308
"""
        signal = parse_crash_output(output)
        assert signal is not None
        assert signal.crash_state == ("__interceptor_strlen", "__libc_start_main")

    def test_ubsan_runtime_error_grammar(self):
        output = "src/codec/int.cpp:44:13: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'\n"
        signal = parse_crash_output(output)
        assert signal is not None
        assert signal.sanitizer_family == "ubsan"
        assert signal.crash_type.startswith("signed-integer-overflow")

    def test_libfuzzer_deadly_signal_grammar(self):
        output = """\
==12== ERROR: libFuzzer: deadly signal
    #0 0x1 in fuzzer::CrashCallback FuzzerLoop.cpp:1
    #1 0x2 in ParseChunk /work/src/parse.cpp:10
"""
        signal = parse_crash_output(output)
        assert signal is not None
        assert signal.crash_type == "deadly-signal"
        assert signal.sanitizer_family == "libfuzzer"
        assert signal.crash_state == ("ParseChunk",)

    def test_non_crash_output_returns_none(self):
        assert parse_crash_output("all tests passed\n") is None
        assert parse_crash_output("") is None


class TestDedupTokens:
    def test_tokens_sorted_and_unique(self):
        output = "DEDUP_TOKEN: beta\nDEDUP_TOKEN: alpha\nDEDUP_TOKEN: beta\n"
        assert extract_dedup_tokens(output) == ("alpha", "beta")

    def test_tokens_take_priority_in_root_signature(self):
        tokenized = ASAN_WRITE + "DEDUP_TOKEN: CopyBlock--DecodeExtent\n"
        with_tokens = parse_crash_output(tokenized)
        without_tokens = parse_crash_output(ASAN_WRITE)
        assert with_tokens is not None and without_tokens is not None
        assert with_tokens.dedup_tokens == ("CopyBlock--DecodeExtent",)
        assert root_signature(with_tokens) != root_signature(without_tokens)
        # Token identity is stable regardless of frame differences.
        variant = parse_crash_output(ASAN_UNRELATED + "DEDUP_TOKEN: CopyBlock--DecodeExtent\n")
        assert variant is not None
        assert root_signature(variant) == root_signature(with_tokens)


class TestRootSignature:
    def test_root_signature_is_cross_harness(self):
        first = parse_crash_output(ASAN_WRITE)
        second = parse_crash_output(ASAN_WRITE_VARIANT)
        assert first is not None and second is not None
        assert root_signature(first) == root_signature(second)
        assert len(root_signature(first)) == 24

    def test_distinct_root_causes_get_distinct_signatures(self):
        first = parse_crash_output(ASAN_WRITE)
        other = parse_crash_output(ASAN_UNRELATED)
        assert first is not None and other is not None
        assert root_signature(first) != root_signature(other)


class TestSimilarity:
    def test_equal_states_similar(self):
        assert crash_states_similar(("a", "b", "c"), ("a", "b", "c"))

    def test_lcs_two_shared_frames_similar(self):
        assert crash_states_similar(
            ("CopyBlock", "DecodeExtent", "ParseHeader"),
            ("DecodeExtent", "ParseHeader", "ReadFile"),
        )

    def test_disjoint_states_not_similar(self):
        assert not crash_states_similar(
            ("CopyBlock", "DecodeExtent", "ParseHeader"),
            ("TailerPeek", "TailerLoop", "RunService"),
        )

    def test_empty_state_never_similar(self):
        assert not crash_states_similar((), ("a",))

    def test_near_identical_names_similar_by_ratio(self):
        # Inlining suffix flap: same functions, cloned suffixes.
        assert crash_states_similar(
            ("DecodeExtent.part.0", "ParseHeaderImpl", "ReadAllData"),
            ("DecodeExtent.part.1", "ParseHeaderImpl", "ReadAllData2"),
        )


class TestFindingSignatureV2:
    BASE = dict(target="localfuzz/c/demo", harness="demo", sanitizer="address", error_token="heap-buffer-overflow")

    def test_interceptor_variant_shares_signature(self):
        first = finding_signature(crash_output=ASAN_WRITE, **self.BASE)
        second = finding_signature(crash_output=ASAN_WRITE_VARIANT, **self.BASE)
        assert first == second
        assert len(first) == 24

    def test_harness_still_scopes_per_finding_signature(self):
        first = finding_signature(crash_output=ASAN_WRITE, **self.BASE)
        other_harness = finding_signature(crash_output=ASAN_WRITE, **{**self.BASE, "harness": "demo2"})
        assert first != other_harness

    def test_unparseable_output_still_deterministic(self):
        first = finding_signature(crash_output="garbage", **self.BASE)
        second = finding_signature(crash_output="garbage", **self.BASE)
        assert first == second


def _finding(signature: str, crash_output: str, *, harness: str = "demo", poc: str | None = None) -> dict:
    return {
        "finding_id": f"finding-{signature}",
        "target": "localfuzz/c/demo",
        "harness": harness,
        "sanitizer": "address",
        "error_token": "heap-buffer-overflow",
        "crash_output": crash_output,
        "signature": signature,
        "poc_artifact": poc,
        "verified": True,
        "reproductions": 3,
    }


class TestDedupeFindings:
    def test_v1_rows_regroup_without_rewrite(self):
        # Two rows recorded under different (v1-era) signatures whose only
        # crash difference is the sanitizer interceptor frame.
        rows = [
            _finding("v1-aaa", ASAN_WRITE),
            _finding("v1-bbb", ASAN_WRITE_VARIANT),
        ]
        groups = dedupe_findings(rows, artifact_sizes={})
        assert len(groups) == 1
        group = groups[0]
        assert group["count"] == 2
        recorded = {group["representative"]["recorded_signature"]} | {
            item["recorded_signature"] for item in group["duplicates"]
        }
        assert recorded == {"v1-aaa", "v1-bbb"}

    def test_inline_flap_consolidates_fuzzily(self):
        rows = [
            _finding("sig-full", ASAN_WRITE),
            _finding("sig-flap", ASAN_INLINE_FLAP),
            _finding("sig-other", ASAN_UNRELATED),
        ]
        groups = dedupe_findings(rows, artifact_sizes={})
        consolidated = [g for g in groups if g.get("consolidated")]
        assert len(consolidated) == 1
        assert consolidated[0]["count"] == 2
        assert len(consolidated[0]["members"]) == 2
        assert consolidated[0]["root_signature"]
        # The unrelated UAF stays its own group.
        assert len(groups) == 2

    def test_consolidation_requires_same_crash_type(self):
        # Same frames, different crash type must not merge.
        uaf_same_frames = ASAN_WRITE.replace("heap-buffer-overflow", "heap-use-after-free")
        rows = [
            _finding("sig-hbo", ASAN_WRITE),
            _finding("sig-uaf", uaf_same_frames),
        ]
        groups = dedupe_findings(rows, artifact_sizes={})
        assert len(groups) == 2
        assert not any(g.get("consolidated") for g in groups)


class TestConsolidateGroups:
    def test_best_representative_wins(self):
        strong = _finding("s1", ASAN_WRITE, poc="povs/small")
        weak = _finding("s2", ASAN_INLINE_FLAP)
        groups = dedupe_findings([weak, strong], artifact_sizes={"povs/small": 8})
        assert len(groups) == 1
        assert groups[0]["representative"]["signature"] == finding_signature(
            target="localfuzz/c/demo",
            harness="demo",
            sanitizer="address",
            error_token="heap-buffer-overflow",
            crash_output=ASAN_WRITE,
        ) or groups[0]["consolidated"]
        # Whatever the merge order, the PoV-backed row is the representative.
        assert groups[0]["representative"]["poc_artifact"] == "povs/small"


class TestCrashStateDepth:
    def test_depth_capped_at_three(self):
        signal = parse_crash_output(ASAN_WRITE)
        assert signal is not None
        assert len(signal.crash_state) == 3
        assert len(compute_crash_state(signal.frames)) == 3


CXX_PARAM_OUTPUT = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
WRITE of size 1048592 at 0x1 thread T0
    #0 0xdead in __asan_memcpy (/ws/bin/inflate_demo/fuzzer+0x12d387) (BuildId: d9f43b)
    #1 0xbeef in codec::InflateBlock(codec::CompType::type, char const*, int, char*, int*) /src/lib/codec/inflate.cpp:325:9
    #2 0xf00d in LLVMFuzzerTestOneInput /ws/targets/c/x/main.cpp:35:3
"""


def test_cxx_parameter_list_frame_keeps_file_and_clean_function():
    """C++ symbols carry parameter lists with spaces; the parser must still
    recover the file:line tail and a clean function name (the old
    single-token regex truncated at the first comma and dropped the file,
    hiding project frames from grading and corrupting crash_state)."""
    from agentic_fuzz_engine.asan import iter_asan_frames

    frames = iter_asan_frames(CXX_PARAM_OUTPUT)
    assert frames[1].function == "codec::InflateBlock"
    assert frames[1].file == "/src/lib/codec/inflate.cpp"
    assert frames[1].line == 325
    # module-offset frame keeps its bare name, no file
    assert frames[0].function == "__asan_memcpy"
    assert frames[0].file is None


def test_cxx_parameter_list_crash_state_uses_project_function():
    signal = parse_crash_output(CXX_PARAM_OUTPUT)
    assert signal is not None
    assert signal.top_function == "codec::InflateBlock"
    assert signal.crash_state[0] == "codec::InflateBlock"
