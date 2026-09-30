"""RESULTS.md assembly: system descriptions, computed disclosures, and the
frozen v1 historical section carried over byte-for-byte."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.results_doc import (
    HISTORICAL_MARKER,
    SYSTEM_DESCRIPTIONS,
    V3_CORPUS_SHA256,
    MissingHistoricalSectionError,
    UndocumentedSystemError,
    UnexpectedCorpusError,
    historical_section,
    main,
    render_document,
    update_results_file,
)
from benchmarks.scorer import System

CORPUS = [
    {"id": "a", "text": "x", "label": "malicious", "source": "garak:enc/b64", "technique": "b64"},
    {
        "id": "b",
        "text": "y",
        "label": "benign",
        "source": "prompt-firewall:README.md",
        "technique": "t",
    },
]


def _row(i: str, blocked: bool, default: bool | None, **extra: Any) -> dict[str, Any]:
    return {
        "id": i,
        "score": None if extra else 0.5,
        "blocked_default": default,
        "blocked_strict": blocked,
        "blocked_balanced": blocked,
        "blocked_permissive": blocked,
        **extra,
    }


def _system(name: str, default: bool | None, refused: bool = False) -> System:
    extra = {"refused": "InputTooLongError"} if refused else {}
    rows = {"a": _row("a", True, default, **extra), "b": _row("b", False, default and False)}
    return System(name, rows, has_default=default is not None)


def test_every_scored_system_is_described() -> None:
    doc = render_document(
        "corpus/v.jsonl", CORPUS, [_system("LLMWarden", True), _system("raw DeBERTa", None)]
    )
    for name in ("LLMWarden", "raw DeBERTa"):
        assert f"| {name} |" in doc
    assert "LlamaFirewall" not in doc.split("## Methodology")[0]  # only systems actually scored


def test_undocumented_system_name_is_refused() -> None:
    with pytest.raises(UndocumentedSystemError, match="Mystery"):
        render_document("c.jsonl", CORPUS, [_system("Mystery", None)])


def test_descriptions_follow_the_spec_wording() -> None:
    # spec, Phase 2: LlamaFirewall is not "raw PG2-86M"; both it and LLM Guard
    # truncate at 512 tokens; LLM Guard blocks on a rounded score with strict >.
    lf = " ".join(SYSTEM_DESCRIPTIONS["LlamaFirewall"])
    assert "whitespace-aware preprocessing" in lf and "512-token truncation" in lf
    lg = " ".join(SYSTEM_DESCRIPTIONS["LLM Guard"])
    assert "512 tokens" in lg and "> 0.92" in lg and "rounded" in lg


def test_refusals_are_disclosed_from_the_data() -> None:
    doc = render_document("c.jsonl", CORPUS, [_system("LLMWarden", True, refused=True)])
    assert "1 case (`a`) refused by LLMWarden" in doc
    none_refused = render_document("c.jsonl", CORPUS, [_system("LLMWarden", True)])
    assert "refused by" not in none_refused


def test_identical_refusals_across_systems_are_one_bullet() -> None:
    # A1: LLMWarden and raw PG2-22M refuse the same case; one bullet names both.
    systems = [_system("LLMWarden", True, refused=True), _system("raw PG2-22M", None, refused=True)]
    doc = render_document("c.jsonl", CORPUS, systems)
    assert doc.count("**Refusals count as blocked.**") == 1
    assert "1 case (`a`) refused by LLMWarden and raw PG2-22M" in doc


def test_refusal_reason_comes_from_the_data() -> None:
    # The exception name is read from row["refused"], not assumed; the
    # "too long" explanation only accompanies InputTooLongError.
    system = _system("LLMWarden", True)
    system.results["a"]["refused"] = "SomeOtherError"
    system.results["a"]["score"] = None
    doc = render_document("c.jsonl", CORPUS, [system])
    assert "(`SomeOtherError`)" in doc
    assert "too long" not in doc and "InputTooLongError" not in doc


def _llm_guard(score_a: float) -> System:
    system = _system("LLM Guard", True)
    system.results["a"]["score"] = score_a
    return system


def test_boundary_bullet_is_computed_from_llm_guard_scores() -> None:
    # R2: the old static sentence claimed no score of ANY system was near a
    # threshold, which was false for LLMWarden/raw PG2 (0.2469, 0.2511).
    # Bullets are wrapped at 80 columns; compare with line breaks collapsed.
    near = " ".join(render_document("c.jsonl", CORPUS, [_llm_guard(0.2469)]).split())
    assert "1 LLM Guard score falls within 0.005 of a threshold (`a`)" in near
    clear = " ".join(render_document("c.jsonl", CORPUS, [_llm_guard(0.5)]).split())
    assert "No LLM Guard score falls within 0.005" in clear
    for doc in (near, clear):
        assert "On this corpus no score falls" not in doc


def test_boundary_bullet_absent_without_llm_guard() -> None:
    doc = render_document("c.jsonl", CORPUS, [_system("LLMWarden", True)])
    assert "Threshold semantics" not in doc


def test_unscored_llamafirewall_is_marked_not_yet_scored() -> None:
    # A2: Limitations must not describe LlamaFirewall's behaviour as if it had
    # been measured when it has not been scored.
    doc = render_document("c.jsonl", CORPUS, [_system("LLMWarden", True)])
    limitations = doc.split("## Limitations", 1)[1]
    assert "**LlamaFirewall is not yet scored.**" in limitations
    assert "LlamaFirewall, LLM Guard" not in limitations  # truncation list: scored only
    scored = render_document("c.jsonl", CORPUS, [_system("LlamaFirewall", False)])
    assert "**LlamaFirewall's preprocessing fails open.**" in scored
    assert "not yet scored" not in scored


def test_llmwarden_time_bound_is_disclosed_only_when_scored() -> None:
    # R3: scan()'s decoded-candidate path is wall-clock bounded.
    with_lw = render_document("c.jsonl", CORPUS, [_system("LLMWarden", True)])
    assert "180 ms" in with_lw.split("## Limitations", 1)[1]
    without = render_document("c.jsonl", CORPUS, [_system("raw DeBERTa", None)])
    assert "180 ms" not in without


def test_committed_v3_corpus_matches_the_pinned_hash() -> None:
    v3 = Path(__file__).resolve().parent.parent / "corpus" / "evasion_corpus_v3.jsonl"
    assert hashlib.sha256(v3.read_bytes()).hexdigest() == V3_CORPUS_SHA256


def test_update_refuses_a_corpus_other_than_frozen_v3(tmp_path: Path) -> None:
    # R2: the prose hardcodes v3 counts (277 cases, 23 over 512 tokens, ...),
    # so rendering it over any other corpus would publish wrong numbers.
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text("".join(json.dumps(c) + "\n" for c in CORPUS), encoding="utf-8")
    results = tmp_path / "RESULTS.md"
    original = f"old\n\n{HISTORICAL_MARKER}\n# v1\n".encode()
    results.write_bytes(original)
    with pytest.raises(UnexpectedCorpusError, match="sha256"):
        main(["--update", str(results), str(corpus), "LLMWarden=unused.jsonl"])
    assert results.read_bytes() == original


def test_historical_section_is_everything_from_the_marker() -> None:
    text = f"generated v3\n\n{HISTORICAL_MARKER}\n# v1\n| t |\r\nverbatim  \n"
    assert historical_section(text) == f"{HISTORICAL_MARKER}\n# v1\n| t |\r\nverbatim  \n"


def test_missing_marker_is_refused() -> None:
    with pytest.raises(MissingHistoricalSectionError):
        historical_section("# no marker here\n")


def test_update_preserves_historical_bytes_and_replaces_the_rest(tmp_path: Path) -> None:
    frozen = f"{HISTORICAL_MARKER}\n# v1 results\n\n- hand-written noteé\n"
    results = tmp_path / "RESULTS.md"
    results.write_bytes(f"old generated part\n\n{frozen}".encode())
    update_results_file(results, "new generated part\n")
    out = results.read_bytes().decode()
    assert out == f"new generated part\n\n{frozen}"
    assert "old generated" not in out


def test_update_leaves_file_untouched_when_marker_missing(tmp_path: Path) -> None:
    results = tmp_path / "RESULTS.md"
    results.write_bytes(b"no marker\n")
    with pytest.raises(MissingHistoricalSectionError):
        update_results_file(results, "new\n")
    assert results.read_bytes() == b"no marker\n"


def test_committed_results_md_has_the_historical_marker() -> None:
    text = (Path(__file__).resolve().parent.parent / "RESULTS.md").read_text(encoding="utf-8")
    assert text.count(HISTORICAL_MARKER) == 1


def test_document_is_valid_utf8_markdown_ending_in_one_newline() -> None:
    doc = render_document("c.jsonl", CORPUS, [_system("LLMWarden", True)])
    assert doc.endswith("\n") and not doc.endswith("\n\n")
    json.dumps(doc)  # plain str, no stray bytes
