"""RESULTS.md assembly: system descriptions, computed disclosures, and the
frozen v1 historical section carried over byte-for-byte."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.results_doc import (
    HISTORICAL_MARKER,
    SYSTEM_DESCRIPTIONS,
    MissingHistoricalSectionError,
    UndocumentedSystemError,
    historical_section,
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
