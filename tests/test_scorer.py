"""N-system scorer: v1 regression, five-system shape, and input validation.
Test numbers refer to temp/dev-tests-llmwarden-benchmarks-phase2-20260929.md in
the HAL repo.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 -- Test 23 runs this repo's own runners
import sys
from pathlib import Path
from typing import Any

import pytest

from benchmarks.results_doc import historical_section
from benchmarks.scorer import (
    DuplicateSystemError,
    ResultsMismatchError,
    load_systems,
    render_tables,
    render_threshold_sections,
)

REPO = Path(__file__).resolve().parent.parent
V1_PATH = REPO / "corpus" / "evasion_corpus_v1.jsonl"


def _case(i: int, label: str, source: str, technique: str) -> dict[str, Any]:
    return {
        "id": f"x-{i}",
        "text": f"t{i}",
        "label": label,
        "source": source,
        "technique": technique,
    }


CORPUS = [
    _case(1, "malicious", "prompt-firewall:tests/test_core.py", "leetspeak"),
    _case(2, "benign", "prompt-firewall:README.md", "leetspeak"),
    _case(3, "malicious", "garak:encoding/base64", "base64"),
    _case(
        4,
        "malicious",
        "external:Lakera/gandalf_ignore_instructions@" + "a" * 40,
        "direct_injection",
    ),
    _case(5, "benign", "external:leolee99/NotInject@" + "b" * 40, "benign_trigger_words"),
    _case(
        6,
        "malicious",
        "external:TrustAIRLab/in-the-wild-jailbreak-prompts@" + "c" * 40,
        "jailbreak_in_the_wild",
    ),
]


def _rows(blocked: dict[str, bool], default: dict[str, bool] | None) -> list[dict[str, Any]]:
    return [
        {
            "id": c["id"],
            "score": 0.5,
            "blocked_default": None if default is None else default[c["id"]],
            "blocked_strict": blocked[c["id"]],
            "blocked_balanced": blocked[c["id"]],
            "blocked_permissive": blocked[c["id"]],
        }
        for c in CORPUS
    ]


def _write(tmp_path: Path, name: str, rows: list[dict[str, Any]]) -> str:
    path = tmp_path / f"{name}.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(path)


ALL = {c["id"]: True for c in CORPUS}
NONE = {c["id"]: False for c in CORPUS}
ONLY_MALICIOUS = {c["id"]: c["label"] == "malicious" for c in CORPUS}


def _five(tmp_path: Path) -> list[tuple[str, str]]:
    return [
        ("LLMWarden", _write(tmp_path, "w", _rows(ONLY_MALICIOUS, default=ONLY_MALICIOUS))),
        ("raw PG2-22M", _write(tmp_path, "r", _rows(NONE, default=None))),
        # Blocks everything at LLMWarden's low thresholds, nothing at its own
        # 0.9: the two views must read different columns.
        ("LlamaFirewall", _write(tmp_path, "lf", _rows(ALL, default=NONE))),
        ("LLM Guard", _write(tmp_path, "lg", _rows(NONE, default=NONE))),
        ("raw DeBERTa", _write(tmp_path, "rd", _rows(ALL, default=None))),
    ]


# --- Test 24: five-system output shape -----------------------------------------


def test_24_five_systems_render_both_tables_with_an_external_row(tmp_path: Path) -> None:
    out = render_tables(CORPUS, load_systems(CORPUS, _five(tmp_path)))
    own, thresholds = out.split("## LLMWarden thresholds", 1)
    assert "## Own shipped defaults" in own
    header = next(line for line in own.splitlines() if line.startswith("| Technique"))
    # Raw models ship no decision threshold: absent from the own-default table.
    assert "raw PG2-22M" not in own and "raw DeBERTa" not in own
    assert header == (
        "| Technique | Source | n (mal/ben) | LLMWarden recall | LlamaFirewall recall "
        "| LLM Guard recall | LLMWarden FPR | LlamaFirewall FPR | LLM Guard FPR |"
    )
    for profile in ("strict", "balanced", "permissive"):
        assert f"## Profile: `{profile}`" in thresholds
    assert "raw PG2-22M recall" in thresholds and "raw DeBERTa FPR" in thresholds
    for section in (own, thresholds):
        assert any(line.startswith("| external | 2/1 |") for line in section.splitlines())
        assert "| direct_injection | external | 1/0 |" in section


def test_24_counts_and_rates_are_per_system(tmp_path: Path) -> None:
    out = render_tables(CORPUS, load_systems(CORPUS, _five(tmp_path)))
    own, thresholds = out.split("## LLMWarden thresholds", 1)
    balanced = thresholds.split("## Profile: `balanced`", 1)[1].split("## Profile:", 1)[0]
    # 4 malicious / 2 benign. Own defaults: LLMWarden catches every malicious
    # case and flags no benign one; LlamaFirewall and LLM Guard block nothing.
    # recall x3, then FPR x3 (LLMWarden, LlamaFirewall, LLM Guard).
    assert (
        "| **Overall** | **all** | **4/2** | **100%** | **0%** | **0%** | **0%** | **0%** | **0%** |"
        in own
    )
    # At balanced, LlamaFirewall and raw DeBERTa block everything. Order:
    # LLMWarden, raw PG2-22M, LlamaFirewall, LLM Guard, raw DeBERTa.
    assert (
        "| **Overall** | **all** | **4/2** | **100%** | **0%** | **100%** | **0%** | **100%** "
        "| **0%** | **0%** | **100%** | **0%** | **100%** |"
    ) in balanced


def test_24_source_rows_cover_every_bucket(tmp_path: Path) -> None:
    out = render_tables(CORPUS, load_systems(CORPUS, _five(tmp_path)))
    sources = {line.split(" | ")[0][2:] for line in out.splitlines() if line.startswith("| ")}
    assert {"LLMWarden (own tests/prose)", "garak-derived", "external"} <= sources


# --- Tests 25/26 and other invalid input ---------------------------------------


def test_25_missing_case_fails_loudly_naming_system_and_id(tmp_path: Path) -> None:
    rows = _rows(NONE, default=NONE)[:-1]
    with pytest.raises(ResultsMismatchError, match=r"LLM Guard.*x-6"):
        load_systems(CORPUS, [("LLM Guard", _write(tmp_path, "lg", rows))])


def test_25_extra_or_duplicate_case_ids_fail_loudly(tmp_path: Path) -> None:
    rows = _rows(NONE, default=NONE)
    extra = [*rows, {**rows[0], "id": "not-in-corpus"}]
    with pytest.raises(ResultsMismatchError, match="not-in-corpus"):
        load_systems(CORPUS, [("A", _write(tmp_path, "a", extra))])
    with pytest.raises(ResultsMismatchError, match="x-1"):
        load_systems(CORPUS, [("A", _write(tmp_path, "b", [*rows, rows[0]]))])


def test_26_duplicate_system_name_rejected_before_reading_any_file(tmp_path: Path) -> None:
    absent = str(tmp_path / "does-not-exist.jsonl")
    with pytest.raises(DuplicateSystemError, match="LLM Guard"):
        load_systems(CORPUS, [("LLM Guard", absent), ("LLM Guard", absent)])


def test_mixed_null_and_non_null_default_is_rejected(tmp_path: Path) -> None:
    # A system either ships a default for every case or for none: a partial
    # column would silently drop cases from the own-default table.
    rows = _rows(NONE, default=NONE)
    rows[2]["blocked_default"] = None
    with pytest.raises(ResultsMismatchError, match=r"A.*blocked_default"):
        load_systems(CORPUS, [("A", _write(tmp_path, "a", rows))])


def test_non_boolean_blocked_value_is_rejected(tmp_path: Path) -> None:
    rows = _rows(NONE, default=NONE)
    rows[0]["blocked_balanced"] = "false"  # truthy string would count as blocked
    with pytest.raises(ResultsMismatchError, match=r"x-1.*blocked_balanced"):
        load_systems(CORPUS, [("A", _write(tmp_path, "a", rows))])


def test_no_system_ships_a_default_omits_the_own_default_section(tmp_path: Path) -> None:
    systems = load_systems(CORPUS, [("raw", _write(tmp_path, "r", _rows(NONE, default=None)))])
    out = render_tables(CORPUS, systems)
    assert "## Own shipped defaults" not in out
    assert "## Profile: `balanced`" in out


# --- Test 23: two-system regression against the published v1 tables ------------


def _published_v1_tables() -> str:
    text = (REPO / "RESULTS.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    # The v3 tables come first; the published v1 tables sit in the frozen
    # historical section after the marker.
    text = historical_section(text)
    start = text.index("## Profile: `strict`")
    end = text.index("\n## Limitations")
    return text[start:end]


@pytest.mark.integration
def test_23_two_systems_reproduce_published_v1_tables(tmp_path: Path) -> None:
    pytest.importorskip("llmwarden", reason="Test 23 re-runs the v1 runners: needs llmwarden")
    pairs = []
    for name, module in (("raw-PG2", "run_raw_promptguard2"), ("wrapper", "run_wrapper")):
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell, this repo's own module
            [sys.executable, "-m", f"benchmarks.{module}", str(V1_PATH)],
            cwd=REPO,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=900,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr[-4000:]
        path = tmp_path / f"{module}.jsonl"
        path.write_text(proc.stdout, encoding="utf-8")
        pairs.append((name, str(path)))
    corpus = [json.loads(line) for line in V1_PATH.read_text(encoding="utf-8").splitlines()]
    rendered = render_threshold_sections(corpus, load_systems(corpus, pairs))
    assert rendered == _published_v1_tables()
