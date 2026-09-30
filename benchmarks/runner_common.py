"""Shared plumbing for the per-system runners: corpus loading, score
validation, the LLMWarden-threshold columns and JSONL output.

Every runner emits one row per corpus case with the same six fields:
`id, score, blocked_default, blocked_strict, blocked_balanced,
blocked_permissive`. `blocked_default` is the system's own shipped decision
(`None` for raw models, which ship none); the other three apply LLMWarden's
profile thresholds, so detection ability is compared at one decision boundary
(spec, Phase 2 threshold policy).

Each runner's `score_cases()` takes an injected scorer and yields rows lazily,
so tests never load a model and a crash mid-run leaves earlier rows written.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any, TextIO

# Mirrors llmwarden.core._PROFILE_THRESHOLDS (module-private, not exported --
# hardcoded here rather than reached into); tests/test_runners.py's
# test_r1_profile_thresholds_mirror_llmwarden fails if they drift.
PROFILE_THRESHOLDS = {"strict": 0.1, "balanced": 0.25, "permissive": 0.7}

Case = dict[str, Any]
Row = dict[str, Any]


def load_cases(path: str) -> list[Case]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def checked_score(case_id: str, score: float) -> float:
    """NaN compares False against every threshold, so an unchecked NaN would
    read as "not blocked" and silently lower recall."""
    if isinstance(score, bool) or not (isinstance(score, float | int) and 0.0 <= score <= 1.0):
        raise ValueError(f"{case_id}: score {score!r} is not a probability in [0, 1]")
    return float(score)


def threshold_row(case_id: str, score: float, default_threshold: float | None) -> Row:
    """Row for a system whose decision is `score >= threshold` (LLMWarden,
    LlamaFirewall and the raw models all use `>=`)."""
    score = checked_score(case_id, score)
    return {
        "id": case_id,
        "score": score,
        "blocked_default": None if default_threshold is None else score >= default_threshold,
        **{f"blocked_{p}": score >= t for p, t in PROFILE_THRESHOLDS.items()},
    }


def refused_row(case_id: str, exc: BaseException, blocked_default: bool | None) -> Row:
    """A case the system refused to score (LLMWarden's InputTooLongError, whose
    message tells the caller to reject the input). Counted as blocked, decided
    2026-09-29, and flagged so RESULTS.md can disclose it."""
    return {
        "id": case_id,
        "score": None,
        "blocked_default": blocked_default,
        **{f"blocked_{p}": True for p in PROFILE_THRESHOLDS},
        "refused": type(exc).__name__,
    }


def score_raw_model_cases(
    cases: Iterable[Case],
    score: Callable[[str], float],
    refusal: type[Exception] | tuple[type[Exception], ...] = (),
) -> Iterator[Row]:
    for case in cases:
        try:
            value = score(case["text"])
        except refusal as exc:
            yield refused_row(case["id"], exc, blocked_default=None)
            continue
        yield threshold_row(case["id"], value, default_threshold=None)


def write_rows(rows: Iterable[Row], out: TextIO) -> None:
    for row in rows:
        json.dump(row, out, ensure_ascii=False)
        out.write("\n")
        out.flush()


def resolve_hf_home() -> Path:
    """Absolute HF_HOME, exported for the model libraries. LlamaFirewall sets
    an unexpanded "~/.cache/huggingface" when HF_HOME is unset, so it is always
    set explicitly before any model library is imported."""
    hf_home = Path(os.environ.get("HF_HOME") or Path.home() / ".cache" / "huggingface")
    hf_home = hf_home.expanduser().resolve()
    os.environ["HF_HOME"] = str(hf_home)
    return hf_home


def go_offline() -> None:
    """Scoring never touches the network: models are prepared beforehand with
    `--prepare`. Must run before huggingface_hub/transformers are imported,
    which read these at import time."""
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"


def cli(main: Callable[[str, TextIO], None], prepare: Callable[[], None] | None = None) -> None:
    """Parses argv and runs `main(corpus_path, out)`. Only result rows go to
    the real stdout (`out`); while `main` runs, `sys.stdout` points at stderr,
    so a model library's stray print can't corrupt the JSONL results."""
    sys.stdout.reconfigure(encoding="utf-8")  # pyright: ignore[reportAttributeAccessIssue]
    args = sys.argv[1:]
    if prepare is not None and args == ["--prepare"]:
        prepare()
        return
    if len(args) != 1 or args[0].startswith("--"):
        usage = "<corpus.jsonl>" + (" | --prepare" if prepare else "")
        module = f"benchmarks.{Path(sys.argv[0]).stem}"
        print(f"usage: python -m {module} {usage}", file=sys.stderr)
        raise SystemExit(2)
    results = sys.stdout
    sys.stdout = sys.stderr
    try:
        main(args[0], results)
    finally:
        sys.stdout = results
