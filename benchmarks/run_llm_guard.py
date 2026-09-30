"""Scores every corpus entry with LLM Guard 0.3.16's `PromptInjection` input
scanner at its defaults (`MatchType.FULL`: the whole prompt as one input,
truncated at 512 tokens) over `protectai/deberta-v3-base-prompt-injection-v2`.

Decisions come only from the public `scan() -> (sanitized, is_valid,
risk_score)` API, one scanner instance per threshold: the shipped default
0.92 plus LLMWarden's 0.1/0.25/0.7. `risk_score` is never used: it is
rescaled against the threshold and rounded to 1 decimal, so it can't be read
back as a probability. LLM Guard also rounds each injection score to 2
decimals and blocks on strict `>`, which is why its columns are its own
verdicts rather than `score >= threshold`.

`score` is the unrounded max injection probability from the scanner's own
pipeline and chunking (`_pipeline`/`_match_type`, private but frozen: 0.3.16
is archived). It is for reporting only; no decision is derived from it.

Prepare the model once with `python -m benchmarks.run_raw_deberta --prepare`.
Run (offline):
    python -m benchmarks.run_llm_guard corpus/evasion_corpus_v3.jsonl > results/llm_guard.jsonl
Needs .venv-llmguard (requirements-llmguard.lock.txt).
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any, Protocol, TextIO

from benchmarks import run_raw_deberta
from benchmarks.runner_common import (
    PROFILE_THRESHOLDS,
    Case,
    Row,
    checked_score,
    cli,
    go_offline,
    load_cases,
    resolve_hf_home,
    write_rows,
)

# Shipped default verified from the 0.3.16 source: `threshold: float = 0.92`
# (its docstring's "0.9" is wrong).
THRESHOLDS = {"default": 0.92, **PROFILE_THRESHOLDS}


class ScannerLike(Protocol):
    def scan(self, prompt: str) -> tuple[str, bool, float]: ...


def score_cases(
    cases: Iterable[Case], scanners: Mapping[str, ScannerLike], probe: Callable[[str], float]
) -> Iterator[Row]:
    if set(scanners) != set(THRESHOLDS):
        mismatch = sorted(set(THRESHOLDS) ^ set(scanners))
        raise ValueError(
            f"need one scanner per threshold {sorted(THRESHOLDS)}; mismatch: {mismatch}"
        )
    for case in cases:
        text = case["text"]
        row: Row = {"id": case["id"], "score": checked_score(case["id"], probe(text))}
        for name, scanner in scanners.items():
            _, is_valid, _risk_score = scanner.scan(text)
            row[f"blocked_{name}"] = not is_valid
        yield row


def _injection_probability(scanner: Any) -> Callable[[str], float]:
    """Max injection probability over the scanner's own inputs, computed the
    way `PromptInjection.scan()` does but without its 2-decimal rounding."""

    def probe(text: str) -> float:
        results = scanner._pipeline(scanner._match_type.get_inputs(text))
        return max(
            r["score"] if r["label"] == run_raw_deberta.INJECTION_LABEL else 1 - r["score"]
            for r in results
        )

    return probe


def main(corpus_path: str, out: TextIO) -> None:
    resolve_hf_home()
    go_offline()
    # llm_guard is installed only in .venv-llmguard (isolated deps).
    from llm_guard.input_scanners import PromptInjection  # pyright: ignore[reportMissingImports]
    from llm_guard.input_scanners.prompt_injection import (  # pyright: ignore[reportMissingImports]
        V2_MODEL,
        MatchType,
    )
    from llm_guard.util import configure_logger  # pyright: ignore[reportMissingImports]

    # structlog binds the original stdout at import; send its logs to stderr.
    configure_logger(log_level="INFO", stream=sys.stderr)

    if (V2_MODEL.path, V2_MODEL.revision) != (run_raw_deberta.REPO_ID, run_raw_deberta.REVISION):
        raise RuntimeError(
            f"llm-guard's model {V2_MODEL.path}@{V2_MODEL.revision} differs from the raw-DeBERTa "
            f"pin {run_raw_deberta.REPO_ID}@{run_raw_deberta.REVISION}; the pair must match"
        )
    scanners = {
        name: PromptInjection(threshold=t, match_type=MatchType.FULL)
        for name, t in THRESHOLDS.items()
    }
    probe = _injection_probability(scanners["default"])
    write_rows(score_cases(load_cases(corpus_path), scanners, probe), out)


if __name__ == "__main__":
    cli(main)
