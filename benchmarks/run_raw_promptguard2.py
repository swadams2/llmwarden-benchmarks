"""Scores every corpus entry with the bundled Llama Prompt Guard 2 classifier
completely standalone -- no fast-path scanner, no Unicode normalization, no
leetspeak/base64 handling. This is deliberately the library's own public
`PromptGuard2Classifier` class used directly (not a reimplementation): see
context/projects/llmwarden-benchmarks/llmwarden-benchmarks-spec.md
for why this is a fair, minimal "raw model" baseline.

The same profile thresholds LLMWarden itself uses (strict=0.1,
balanced=0.25, permissive=0.4) are applied to the raw score, so results
isolate exactly the effect of LLMWarden's preprocessing rather than
conflating it with a different decision boundary. A raw model ships no
decision threshold, so `blocked_default` is null.

Run: python -m benchmarks.run_raw_promptguard2 corpus/evasion_corpus_v3.jsonl > results/raw_promptguard2.jsonl
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from typing import TextIO

from benchmarks.runner_common import (
    Case,
    Row,
    cli,
    load_cases,
    score_raw_model_cases,
    write_rows,
)


def score_cases(cases: Iterable[Case], score: Callable[[str], float]) -> Iterator[Row]:
    return score_raw_model_cases(cases, score)


def main(corpus_path: str, out: TextIO) -> None:
    from llmwarden.classifier import PromptGuard2Classifier

    classifier = PromptGuard2Classifier()
    write_rows(score_cases(load_cases(corpus_path), classifier.score), out)


if __name__ == "__main__":
    cli(main)
