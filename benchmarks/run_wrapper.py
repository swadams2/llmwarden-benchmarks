"""Scores every corpus entry with the full LLMWarden.scan()
pipeline (fast-path scanner, normalization, base64 candidate-feeding,
windowing) at each of its 3 profiles.

`blocked_default` is the `balanced` profile (LLMWarden's default). `score` is
the classifier score at `balanced`, null when the fast-path scanner decided
before the classifier ran; `matched_rule` names that fast-path rule.

Run: python -m benchmarks.run_wrapper corpus/evasion_corpus_v3.jsonl > results/wrapper.jsonl
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Protocol, TextIO

from benchmarks.runner_common import (
    PROFILE_THRESHOLDS,
    Case,
    Row,
    checked_score,
    cli,
    load_cases,
    write_rows,
)

DEFAULT_PROFILE = "balanced"


class ScanResultLike(Protocol):
    @property
    def blocked(self) -> bool: ...
    @property
    def matched_rule(self) -> str | None: ...
    @property
    def classifier_score(self) -> float | None: ...


def score_cases(
    cases: Iterable[Case], scanners: Mapping[str, Callable[[str], ScanResultLike]]
) -> Iterator[Row]:
    if set(scanners) != set(PROFILE_THRESHOLDS):
        raise ValueError(
            f"need one scanner per profile {sorted(PROFILE_THRESHOLDS)}, got {sorted(scanners)}"
        )
    for case in cases:
        results = {profile: scan(case["text"]) for profile, scan in scanners.items()}
        default = results[DEFAULT_PROFILE]
        score = default.classifier_score
        yield {
            "id": case["id"],
            "score": None if score is None else checked_score(case["id"], score),
            "blocked_default": default.blocked,
            **{f"blocked_{p}": results[p].blocked for p in PROFILE_THRESHOLDS},
            "matched_rule": default.matched_rule,
        }


def main(corpus_path: str, out: TextIO) -> None:
    from llmwarden import LLMWarden
    from llmwarden.classifier import PromptGuard2Classifier

    # One shared classifier instance across all 3 profiles -- avoids loading
    # the same 283MB model 3 times over.
    shared_classifier = PromptGuard2Classifier()
    scanners = {
        profile: LLMWarden(profile=profile, classifier=shared_classifier).scan
        for profile in PROFILE_THRESHOLDS
    }
    write_rows(score_cases(load_cases(corpus_path), scanners), out)


if __name__ == "__main__":
    cli(main)
