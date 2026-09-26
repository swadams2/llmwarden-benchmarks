"""Scores every corpus entry with the full LLMWarden.scan()
pipeline (fast-path scanner, normalization, base64 candidate-feeding,
windowing) at each of its 3 profiles.

Run: python benchmarks/run_wrapper.py corpus/evasion_corpus_v1.jsonl > results/wrapper.jsonl
"""

from __future__ import annotations

import json
import sys

from llmwarden import LLMWarden
from llmwarden.classifier import PromptGuard2Classifier

PROFILES = ["strict", "balanced", "permissive"]


def main(corpus_path: str) -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # pyright: ignore[reportAttributeAccessIssue]
    # One shared classifier instance across all 3 profiles -- avoids loading
    # the same 283MB model 3 times over.
    shared_classifier = PromptGuard2Classifier()
    firewalls = {
        profile: LLMWarden(profile=profile, classifier=shared_classifier)
        for profile in PROFILES
    }

    with open(corpus_path, encoding="utf-8") as f:
        cases = [json.loads(line) for line in f]

    for case in cases:
        result = {"id": case["id"]}
        for profile in PROFILES:
            scan_result = firewalls[profile].scan(case["text"])
            result[f"blocked_{profile}"] = scan_result.blocked
            if profile == "balanced":
                result["matched_rule"] = scan_result.matched_rule
                result["classifier_score"] = scan_result.classifier_score
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: run_wrapper.py <corpus.jsonl>", file=sys.stderr)
        raise SystemExit(2)
    main(sys.argv[1])
