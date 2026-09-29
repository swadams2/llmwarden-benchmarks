"""Scores every corpus entry with `protectai/deberta-v3-base-prompt-injection-v2`
used raw: tokenizer + model + softmax, no chunking and no scanner. It is the
raw-model half of the LLM Guard pair, as raw Prompt Guard 2 is for LLMWarden,
so the two runners share one pinned snapshot and differ only by LLM Guard's
wrapper. Tokenization matches LLM Guard's `pipeline_kwargs` (512-token
truncation, no token type ids): text past 512 tokens is not seen.

A raw model ships no decision threshold, so `blocked_default` is null.

Prepare once (online, public model, no token sent):
    python -m benchmarks.run_raw_deberta --prepare
Run (offline):
    python -m benchmarks.run_raw_deberta corpus/evasion_corpus_v3.jsonl > results/raw_deberta.jsonl
Needs .venv-llmguard (transformers 4.51.3; see requirements-llmguard.lock.txt).
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable, Iterator
from typing import TextIO

from benchmarks.runner_common import (
    Case,
    Row,
    cli,
    go_offline,
    load_cases,
    resolve_hf_home,
    score_raw_model_cases,
    write_rows,
)

REPO_ID = "protectai/deberta-v3-base-prompt-injection-v2"
# The revision llm-guard 0.3.16 pins in its own V2_MODEL; run_llm_guard asserts
# they still agree.
REVISION = "89b085cd330414d3e7d9dd787870f315957e1e9f"
# What from_pretrained reads for this model. The repo also holds an ONNX export
# and training_args.bin (a pickle), neither of which is downloaded.
MODEL_FILES = [
    "config.json",
    "model.safetensors",
    "added_tokens.json",
    "special_tokens_map.json",
    "spm.model",
    "tokenizer.json",
    "tokenizer_config.json",
]
MAX_TOKENS = 512
INJECTION_LABEL = "INJECTION"


def score_cases(cases: Iterable[Case], score: Callable[[str], float]) -> Iterator[Row]:
    return score_raw_model_cases(cases, score)


def load_scorer() -> Callable[[str], float]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(REPO_ID, revision=REVISION)
    model = AutoModelForSequenceClassification.from_pretrained(REPO_ID, revision=REVISION)
    model.eval()
    injection = model.config.label2id[INJECTION_LABEL]

    def score(text: str) -> float:
        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=MAX_TOKENS,
            return_token_type_ids=False,
        )
        with torch.no_grad():
            logits = model(**inputs).logits
        return torch.softmax(logits, dim=-1)[0, injection].item()

    return score


def prepare() -> None:
    resolve_hf_home()
    from huggingface_hub import snapshot_download

    # max_workers=1: huggingface_hub 0.36 marks a cache dir symlink-capable
    # before probing it, so parallel download threads can race into a symlink
    # Windows refuses (WinError 1314) instead of falling back to a copy.
    path = snapshot_download(
        REPO_ID, revision=REVISION, allow_patterns=MODEL_FILES, token=False, max_workers=1
    )
    print(f"prepared {REPO_ID}@{REVISION} at {path}", file=sys.stderr)


def main(corpus_path: str, out: TextIO) -> None:
    resolve_hf_home()
    go_offline()
    write_rows(score_cases(load_cases(corpus_path), load_scorer()), out)


if __name__ == "__main__":
    cli(main, prepare)
