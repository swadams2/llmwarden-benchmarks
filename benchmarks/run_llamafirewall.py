"""Scores every corpus entry with LlamaFirewall 1.0.3's `PromptGuardScanner` at
its shipped default (block when `score >= 0.9`): Llama-Prompt-Guard-2-86M plus
LlamaFirewall's whitespace-aware preprocessing and 512-token truncation. Not
a raw model.

Called through the public async `scan()` with a user `Message`. `score` is its
unrounded jailbreak probability, so LLMWarden's thresholds (`>=`) apply to it
directly. `blocked_default` is `score >= 0.9`, cross-checked against the
scanner's own BLOCK decision; a disagreement aborts the run.

LlamaFirewall's loader downloads from floating `main` (or calls interactive
`login()`) whenever `$HF_HOME/meta-llama--Llama-Prompt-Guard-2-86M` is missing.
So that directory is prepared from a pinned revision and checked against a
sha256 manifest before the scanner is constructed, and scoring runs offline.

Prepare once (online; the model is gated, so HF_TOKEN must be set in the
environment -- huggingface_hub reads it, this code never does):
    python -m benchmarks.run_llamafirewall --prepare
Run (offline):
    python -m benchmarks.run_llamafirewall corpus/evasion_corpus_v3.jsonl > results/llamafirewall.jsonl
Needs .venv-llamafirewall (requirements-llamafirewall.lock.txt).
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any, TextIO

from benchmarks.runner_common import (
    Case,
    Row,
    cli,
    go_offline,
    load_cases,
    resolve_hf_home,
    threshold_row,
    write_rows,
)

DEFAULT_THRESHOLD = 0.9  # PromptGuardScanner(block_threshold=0.9), verified in the 1.0.3 wheel
REPO_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
REVISION = "a8ded8e697ce7c355e395a0df51f94adb4a2fd27"
MODEL_DIR_NAME = REPO_ID.replace("/", "--")  # LlamaFirewall's own path scheme
MODEL_FILES = [
    "config.json",
    "model.safetensors",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
]
# sha256 per file of the prepared model dir, pinned after the first `--prepare`
# (HF hides a gated repo's hashes until access is granted). Empty = not pinned
# yet, and the runner refuses to score.
MANIFEST: dict[str, str] = {}
# huggingface_hub's local_dir bookkeeping; never read by from_pretrained.
_IGNORED_DIRS = {".cache"}


class ModelIntegrityError(RuntimeError):
    """The prepared model dir does not match the pinned manifest."""


class DecisionMismatchError(RuntimeError):
    """The scanner's own decision disagrees with `score >= DEFAULT_THRESHOLD`."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _files(model_dir: Path) -> set[str]:
    return {
        p.relative_to(model_dir).as_posix()
        for p in model_dir.rglob("*")
        if p.is_file() and p.relative_to(model_dir).parts[0] not in _IGNORED_DIRS
    }


def verify_model_dir(model_dir: Path, manifest: Mapping[str, str]) -> None:
    if not manifest:
        raise ModelIntegrityError(
            f"no pinned manifest for {REPO_ID}@{REVISION}: run --prepare and pin MANIFEST first"
        )
    if not model_dir.is_dir():
        raise ModelIntegrityError(f"model dir {model_dir} does not exist: run --prepare")
    present = _files(model_dir)
    problems = [f"missing {name}" for name in sorted(set(manifest) - present)]
    problems += [f"unexpected {name}" for name in sorted(present - set(manifest))]
    for name in sorted(set(manifest) & present):
        actual = _sha256(model_dir / name)
        if actual != manifest[name]:
            problems.append(f"{name}: expected sha256 {manifest[name]}, got {actual}")
    if problems:
        raise ModelIntegrityError(f"{model_dir} fails the pinned manifest: " + "; ".join(problems))


def score_cases(cases: Iterable[Case], scan: Callable[[str], tuple[float, bool]]) -> Iterator[Row]:
    """`scan(text)` returns `(score, blocked)`, `blocked` being the scanner's
    own decision at its default threshold."""
    for case in cases:
        score, blocked = scan(case["text"])
        row = threshold_row(case["id"], score, DEFAULT_THRESHOLD)
        if row["blocked_default"] != blocked:
            raise DecisionMismatchError(
                f"{case['id']}: scanner decided blocked={blocked} at score {score!r}, "
                f"but score >= {DEFAULT_THRESHOLD} is {row['blocked_default']}"
            )
        yield row


def _load_scanner() -> Callable[[str], tuple[float, bool]]:
    import asyncio

    # llamafirewall is installed only in .venv-llamafirewall (isolated deps).
    from llamafirewall.llamafirewall_data_types import (  # pyright: ignore[reportMissingImports]
        Message,
        Role,
        ScanDecision,
        ScanStatus,
    )
    from llamafirewall.scanners.prompt_guard_scanner import (  # pyright: ignore[reportMissingImports]
        PromptGuardScanner,
    )

    scanner = PromptGuardScanner()  # shipped default threshold

    def scan(text: str) -> tuple[float, bool]:
        result: Any = asyncio.run(scanner.scan(Message(role=Role.USER, content=text)))
        # `result.reason` embeds the full prompt text; it is never emitted.
        if result.status != ScanStatus.SUCCESS:
            raise RuntimeError(f"PromptGuardScanner returned status {result.status}")
        return result.score, result.decision == ScanDecision.BLOCK

    return scan


def prepare() -> None:
    model_dir = resolve_hf_home() / MODEL_DIR_NAME
    from huggingface_hub import snapshot_download

    snapshot_download(REPO_ID, revision=REVISION, allow_patterns=MODEL_FILES, local_dir=model_dir)
    manifest = {name: _sha256(model_dir / name) for name in sorted(_files(model_dir))}
    print(f"prepared {REPO_ID}@{REVISION} at {model_dir}; pin as MANIFEST:", file=sys.stderr)
    print(json.dumps(manifest, indent=4))


def main(corpus_path: str, out: TextIO) -> None:
    model_dir = resolve_hf_home() / MODEL_DIR_NAME
    go_offline()
    verify_model_dir(model_dir, MANIFEST)  # before the scanner can reach its loader
    cases = load_cases(corpus_path)
    write_rows(score_cases(cases, _load_scanner()), out)


if __name__ == "__main__":
    cli(main, prepare)
