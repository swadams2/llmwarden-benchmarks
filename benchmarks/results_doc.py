"""Assembles RESULTS.md: the generated v3 document (systems, methodology,
tables, limitations) followed by the frozen v1 section, carried over
byte-for-byte from `HISTORICAL_MARKER` onward.

The prose states methods and limitations, never findings: numbers live only
in the generated tables, so a re-score can't leave a stale claim behind.

Run (reads RESULTS.md's historical section first, then replaces the file):
    python -m benchmarks.results_doc --update RESULTS.md corpus/evasion_corpus_v3.jsonl \\
        "LLMWarden=results/v3/wrapper.jsonl" "raw PG2-22M=results/v3/raw_promptguard2.jsonl" ...
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from benchmarks.scorer import (
    JsonRecord,
    System,
    load_jsonl,
    load_systems,
    parse_pair,
    render_tables,
)

HISTORICAL_MARKER = "<!-- historical: v1 -->"

# name -> (what it is, what is scored, own shipped decision). Wording for the
# third-party systems follows the spec (Phase 2, "System descriptions").
SYSTEM_DESCRIPTIONS: dict[str, tuple[str, str, str]] = {
    "LLMWarden": (
        "LLMWarden v0.7.0 (`41c4ab8`)",
        (
            "full `scan()` pipeline: fast-path signature scanner, Unicode normalization, "
            "encoding candidate-feeding and overlapping-window classification over "
            "Llama Prompt Guard 2 (22M)"
        ),
        "`balanced` profile: block when score >= 0.25",
    ),
    "raw PG2-22M": (
        "Llama Prompt Guard 2 (22M), raw",
        (
            "LLMWarden's own `PromptGuard2Classifier().score(text)`: no fast path, "
            "normalization or decoding. Its overlapping 512-token windows (up to 8) still "
            "apply, so long inputs are not truncated"
        ),
        "none (raw model)",
    ),
    "LlamaFirewall": (
        "LlamaFirewall 1.0.3 `PromptGuardScanner`",
        (
            "Llama Prompt Guard 2 (86M) @ `a8ded8e6` + whitespace-aware preprocessing + "
            "512-token truncation (not a raw model)"
        ),
        "block when score >= 0.9",
    ),
    "LLM Guard": (
        "LLM Guard 0.3.16 `PromptInjection`",
        (
            "`protectai/deberta-v3-base-prompt-injection-v2` @ `89b085cd` at the default "
            "`MatchType.FULL`: the whole prompt as one input, truncated at 512 tokens"
        ),
        "block when the injection score, rounded to 2 decimals, is > 0.92",
    ),
    "raw DeBERTa": (
        "deberta-v3-base-prompt-injection-v2, raw",
        (
            "the same model and revision as LLM Guard: tokenizer + softmax, truncated at "
            "512 tokens, no scanner"
        ),
        "none (raw model)",
    ),
}

METHODOLOGY = """\
## Methodology

Every system scores the exact same `text` per case. Recall = malicious cases
blocked / malicious cases. FPR = benign cases blocked / benign cases (lower is
better). Percentages are rounded to whole numbers; each row shows its n.

Two views:

- **Own shipped defaults**: each system's own decision at its shipped
  threshold, i.e. what an adopter gets out of the box. Raw models ship no
  threshold and are not in this view.
- **LLMWarden thresholds**: every system at LLMWarden's strict/balanced/permissive
  thresholds (0.1/0.25/0.4) applied to its score, which separates detection
  ability from the choice of decision boundary. LLM Guard's columns are its own
  `is_valid` verdicts from one scanner instance per threshold, since it rounds
  and compares with `>`; every other system's column is `score >= threshold`.

Sources: `LLMWarden (own tests/prose)` and `garak-derived` are the v2 cases
(LLMWarden's own test suite and garak encoding transforms applied to its
trigger phrases). `external` is the 200-case v3 slice from four public MIT
datasets that LLMWarden was not tuned on, deduplicated and human-reviewed (see
`corpus/SCHEMA.md` and `corpus/CHANGELOG.md`). LLMWarden is never tuned on it.
"""

LIMITATIONS = """\
- **Home-field bias is reduced, not removed.** 77 of 277 cases come from
  LLMWarden's own tests or reuse its trigger phrases; read the `external` rows
  for the least LLMWarden-shaped view. Any external source may still be in a
  model's training data: DeBERTa's model card names only 7 of about 22
  training datasets, and Meta does not itemize Prompt Guard 2's. No slice can
  be proven neutral for every system.
- **SPML labels are noisy.** SPML's injection label depends on a system prompt
  that is not scored. At review, 22 of 57 SPML malicious rows (39%) were
  rejected because the user text on its own was not an attack; the kept rows
  passed that check, but the source remains the lowest-confidence one.
- **Gandalf is selected on one phrasing.** Its rows were chosen by similarity
  to "ignore all previous instructions", so it is capped at 25 cases and
  stratified by similarity quartile.
- **Part of the benign slice is multilingual.** About 13 of the 50 NotInject
  cases are not in English, so benign FPR partly measures multilingual
  over-blocking.
- **Truncation is part of what is measured.** 23 of 277 cases exceed 512
  tokens (17 of the 40 in-the-wild jailbreaks). LlamaFirewall, LLM Guard (FULL)
  and raw DeBERTa see only the first 512 tokens; LLMWarden and raw PG2-22M
  score overlapping windows. These are the systems' shipped behaviours.
- **Threshold semantics differ only at the boundary.** LLM Guard rounds to 2
  decimals and blocks on `>`; the others block on `>=`. On this corpus no score
  falls within 0.005 of any threshold, so this changes no verdict.
- **LlamaFirewall's preprocessing fails open.** If its whitespace-aware
  preprocessing raises, it silently scores the unpreprocessed text.
- **Reproduction caveat.** LLM Guard and LlamaFirewall pin `transformers`
  4.51.3, which has published CVEs. They were run in isolated, hash-locked
  environments, offline, with model revisions pinned and their configs
  inspected. This affects how to rerun them safely, not their scores.
- **Scope** is direct-input injection/jailbreak detection only; output, PII,
  secret and tool-call scanning are not compared. Point-in-time results on a
  small corpus, not an exhaustive red-team.
"""


class UndocumentedSystemError(ValueError):
    """A scored system has no description, so readers couldn't tell what it is."""


class MissingHistoricalSectionError(ValueError):
    """RESULTS.md lacks the marker that starts the frozen v1 section."""


def historical_section(text: str) -> str:
    index = text.find(HISTORICAL_MARKER)
    if index == -1:
        raise MissingHistoricalSectionError(f"no {HISTORICAL_MARKER!r} line found")
    return text[index:]


def _refusal_lines(systems: Sequence[System]) -> list[str]:
    lines: list[str] = []
    for system in systems:
        refused = [i for i, row in system.results.items() if row.get("refused")]
        if refused:
            cases = ", ".join(f"`{i}`" for i in refused)
            noun = "case" if len(refused) == 1 else "cases"
            lines.append(
                f"- **Refusals count as blocked.** {len(refused)} {noun} ({cases}) refused by "
                + f"{system.name} as too long to score safely (`InputTooLongError`, which tells "
                + "the caller to reject the input). Counted as blocked, with no score."
            )
    return lines


def render_document(corpus_path: str, corpus: list[JsonRecord], systems: Sequence[System]) -> str:
    unknown = [s.name for s in systems if s.name not in SYSTEM_DESCRIPTIONS]
    if unknown:
        raise UndocumentedSystemError(f"no description for scored system(s): {unknown}")
    n_mal = sum(c["label"] == "malicious" for c in corpus)
    corpus_line = (
        f"Corpus: `{corpus_path}`, {len(corpus)} cases "
        + f"({n_mal} malicious / {len(corpus) - n_mal} benign).\n"
    )
    parts = [
        "# Prompt-injection detectors on the LLMWarden evasion corpus\n",
        corpus_line,
        "## Systems\n",
        "| System | What it is | What is scored | Own shipped decision |",
        "|---|---|---|---|",
        *(f"| {s.name} | {' | '.join(SYSTEM_DESCRIPTIONS[s.name])} |" for s in systems),
        "",
        METHODOLOGY,
        render_tables(corpus, list(systems)),
        "## Limitations\n",
        "\n".join([*_refusal_lines(systems), LIMITATIONS.rstrip("\n")]),
    ]
    return "\n".join(parts) + "\n"


def update_results_file(path: Path, generated: str) -> None:
    """Replaces everything before the historical marker. Reads the file first
    and writes via a temp file, so a failure leaves the original intact."""
    frozen = historical_section(path.read_bytes().decode("utf-8"))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".RESULTS.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            _ = f.write(f"{generated}\n{frozen}".encode())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def main(argv: Sequence[str]) -> None:
    if len(argv) < 4 or argv[0] != "--update":
        print(
            "usage: python -m benchmarks.results_doc --update RESULTS.md <corpus.jsonl> "
            + "NAME=RESULTS.jsonl ...",
            file=sys.stderr,
        )
        raise SystemExit(2)
    results_path, corpus_path, pair_args = Path(argv[1]), argv[2], argv[3:]
    corpus = load_jsonl(corpus_path)
    systems = load_systems(corpus, [parse_pair(a) for a in pair_args])
    update_results_file(results_path, render_document(corpus_path, corpus, systems))


if __name__ == "__main__":
    main(sys.argv[1:])
