"""Assembles RESULTS.md: the generated v3 document (systems, methodology,
tables, limitations) followed by the frozen v1 section, carried over
byte-for-byte from `HISTORICAL_MARKER` onward.

The prose states methods and limitations, never findings: numbers live only
in the generated tables, so a re-score can't leave a stale claim behind. The
few corpus counts the prose does state (277 cases, 23 over 512 tokens, ...)
are v3's, so `main` refuses any corpus but frozen v3.

Run (reads RESULTS.md's historical section first, then replaces the file):
    python -m benchmarks.results_doc --update RESULTS.md corpus/evasion_corpus_v3.jsonl \\
        "LLMWarden=results/v3/wrapper.jsonl" "raw PG2-22M=results/v3/raw_promptguard2.jsonl" ...
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import textwrap
from collections.abc import Sequence
from pathlib import Path

from benchmarks.run_llm_guard import THRESHOLDS as LLM_GUARD_THRESHOLDS
from benchmarks.runner_common import load_cases
from benchmarks.scorer import (
    JsonRecord,
    System,
    corpus_summary,
    load_systems,
    parse_pair,
    render_tables,
)

HISTORICAL_MARKER = "<!-- historical: v1 -->"

# sha256 of corpus/evasion_corpus_v3.jsonl as frozen 2026-09-29 (`477aef5`).
V3_CORPUS_SHA256 = "b2eb5cc281793b111c65c733ca3ee17ce5d56c86f6f19cac8be130ddb91b4991"

# LLM Guard rounds to 2 decimals before comparing, so only a score this close
# to a threshold can get a different verdict than a plain `>=` would give.
BOUNDARY_MARGIN = 0.005

# Mirrors llmwarden.core._CLASSIFIER_TIME_BUDGET_MS (module-private, not
# exported -- hardcoded here rather than reached into, like PROFILE_THRESHOLDS).
LLMWARDEN_CANDIDATE_BUDGET_MS = 180

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

# Table labels, in table order, for systems that see only the first 512
# tokens vs. those that score overlapping windows.
TRUNCATING = {
    "LlamaFirewall": "LlamaFirewall",
    "LLM Guard": "LLM Guard (FULL)",
    "raw DeBERTa": "raw DeBERTa",
}
WINDOWING = ("LLMWarden", "raw PG2-22M")

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

LIMITATIONS_HEAD = """\
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
  over-blocking."""

LLAMAFIREWALL_SCORED = """\
- **LlamaFirewall's preprocessing fails open.** If its whitespace-aware
  preprocessing raises, it silently scores the unpreprocessed text."""

LLAMAFIREWALL_UNSCORED = """\
- **LlamaFirewall is not yet scored.** It is waiting on gated access to Prompt
  Guard 2 (86M) and is absent from every table above. When it is scored, note
  that its whitespace-aware preprocessing fails open: if that raises, the
  unpreprocessed text is scored."""

LIMITATIONS_TAIL = """\
- **Reproduction caveat.** The LLM Guard and LlamaFirewall environments pin
  `transformers` 4.51.3, which has published CVEs. Both are isolated and
  hash-locked, and scoring runs offline with model revisions pinned and
  configs inspected. This affects how to rerun them safely, not the scores.
- **Scope** is direct-input injection/jailbreak detection only; output, PII,
  secret and tool-call scanning are not compared. Point-in-time results on a
  small corpus, not an exhaustive red-team."""


class UndocumentedSystemError(ValueError):
    """A scored system has no description, so readers couldn't tell what it is."""


class MissingHistoricalSectionError(ValueError):
    """RESULTS.md lacks the marker that starts the frozen v1 section."""


class UnexpectedCorpusError(ValueError):
    """The corpus is not frozen v3, whose counts the Limitations prose states."""


def historical_section(text: str) -> str:
    index = text.find(HISTORICAL_MARKER)
    if index == -1:
        raise MissingHistoricalSectionError(f"no {HISTORICAL_MARKER!r} line found")
    return text[index:]


def _bullet(text: str) -> str:
    return textwrap.fill(text, width=80, initial_indent="- ", subsequent_indent="  ")


def _names(names: Sequence[str]) -> str:
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def _refusal_lines(systems: Sequence[System]) -> list[str]:
    """One bullet per distinct (cases, reasons) pair, naming every system that
    refused exactly those cases. Reasons are read from each row's `refused`."""
    groups: dict[tuple[tuple[str, ...], tuple[str, ...]], list[str]] = {}
    for system in systems:
        refused: dict[str, str] = {}
        for case_id, row in system.results.items():
            match row:
                case {"refused": str() as reason} if reason:
                    refused[case_id] = reason
                case _:
                    pass
        if refused:
            key = (tuple(refused), tuple(sorted(set(refused.values()))))
            groups.setdefault(key, []).append(system.name)
    lines: list[str] = []
    for (cases, reasons), names in groups.items():
        too_long = reasons == ("InputTooLongError",)
        why = " as too long to score safely" if too_long else ""
        note = ", which tells the caller to reject the input" if too_long else ""
        listed = ", ".join(f"`{i}`" for i in cases)
        noun = "case" if len(cases) == 1 else "cases"
        errors = ", ".join(f"`{r}`" for r in reasons)
        lines.append(
            f"- **Refusals count as blocked.** {len(cases)} {noun} ({listed}) refused by "
            + f"{_names(names)}{why} ({errors}{note}). Counted as blocked, with no score."
        )
    return lines


def _truncation_line(scored: set[str]) -> str:
    clauses: list[str] = []
    truncating = [label for name, label in TRUNCATING.items() if name in scored]
    if truncating:
        clauses.append(f"{_names(truncating)} see only the first 512 tokens")
    windowing = [name for name in WINDOWING if name in scored]
    if windowing:
        clauses.append(f"{_names(windowing)} score overlapping windows")
    return _bullet(
        "**Truncation is part of what is measured.** 23 of 277 cases exceed 512 tokens "
        + f"(17 of the 40 in-the-wild jailbreaks). {'; '.join(clauses)}. "
        + "These are the systems' shipped behaviours."
    )


def _boundary_line(llm_guard: System) -> str:
    thresholds = sorted(set(LLM_GUARD_THRESHOLDS.values()), reverse=True)
    near: list[str] = []
    for case_id, row in llm_guard.results.items():
        match row:
            case {"score": float() as score} if any(
                abs(score - t) <= BOUNDARY_MARGIN for t in thresholds
            ):
                near.append(case_id)
            case _:
                pass
    if near:
        one = len(near) == 1
        listed = ", ".join(f"`{i}`" for i in near)
        finding = (
            f"{len(near)} LLM Guard {'score falls' if one else 'scores fall'} within "
            + f"{BOUNDARY_MARGIN} of a threshold ({listed}); "
            + f"{'its verdict is' if one else 'their verdicts are'} LLM Guard's own, "
            + "rounding included."
        )
    else:
        listed = ", ".join(f"{t:g}" for t in thresholds)
        finding = (
            f"No LLM Guard score falls within {BOUNDARY_MARGIN} of a threshold it is "
            + f"compared against ({listed}), so this changes no verdict here."
        )
    return _bullet(
        "**Threshold semantics differ only at the boundary.** LLM Guard rounds to 2 "
        + f"decimals and blocks on `>`; the others block on `>=`. {finding}"
    )


def _time_bound_line() -> str:
    return _bullet(
        "**LLMWarden's decoded-candidate scoring is time-bounded.** `scan()` stops "
        + f"scoring decoded encoding candidates after {LLMWARDEN_CANDIDATE_BUDGET_MS} ms "
        + "of wall-clock time, so a much slower machine could reach a different verdict. "
        + "The runner loads the model before scoring, so loading time is never counted; "
        + "a cold run and two warm-up runs of v3 gave identical per-case results."
    )


def _limitations(systems: Sequence[System]) -> str:
    by_name = {s.name: s for s in systems}
    lines = [*_refusal_lines(systems), LIMITATIONS_HEAD, _truncation_line(set(by_name))]
    if "LLM Guard" in by_name:
        lines.append(_boundary_line(by_name["LLM Guard"]))
    if "LLMWarden" in by_name:
        lines.append(_time_bound_line())
    lines.append(LLAMAFIREWALL_SCORED if "LlamaFirewall" in by_name else LLAMAFIREWALL_UNSCORED)
    lines.append(LIMITATIONS_TAIL)
    return "\n".join(lines)


def render_document(corpus_path: str, corpus: list[JsonRecord], systems: Sequence[System]) -> str:
    unknown = [s.name for s in systems if s.name not in SYSTEM_DESCRIPTIONS]
    if unknown:
        raise UndocumentedSystemError(f"no description for scored system(s): {unknown}")
    parts = [
        "# Prompt-injection detectors on the LLMWarden evasion corpus\n",
        corpus_summary(corpus_path, corpus) + "\n",
        "## Systems\n",
        "| System | What it is | What is scored | Own shipped decision |",
        "|---|---|---|---|",
        *(f"| {s.name} | {' | '.join(SYSTEM_DESCRIPTIONS[s.name])} |" for s in systems),
        "",
        METHODOLOGY,
        render_tables(corpus, list(systems)),
        "## Limitations\n",
        _limitations(systems),
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


def _require_frozen_v3(corpus_path: str) -> None:
    digest = hashlib.sha256(Path(corpus_path).read_bytes()).hexdigest()
    if digest != V3_CORPUS_SHA256:
        raise UnexpectedCorpusError(
            f"{corpus_path}: sha256 {digest[:12]}... is not frozen v3 "
            + f"({V3_CORPUS_SHA256[:12]}...); the Limitations prose states v3's counts"
        )


def main(argv: Sequence[str]) -> None:
    if len(argv) < 4 or argv[0] != "--update":
        print(
            "usage: python -m benchmarks.results_doc --update RESULTS.md <corpus.jsonl> "
            + "NAME=RESULTS.jsonl ...",
            file=sys.stderr,
        )
        raise SystemExit(2)
    results_path, corpus_path, pair_args = Path(argv[1]), argv[2], argv[3:]
    _require_frozen_v3(corpus_path)
    corpus = load_cases(corpus_path)
    systems = load_systems(corpus, [parse_pair(a) for a in pair_args])
    update_results_file(results_path, render_document(corpus_path, corpus, systems))


if __name__ == "__main__":
    main(sys.argv[1:])
