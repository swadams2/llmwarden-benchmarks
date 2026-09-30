"""Loads the external (non-LLMWarden) corpus sources for v3 and maps each
upstream row to a `Candidate`. Every fetch is pinned to a full 40-hex HF
commit SHA -- a floating ref (`main`, a branch, a short SHA) is refused before
any network request, since a dataset repo can be rewritten under a floating
ref after results are published.

Sources and why they were chosen/excluded:
context/projects/llmwarden-benchmarks/llmwarden-benchmarks-spec.md (Phase 2).
"""

from __future__ import annotations

import csv
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

GANDALF = "Lakera/gandalf_ignore_instructions"
IN_THE_WILD = "TrustAIRLab/in-the-wild-jailbreak-prompts"
SPML = "reshabhs/SPML_Chatbot_Prompt_Injection"
NOTINJECT = "leolee99/NotInject"
JACKHHAO = "jackhhao/jailbreak-classification"
DEEPSET = "deepset/prompt-injections"

# (dataset, config, split) -> file path inside the dataset repo. Explicit rather
# than discovered, so exactly which upstream files feed the corpus is auditable.
# Paths verified against the HF tree API at each pinned revision on 2026-09-29.
# NotInject's train/validation/test parquet files duplicate NotInject_one/two/three
# and are deliberately not listed.
_FILES: dict[tuple[str, str, str], str] = {
    (GANDALF, "default", "train"): "data/train-00000-of-00001-ded53be747ff55cd.parquet",
    (GANDALF, "default", "validation"): "data/validation-00000-of-00001-94481a2a09ff2fff.parquet",
    (GANDALF, "default", "test"): "data/test-00000-of-00001-bc92128b9288a6d1.parquet",
    (
        IN_THE_WILD,
        "jailbreak_2023_12_25",
        "train",
    ): "jailbreak_2023_12_25/train-00000-of-00001.parquet",
    (IN_THE_WILD, "regular_2023_12_25", "train"): "regular_2023_12_25/train-00000-of-00001.parquet",
    (SPML, "default", "train"): "spml_prompt_injection.csv",
    (NOTINJECT, "default", "NotInject_one"): "data/NotInject_one-00000-of-00001.parquet",
    (NOTINJECT, "default", "NotInject_two"): "data/NotInject_two-00000-of-00001.parquet",
    (NOTINJECT, "default", "NotInject_three"): "data/NotInject_three-00000-of-00001.parquet",
    (JACKHHAO, "default", "full"): "default/jailbreak_dataset_full.csv",
    (DEEPSET, "default", "train"): "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
    (DEEPSET, "default", "test"): "data/test-00000-of-00001-701d16158af87368.parquet",
}

_FULL_SHA = re.compile(r"[0-9a-f]{40}")


class FloatingRevisionError(ValueError):
    """A dataset revision that is not a full 40-hex commit SHA."""


@dataclass(frozen=True)
class Candidate:
    text: str
    label: str  # "malicious" | "benign"
    dataset: str  # HF dataset id, e.g. GANDALF
    revision: str  # full 40-hex HF commit SHA
    row_ref: str  # upstream location, e.g. "test/17" -- traceability only
    technique: str
    stratum: str = ""  # sampling stratum within its (dataset, label) quota; "" = none


def validate_revision(revision: str) -> str:
    if not _FULL_SHA.fullmatch(revision):
        raise FloatingRevisionError(
            f"dataset revision must be a full 40-hex lowercase commit SHA, got {revision!r}"
        )
    return revision


def fetch_rows(dataset: str, revision: str, config: str, split: str) -> list[Mapping[str, Any]]:
    """Downloads one pinned upstream file and returns its rows as dicts."""
    validate_revision(revision)  # before anything else, including the network
    try:
        filename = _FILES[(dataset, config, split)]
    except KeyError:
        raise ValueError(f"no known file for {dataset} config={config} split={split}") from None

    from huggingface_hub import hf_hub_download

    # Public datasets: never send the user's HF token where it isn't needed.
    path = hf_hub_download(
        repo_id=dataset, repo_type="dataset", filename=filename, revision=revision, token=False
    )
    if filename.endswith(".parquet"):
        import pyarrow.parquet as pq

        return pq.read_table(path).to_pylist()
    # SPML prompts exceed csv's 128KB default field limit; 2**31-1 is the max a
    # 32-bit C long (Windows) accepts -- sys.maxsize overflows there.
    csv.field_size_limit(2**31 - 1)
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def quartile_labels(values: Sequence[float]) -> list[str]:
    """Labels each value "q1".."q4" by its quartile within `values` (rank-based;
    ties broken by position, so the split stays even)."""
    n = len(values)
    order = sorted(range(n), key=lambda i: values[i])
    labels = [""] * n
    for rank, i in enumerate(order):
        labels[i] = f"q{1 + (rank * 4) // n}"
    return labels


def _text_field(row: Mapping[str, Any], key: str, dataset: str, row_ref: str) -> str:
    """Upstream rows are external input: a missing or non-string text field is
    rejected, never coerced (str(None) would enter the corpus as "None")."""
    value = row.get(key)
    if not isinstance(value, str):
        raise TypeError(f"{dataset} {row_ref}: {key!r} is {type(value).__name__}, expected str")
    return value


def gandalf_row_to_candidate(
    row: Mapping[str, Any], revision: str, row_ref: str, stratum: str
) -> Candidate:
    return Candidate(
        text=_text_field(row, "text", GANDALF, row_ref),
        label="malicious",
        dataset=GANDALF,
        revision=validate_revision(revision),
        row_ref=row_ref,
        technique="direct_injection",
        stratum=stratum,
    )


def spml_row_to_candidate(row: Mapping[str, Any], revision: str, row_ref: str) -> Candidate:
    # Only the user prompt is the attacker-controlled direct input; the system
    # prompt is the application's and is never emitted.
    malicious = int(row["Prompt injection"]) == 1
    return Candidate(
        text=_text_field(row, "User Prompt", SPML, row_ref),
        label="malicious" if malicious else "benign",
        dataset=SPML,
        revision=validate_revision(revision),
        row_ref=row_ref,
        technique="direct_injection" if malicious else "benign_natural",
        stratum=f"degree:{int(row['Degree'])}",
    )


def in_the_wild_row_to_candidate(
    row: Mapping[str, Any], revision: str, row_ref: str, label: str
) -> Candidate:
    # The config (jailbreak_* vs regular_*) decides the label; the row's own
    # `jailbreak` flag must agree, or the upstream data isn't what we think it is.
    flag = row.get("jailbreak")
    if flag is not None and bool(flag) != (label == "malicious"):
        raise ValueError(f"{IN_THE_WILD} {row_ref}: jailbreak={flag!r} contradicts label {label!r}")
    return Candidate(
        text=_text_field(row, "prompt", IN_THE_WILD, row_ref),
        label=label,
        dataset=IN_THE_WILD,
        revision=validate_revision(revision),
        row_ref=row_ref,
        technique="jailbreak_in_the_wild" if label == "malicious" else "benign_natural",
    )


def notinject_row_to_candidate(
    row: Mapping[str, Any], revision: str, row_ref: str, split: str
) -> Candidate:
    return Candidate(
        text=_text_field(row, "prompt", NOTINJECT, row_ref),
        label="benign",
        dataset=NOTINJECT,
        revision=validate_revision(revision),
        row_ref=row_ref,
        technique="benign_trigger_words",
        stratum=split.removeprefix("NotInject_"),
    )


# Revisions verified 2026-09-29 (dev-log, Phase 2 research step). Changing one
# changes the corpus: bump only together with a new corpus version.
PINNED: dict[str, str] = {
    GANDALF: "04737b65e90a6794ec227012e4a255a7def6344b",
    IN_THE_WILD: "a10aab8eff1c73165a442d4464dce192bd28b9c5",
    SPML: "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
    NOTINJECT: "847ae76cf8fea5ed325429e569ae8cfef022d2e0",
    JACKHHAO: "2f2ceeb39658696fd3f462403562b6eea5306287",
    DEEPSET: "4f61ecb038e9c3fb77e21034b22511b523772cdd",
}


def load_candidates() -> tuple[list[Candidate], list[str]]:
    """Fetches every external source at its pinned revision. Returns the
    candidates plus a note per upstream row that failed validation -- reported,
    never silently dropped."""
    candidates: list[Candidate] = []
    skipped: list[str] = []

    def add(where: str, make: Callable[..., Candidate], *args: Any) -> None:
        try:
            candidates.append(make(*args))
        except (TypeError, ValueError) as exc:
            skipped.append(f"{where}: {exc}")

    rev = PINNED[GANDALF]
    gandalf = [
        (f"{split}/{i}", row)
        for split in ("train", "validation", "test")
        for i, row in enumerate(fetch_rows(GANDALF, rev, "default", split))
    ]
    # Quartiles over all 1,000 rows: every row was selected at similarity
    # >=0.825 to "ignore all previous instructions", so sampling across the
    # quartiles keeps the less-similar phrasings represented (spec, Phase 2).
    strata = quartile_labels([float(row["similarity"]) for _, row in gandalf])
    for (ref, row), stratum in zip(gandalf, strata, strict=True):
        add(f"{GANDALF} {ref}", gandalf_row_to_candidate, row, rev, ref, stratum)

    rev = PINNED[IN_THE_WILD]
    for config, label in (("jailbreak_2023_12_25", "malicious"), ("regular_2023_12_25", "benign")):
        for i, row in enumerate(fetch_rows(IN_THE_WILD, rev, config, "train")):
            ref = f"{config}/{i}"
            add(f"{IN_THE_WILD} {ref}", in_the_wild_row_to_candidate, row, rev, ref, label)

    rev = PINNED[SPML]
    for i, row in enumerate(fetch_rows(SPML, rev, "default", "train")):
        ref = f"train/{i}"
        add(f"{SPML} {ref}", spml_row_to_candidate, row, rev, ref)

    rev = PINNED[NOTINJECT]
    for split in ("NotInject_one", "NotInject_two", "NotInject_three"):
        for i, row in enumerate(fetch_rows(NOTINJECT, rev, "default", split)):
            ref = f"{split}/{i}"
            add(f"{NOTINJECT} {ref}", notinject_row_to_candidate, row, rev, ref, split)

    return candidates, skipped


def load_exclusions() -> dict[str, list[str]]:
    """Every text from the datasets LLMWarden was tuned/scored on, regardless of
    label -- both labels were used, so both carry the bias."""
    jackhhao = fetch_rows(JACKHHAO, PINNED[JACKHHAO], "default", "full")
    deepset = [
        row
        for split in ("train", "test")
        for row in fetch_rows(DEEPSET, PINNED[DEEPSET], "default", split)
    ]
    return {
        JACKHHAO: [row["prompt"] for row in jackhhao if isinstance(row.get("prompt"), str)],
        DEEPSET: [row["text"] for row in deepset if isinstance(row.get("text"), str)],
    }
