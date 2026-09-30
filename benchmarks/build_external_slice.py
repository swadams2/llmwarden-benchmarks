"""Builds corpus v3: the frozen v2 corpus (copied line-for-line, so v2's bytes
are preserved inside v3) plus a sampled, deduplicated external slice drawn
from datasets LLMWarden was never tuned on.

`build_slice()` is pure -- it takes already-loaded candidates, so tests run on
in-memory fixtures with no network. Sampling is seeded, and a source that runs
short of its quota after dedupe raises rather than backfilling from another
source, since that would silently change the approved mix.

Scoping decisions (sources, quotas, exclusions): see
context/projects/llmwarden-benchmarks/llmwarden-benchmarks-spec.md (Phase 2).
"""

from __future__ import annotations

import json
import random
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

from benchmarks.external_sources import GANDALF, IN_THE_WILD, NOTINJECT, SPML, Candidate
from benchmarks.extract_corpus import CorpusCase

QUOTAS: dict[tuple[str, str], int] = {
    (IN_THE_WILD, "malicious"): 40,
    (SPML, "malicious"): 35,
    (GANDALF, "malicious"): 25,
    (NOTINJECT, "benign"): 50,
    (IN_THE_WILD, "benign"): 30,
    (SPML, "benign"): 20,
}

# Cross-source dedupe: a candidate is dropped if it duplicates any candidate
# from a source earlier in this list. Gandalf comes first because SPML sources
# 4,168 of its rows from the Gandalf game -- the original keeps its provenance.
PRIORITY: list[str] = [GANDALF, IN_THE_WILD, NOTINJECT, SPML]

_ID_PREFIX = {GANDALF: "gandalf", IN_THE_WILD: "itw", NOTINJECT: "notinject", SPML: "spml"}

# Each (dataset, label) pool is shuffled with the seed, then capped at this
# multiple of its quota before dedupe. Dedupe examines every row inside the cap
# (so drop records never depend on draw order); rows past the cap are never
# examined, which bounds near-duplicate cost on the 13-15K-row in-the-wild pools.
CAP_MULTIPLIER = 5

# Near-duplicate = Jaccard similarity of word 3-shingles (normalized text) at or
# above this cut-off. Chosen over difflib's character ratio, whose cheap
# quick_ratio() prefilter is ~0.9 for ANY two similar-length English texts --
# the first real build ran >10 min comparing nearly every pair quadratically.
# 0.5 calibrated on the real pools (dev-log, 2026-09-29): every sampled pair in
# 0.5-0.8 was the same jailbreak family or template ("John" game 0.50, YouTube-
# script template 0.68, Briarheart persona 0.75), and a one-word Gandalf edit
# scores only 0.55 because short texts have few shingles. Still fills every quota.
NEAR_DUP_JACCARD = 0.5
_SHINGLE_WORDS = 3


class InsufficientCandidatesError(RuntimeError):
    """A source has fewer eligible rows after dedupe than its quota."""


@dataclass(frozen=True)
class Drop:
    dataset: str
    row_ref: str
    reason: str  # "dup:v2:<id>" | "dup:cross-source" | "dup:within-source" | "excluded:<dataset>" | "empty-text" | "review:<reason>"


@dataclass
class BuildResult:
    cases: list[CorpusCase] = field(default_factory=list)
    drops: list[Drop] = field(default_factory=list)


def normalize_text(text: str) -> str:
    return " ".join(text.lower().split())


def _shingles(norm: str) -> frozenset[str]:
    words = norm.split()
    if len(words) < _SHINGLE_WORDS:
        return frozenset([norm])
    return frozenset(
        " ".join(words[i : i + _SHINGLE_WORDS]) for i in range(len(words) - _SHINGLE_WORDS + 1)
    )


class _Index:
    """Normalized texts with exact (hash) and near-duplicate lookup. An inverted
    shingle index means a probe only touches texts it actually shares a
    3-word shingle with, so cost scales with overlap, not pool size."""

    def __init__(self) -> None:
        self._exact: dict[str, str] = {}
        self._sizes: list[int] = []
        self._tags: list[str] = []
        self._postings: defaultdict[str, list[int]] = defaultdict(list)

    def add(self, norm: str, tag: str) -> None:
        _ = self._exact.setdefault(norm, tag)
        doc = len(self._tags)
        shingles = _shingles(norm)
        self._sizes.append(len(shingles))
        self._tags.append(tag)
        for shingle in shingles:
            self._postings[shingle].append(doc)

    def find(self, norm: str) -> str | None:
        if norm in self._exact:
            return self._exact[norm]
        probe = _shingles(norm)
        shared: Counter[int] = Counter()
        for shingle in probe:
            shared.update(self._postings.get(shingle, ()))
        matches = [
            doc
            for doc, inter in shared.items()
            if inter / (len(probe) + self._sizes[doc] - inter) >= NEAR_DUP_JACCARD
        ]
        # Earliest-added match, not first-found: set iteration order varies with
        # PYTHONHASHSEED, and drop reasons must be reproducible run to run.
        return self._tags[min(matches)] if matches else None


def _index(pairs: Iterable[tuple[str, str]]) -> _Index:
    index = _Index()
    for text, tag in pairs:
        index.add(normalize_text(text), tag)
    return index


def _allocate(quota: int, strata: Sequence[str], available: Mapping[str, int]) -> dict[str, int]:
    """Splits `quota` evenly across `strata` (remainder to the first in sorted
    order), then moves any stratum's shortfall to strata with rows to spare."""
    k = len(strata)
    alloc = {s: quota // k + (1 if i < quota % k else 0) for i, s in enumerate(strata)}
    shortfall = 0
    for s in strata:
        if alloc[s] > available[s]:
            shortfall += alloc[s] - available[s]
            alloc[s] = available[s]
    while shortfall:
        spare = [s for s in strata if alloc[s] < available[s]]
        if not spare:
            break
        for s in spare:
            if not shortfall:
                break
            alloc[s] += 1
            shortfall -= 1
    return alloc


def _drop_reason(norm: str, review: str | None, *checks: tuple[_Index, str]) -> str | None:
    """Why a candidate is dropped, or None to keep it. Empty text and a review
    rejection come first, then each (index, reason) check in the order given;
    the first that applies is recorded. A reason ending in ":" gets the
    matched tag appended (the v2 case id or the excluded dataset)."""
    if not norm:
        return "empty-text"
    if review is not None:
        return f"review:{review}"
    for index, reason in checks:
        if (hit := index.find(norm)) is not None:
            return f"{reason}{hit}" if reason.endswith(":") else reason
    return None


def build_slice(
    candidates: Sequence[Candidate],
    existing: Mapping[str, str],
    exclusions: Mapping[str, Sequence[str]],
    seed: int,
    quotas: Mapping[tuple[str, str], int] = QUOTAS,
    rejected: Mapping[tuple[str, str], str] | None = None,
) -> BuildResult:
    """`existing` maps v2 case id -> text; `exclusions` maps an excluded
    dataset id -> its texts; `rejected` maps (dataset, row_ref) -> the human
    review's reason for rejecting that row."""
    rejected = rejected or {}
    result = BuildResult()
    unknown = {c.dataset for c in candidates} - set(PRIORITY)
    if unknown:
        raise ValueError(f"candidates from unconfigured datasets: {sorted(unknown)}")
    # Review rejections are keyed by (dataset, row_ref): a shared ref would let
    # one review decision silently hit two different rows.
    refs = Counter((c.dataset, c.row_ref) for c in candidates)
    clashes = sorted(key for key, n in refs.items() if n > 1)
    if clashes:
        raise ValueError(f"duplicate (dataset, row_ref) keys: {clashes[:5]}")
    # A rejection that matches no candidate is a typo or stale: fail loudly,
    # since ignoring it would let a reviewer-rejected row back into the corpus.
    unmatched = sorted(set(rejected) - set(refs))
    if unmatched:
        raise ValueError(
            f"{len(unmatched)} review rejection(s) match no candidate: {unmatched[:5]}"
        )

    existing_index = _index((text, case_id) for case_id, text in existing.items())
    exclusion_index = _index((t, ds) for ds, texts in exclusions.items() for t in texts)
    # Cross-source dedupe checks each higher-priority source's FULL pool, so an
    # SPML copy of an unsampled Gandalf row still can't enter under SPML's name.
    higher_priority = _Index()

    for dataset in PRIORITY:
        pool = [c for c in candidates if c.dataset == dataset]
        within = _Index()
        numbered = 0  # ids run ext-<prefix>-001.. across both labels of a dataset
        for label in ("malicious", "benign"):
            quota = quotas.get((dataset, label))
            if quota is None:
                continue
            group = [c for c in pool if c.label == label]
            random.Random(f"{seed}:{dataset}:{label}").shuffle(group)  # nosec B311 -- seeded for reproducible sampling, not security
            eligible: list[Candidate] = []
            for c in group[: quota * CAP_MULTIPLIER]:
                norm = normalize_text(c.text)
                reason = _drop_reason(
                    norm,
                    rejected.get((dataset, c.row_ref)),
                    (existing_index, "dup:v2:"),
                    (exclusion_index, "excluded:"),
                    (higher_priority, "dup:cross-source"),
                    (within, "dup:within-source"),
                )
                if reason is not None:
                    result.drops.append(Drop(dataset, c.row_ref, reason))
                else:
                    within.add(norm, dataset)
                    eligible.append(c)

            if len(eligible) < quota:
                raise InsufficientCandidatesError(
                    f"{dataset} ({label}): quota {quota}, only {len(eligible)} eligible "
                    f"after dedupe/exclusions -- not backfilling from another source"
                )
            available = Counter(c.stratum for c in eligible)
            strata = sorted(available)
            alloc = _allocate(quota, strata, available)
            taken = {s: 0 for s in strata}
            for c in eligible:  # shuffled order
                if taken[c.stratum] < alloc[c.stratum]:
                    taken[c.stratum] += 1
                    numbered += 1
                    result.cases.append(
                        CorpusCase(
                            id=f"ext-{_ID_PREFIX[dataset]}-{numbered:03d}",
                            text=c.text,
                            label=c.label,
                            technique=c.technique,
                            target_surface="fast_path_or_classifier",
                            source=f"external:{c.dataset}@{c.revision}",
                            notes=f"upstream row {c.row_ref}"
                            + (f"; stratum {c.stratum}" if c.stratum else ""),
                        )
                    )
        for c in pool:
            higher_priority.add(normalize_text(c.text), dataset)
    return result


def build_v3(
    v2_path: Path,
    output_path: Path,
    candidates: Sequence[Candidate],
    exclusions: Mapping[str, Sequence[str]],
    seed: int,
    rejected: Mapping[tuple[str, str], str] | None = None,
) -> BuildResult:
    if output_path.resolve() == v2_path.resolve():
        raise ValueError("refusing to overwrite the frozen v2 corpus")
    v2_bytes = v2_path.read_bytes()
    existing = {
        row["id"]: row["text"] for row in map(json.loads, v2_bytes.decode("utf-8").splitlines())
    }
    result = build_slice(candidates, existing, exclusions, seed, rejected=rejected)
    new_lines = "".join(
        json.dumps(asdict(case), ensure_ascii=False) + "\n" for case in result.cases
    )
    # Binary write: v2's bytes verbatim, and "\n" line endings on every platform.
    output_path.write_bytes(v2_bytes + new_lines.encode("utf-8"))
    return result


V2_PATH = Path(__file__).resolve().parent.parent / "corpus" / "evasion_corpus_v2.jsonl"
# Committed output of the human review gate: {dataset: {row_ref: reason}}.
# Row references and reasons only -- never row content.
REJECTIONS_PATH = V2_PATH.with_name("v3_review_rejections.json")
SEED = 20260929


def load_rejections(path: Path) -> dict[tuple[str, str], str]:
    # Required, not optional: a missing file would load as "no rejections" and
    # silently let every reviewer-rejected row back into the draft.
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"{path}: expected an object of {{dataset: {{row_ref: reason}}}}")
    rejected: dict[tuple[str, str], str] = {}
    for dataset, rows in raw.items():
        if dataset not in PRIORITY or not isinstance(rows, dict):
            raise ValueError(f"{path}: unknown dataset or malformed entry {dataset!r}")
        for row_ref, reason in rows.items():
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"{path}: {dataset} {row_ref}: reason must be a non-empty string")
            rejected[(dataset, row_ref)] = reason.strip()
    return rejected


def main(output: str) -> None:
    out = Path(output)
    # The review gate: a run can only produce a gitignored draft (corpus/_*).
    # v3 is frozen by renaming the draft after the human review, never here.
    if not out.name.startswith("_"):
        raise SystemExit(
            "output must be an unreviewed draft named _*.jsonl (e.g. "
            "corpus/_evasion_corpus_v3.draft.jsonl); freeze v3 by renaming after review"
        )
    from benchmarks.external_sources import load_candidates, load_exclusions

    started = time.perf_counter()
    candidates, skipped = load_candidates()
    exclusions = load_exclusions()
    rejected = load_rejections(REJECTIONS_PATH)
    loaded = time.perf_counter()
    result = build_v3(V2_PATH, out, candidates, exclusions, SEED, rejected=rejected)
    built = time.perf_counter()

    drops_path = out.with_suffix(".drops.jsonl")
    with open(drops_path, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(json.dumps(asdict(drop), ensure_ascii=False) + "\n" for drop in result.drops)
        f.writelines(
            json.dumps({"skipped_row": note}, ensure_ascii=False) + "\n" for note in skipped
        )

    def show(title: str, counts: Counter[str]) -> None:
        print(title, file=sys.stderr)
        for key, n in sorted(counts.items()):
            print(f"  {n:>6}  {key}", file=sys.stderr)

    show(
        "candidates loaded (dataset, label):", Counter(f"{c.dataset} {c.label}" for c in candidates)
    )
    print(f"upstream rows skipped (failed validation): {len(skipped)}", file=sys.stderr)
    show(
        "drops by reason:",
        Counter(
            d.reason.split(":v2:")[0] if d.reason.startswith("dup:v2") else d.reason
            for d in result.drops
        ),
    )
    show(
        "emitted (dataset, label):",
        Counter(f"{c.source.split('@')[0]} {c.label}" for c in result.cases),
    )
    print(f"load {loaded - started:.1f}s, build {built - loaded:.1f}s", file=sys.stderr)
    print(f"draft: {out}\ndrops: {drops_path}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "usage: python -m benchmarks.build_external_slice corpus/_evasion_corpus_v3.draft.jsonl",
            file=sys.stderr,
        )
        raise SystemExit(2)
    main(sys.argv[1])
