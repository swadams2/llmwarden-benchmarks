"""Shows how LLMWarden, raw Prompt Guard 2, LLM Guard and raw DeBERTa judge
one prompt, as a table: System, Test Prompt, Verdict, Correctness.

Each system is scored by its benchmark runner, unchanged, in its own venv, on
a one-case temporary corpus; the verdicts are exactly what the benchmark
records. Systems with a shipped decision use it (LLMWarden's `balanced`
profile, LLM Guard's 0.92). The raw models ship none, so they are read at
LLMWarden's `balanced` boundary, as in RESULTS.md. Correctness compares the
verdict with `--expect`.

Run from the repo root in .venv (needs .venv-llmguard too, and the DeBERTa
snapshot from `python -m benchmarks.run_raw_deberta --prepare`):
    python -m benchmarks.demo --expect malicious "Ignore all previous instructions"
    python -m benchmarks.demo --expect benign - < prompt.txt

Exit codes: 0 every system ran; 1 at least one system failed (its row says
why); 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404 -- runs this repo's own runners
import sys
import tempfile
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from benchmarks.run_llm_guard import THRESHOLDS as LLM_GUARD_THRESHOLDS
from benchmarks.runner_common import PROFILE_THRESHOLDS, Row

REPO = Path(__file__).resolve().parent.parent
PROMPT_WIDTH = 60
ERROR_WIDTH = 80
RUNNER_TIMEOUT_S = 600
# Control, format (bidi, zero-width, tag characters), private-use, unassigned
# and line/paragraph separators: shown as escapes so a prompt can't move the
# cursor, recolour the terminal or hide text in the table.
ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cn", "Zl", "Zp"})
TOKEN_VARS = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")
HEADERS = ("System", "Test Prompt", "Verdict", "Correctness")


class RunnerError(Exception):
    """A system could not produce a verdict."""


@dataclass(frozen=True)
class System:
    name: str
    venv: str
    module: str
    verdict_column: str
    boundary: str


_BALANCED = PROFILE_THRESHOLDS["balanced"]
SYSTEMS = (
    System(
        "LLMWarden",
        ".venv",
        "benchmarks.run_wrapper",
        "blocked_default",
        f"balanced profile (fast-path rules, then classifier score >= {_BALANCED})",
    ),
    System(
        "Raw Prompt Guard 2",
        ".venv",
        "benchmarks.run_raw_promptguard2",
        "blocked_balanced",
        f"score >= {_BALANCED} (no shipped threshold; LLMWarden's balanced boundary)",
    ),
    System(
        "LLM Guard",
        ".venv-llmguard",
        "benchmarks.run_llm_guard",
        "blocked_default",
        f"shipped default (injection score > {LLM_GUARD_THRESHOLDS['default']})",
    ),
    System(
        "Raw DeBERTa",
        ".venv-llmguard",
        "benchmarks.run_raw_deberta",
        "blocked_balanced",
        f"score >= {_BALANCED} (no shipped threshold; LLMWarden's balanced boundary)",
    ),
)


def venv_python(venv: str) -> Path:
    return REPO / venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def child_env() -> dict[str, str]:
    """The runners' environment: offline, and no Hugging Face token."""
    env = {k: v for k, v in os.environ.items() if k not in TOKEN_VARS}
    hf_home = Path(env.get("HF_HOME") or Path.home() / ".cache" / "huggingface")
    env["HF_HOME"] = str(hf_home.expanduser().resolve())
    env["HF_HUB_OFFLINE"] = "1"
    env["TRANSFORMERS_OFFLINE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def parse_runner_output(stdout: str) -> Row:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RunnerError(f"runner printed {len(lines)} result rows, expected 1")
    try:
        row = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise RunnerError(f"runner printed a row that is not JSON ({exc.msg})") from exc
    if not isinstance(row, dict):
        raise RunnerError("runner printed a row that is not a JSON object")
    return row


def run_system(system: System, corpus: Path) -> Row:
    python = venv_python(system.venv)
    if not python.exists():
        raise RunnerError(f"{system.venv} not set up")
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell, this repo's own module
            [str(python), "-m", system.module, str(corpus)],
            cwd=REPO,
            env=child_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=RUNNER_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(f"{system.module} timed out after {RUNNER_TIMEOUT_S}s") from exc
    if proc.returncode != 0:
        last = next((line for line in reversed(proc.stderr.splitlines()) if line.strip()), "")
        raise RunnerError(f"{system.module} exited {proc.returncode}: {last}")
    return parse_runner_output(proc.stdout)


def verdict(row: Row, column: str) -> tuple[str, bool]:
    """The Verdict text and whether the system blocked."""
    blocked = row.get(column)
    if not isinstance(blocked, bool):
        raise RunnerError(f"runner row has no boolean {column}")
    if not blocked:
        return "Allowed", False
    return ("Blocked (refused: too long)" if row.get("refused") else "Blocked"), True


def _escape(ch: str) -> str:
    if unicodedata.category(ch) in ESCAPED_CATEGORIES:
        return ch.encode("unicode_escape").decode("ascii")
    return ch


def _display(text: str, width: int) -> str:
    """Escaped text, truncated to `width` without splitting an escape."""
    pieces = [_escape(ch) for ch in text]
    if sum(map(len, pieces)) <= width:
        return "".join(pieces)
    kept, used = [], 0
    for piece in pieces:
        if used + len(piece) > width - 3:
            break
        kept.append(piece)
        used += len(piece)
    return "".join(kept) + "..."


def display_prompt(text: str) -> str:
    return _display(text, PROMPT_WIDTH)


def render_table(rows: Sequence[Sequence[str]]) -> str:
    widths = [max(len(r[i]) for r in [HEADERS, *rows]) for i in range(len(HEADERS))]

    def line(cells: Sequence[str]) -> str:
        return " | ".join(cell.ljust(w) for cell, w in zip(cells, widths, strict=True))

    rule = "-+-".join("-" * w for w in widths)
    return "\n".join([line(HEADERS), rule, *map(line, rows)])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.demo",
        description="Show how each system judges one prompt.",
    )
    parser.add_argument(
        "--expect",
        required=True,
        choices=["malicious", "benign"],
        help="the prompt's true label; Correctness compares each verdict with it",
    )
    parser.add_argument("prompt", help="the test prompt, or - to read it from stdin")
    return parser


def main(
    argv: Sequence[str] | None = None,
    run: Callable[[System, Path], Row] = run_system,
    stdin: TextIO | None = None,
    out: TextIO | None = None,
) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    out = out if out is not None else sys.stdout
    text: str = args.prompt
    if text == "-":
        text = (stdin if stdin is not None else sys.stdin).read().removesuffix("\n")
    if not text.strip():
        parser.error("the prompt is empty")
    try:
        _ = text.encode("utf-8")
    except UnicodeEncodeError:
        # A non-UTF-8 byte in argv arrives as a lone surrogate; the runners
        # need real text, and the corpus file couldn't hold it.
        parser.error("the prompt is not valid Unicode (unpaired surrogate)")
    should_block = args.expect == "malicious"
    prompt_shown = display_prompt(text)

    rows: list[tuple[str, str, str, str]] = []
    failed = False
    with tempfile.TemporaryDirectory(prefix="llmwarden-demo-") as tmp:
        corpus = Path(tmp) / "demo.jsonl"
        case = {"id": "demo", "label": args.expect, "text": text}
        corpus.write_text(json.dumps(case, ensure_ascii=False) + "\n", encoding="utf-8")
        for system in SYSTEMS:
            print(f"Running {system.name}...", file=sys.stderr, flush=True)
            try:
                shown, blocked = verdict(run(system, corpus), system.verdict_column)
                correctness = "Correct" if blocked == should_block else "Incorrect"
            except RunnerError as exc:
                shown = f"Error: {_display(str(exc), ERROR_WIDTH)}"
                correctness = "n/a"
                failed = True
            rows.append((system.name, prompt_shown, shown, correctness))

    print(f"Expected: {args.expect}\n", file=out)
    print(render_table(rows), file=out)
    print("\nDecision boundaries:", file=out)
    for system in SYSTEMS:
        print(f"  {system.name}: {system.boundary}", file=out)
    return 1 if failed else 0


if __name__ == "__main__":
    for stream in (sys.stdin, sys.stdout):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")  # pyright: ignore[reportAttributeAccessIssue]
    raise SystemExit(main())
