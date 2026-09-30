# llmwarden-benchmarks

A versioned evasion-case corpus and scorer for prompt-injection detectors. It compares
LLMWarden's full `LLMWarden.scan()` pipeline (LLMWarden is a private repository, not publicly
available; see [Without LLMWarden access](#without-llmwarden-access)) with the classifier it
bundles used raw, and with two third-party detectors and their own raw model, all on
the same input:

| System | What is scored |
|---|---|
| LLMWarden | full `scan()` pipeline over Llama Prompt Guard 2 (22M) |
| raw PG2-22M | the same classifier, no LLMWarden preprocessing |
| LlamaFirewall 1.0.3 | `PromptGuardScanner`: Llama Prompt Guard 2 (86M) + whitespace-aware preprocessing |
| LLM Guard 0.3.16 | `PromptInjection` scanner over `deberta-v3-base-prompt-injection-v2` |
| raw DeBERTa | the same DeBERTa model, no scanner |

Two questions: how much does each wrapper change detection over its own raw model, and how do the
systems compare on prompts LLMWarden was never tuned on?

**Results: [`RESULTS.md`](RESULTS.md).** It holds the current corpus (v3) results, followed by
the original v1 two-system results, kept verbatim.

> **Status:** LlamaFirewall's model (Llama-Prompt-Guard-2-86M) is gated on Hugging Face and needs
> Meta's manual approval. Until it is scored, `RESULTS.md` covers the other four systems.

## Environments

The third-party systems pin dependencies that conflict with LLMWarden's and with each other
(LLM Guard hard-pins `transformers==4.51.3`; LlamaFirewall needs `huggingface-hub<1.0`), so there
are three virtual environments. The two third-party ones install from hash-locked requirement files.

| Environment | Runners | Install from |
|---|---|---|
| `.venv` | LLMWarden, raw PG2-22M, scorer, corpus builder, tests | `pyproject.toml` |
| `.venv-llmguard` | LLM Guard, raw DeBERTa (same env, so the pair differs only by the scanner) | `requirements-llmguard.lock.txt` |
| `.venv-llamafirewall` | LlamaFirewall | `requirements-llamafirewall.lock.txt` + `requirements-llamafirewall-pkg.txt` |

**Main environment.** Installing `llmwarden[classifier]` pulls LLMWarden's Git-LFS-tracked
classifier weights (~283MB). Run `git lfs install` once per machine first, or you get a 134-byte
pointer file and the classifier fails to load.

```bash
git lfs install   # once per machine
python -m venv .venv && source .venv/Scripts/activate   # or .venv/bin/activate on macOS/Linux
pip install -e ".[dev]"
```

`llmwarden[classifier]` is pinned to a commit SHA, not a mutable tag (see `pyproject.toml`).
This install needs read access to LLMWarden's private repository: without it, pip's clone of
that dependency fails with "Repository not found". See
[Without LLMWarden access](#without-llmwarden-access) for what reproduces without it.

**Third-party environments** (Python 3.12: llm-guard 0.3.16 does not support 3.13; the commands use
[uv](https://docs.astral.sh/uv/)). Paths are shown for Windows; on macOS/Linux use `bin/` in place of `Scripts/`.

```bash
uv venv .venv-llmguard --python 3.12
uv pip install --python .venv-llmguard/Scripts/python.exe --require-hashes -r requirements-llmguard.lock.txt

uv venv .venv-llamafirewall --python 3.12
uv pip install --python .venv-llamafirewall/Scripts/python.exe --require-hashes -r requirements-llamafirewall.lock.txt
uv pip install --python .venv-llamafirewall/Scripts/python.exe --require-hashes --no-deps -r requirements-llamafirewall-pkg.txt
```

`llamafirewall` is installed `--no-deps` on purpose: its declared `codeshield` (which pulls
`semgrep`), `openai` and `typer` dependencies are only imported by other scanners, never on the
`PromptGuardScanner` path. `pip check` reports them missing; that is expected. The reasoning is in
the comments of `requirements-llamafirewall.in`.

LLM Guard and LlamaFirewall's pinned `transformers` 4.51.3 has published CVEs. Keep these two
environments separate from anything else, and score offline as below.

## Without LLMWarden access

Everything except the LLMWarden and raw PG2-22M columns reproduces without access to LLMWarden.
Skip `pip install -e .` (it pulls the private dependency) and run from the repository root:

- **Tests:** a plain venv with only pytest. Tests that need LLMWarden, or a third-party venv
  you haven't set up, skip with a stated reason.

  ```bash
  python -m venv .venv-plain && .venv-plain/Scripts/python -m pip install pytest
  .venv-plain/Scripts/python -m pytest
  ```

- **Corpora:** both rebuild as in [Rebuild the corpus from source](#rebuild-the-corpus-from-source).
  v2 needs only Python; v3 needs the build-corpus lock and downloads its public datasets without a token.
- **LLM Guard and raw DeBERTa:** set up `.venv-llmguard` as above, prepare DeBERTa and run both
  runners as in steps 1 and 2 below. Then score them, without installing this package:

  ```bash
  .venv-plain/Scripts/python -m benchmarks.scorer corpus/evasion_corpus_v3.jsonl \
      "LLM Guard=results/v3/llm_guard.jsonl" "raw DeBERTa=results/v3/raw_deberta.jsonl"
  ```

Regenerating `RESULTS.md` as published needs the LLMWarden and raw PG2-22M results, and so
needs LLMWarden installed.

## Reproduce the results

**1. Prepare the models once (online).** Scoring never touches the network. The third-party
runners set `HF_HUB_OFFLINE=1`; LLMWarden loads the weights bundled in its installed package
(`local_files_only=True`). The third-party models are downloaded beforehand at pinned revisions:

```bash
# DeBERTa @ 89b085cd (public; no token is sent). Used by both LLM Guard and raw DeBERTa.
.venv-llmguard/Scripts/python -m benchmarks.run_raw_deberta --prepare

# Llama-Prompt-Guard-2-86M @ a8ded8e6 (gated). Needs Meta's approval and HF_TOKEN in the environment.
.venv-llamafirewall/Scripts/python -m benchmarks.run_llamafirewall --prepare
```

LlamaFirewall's own loader would otherwise download from floating `main`, or prompt for a login,
the first time. `--prepare` fills the directory it loads from (`$HF_HOME/meta-llama--Llama-Prompt-Guard-2-86M`)
and prints a sha256 manifest of the files. That manifest is pinned in `benchmarks/run_llamafirewall.py`,
and the runner refuses to score if the directory doesn't match it.

**2. Score the corpus.** Each runner writes one JSON line per case to stdout (status and library
logs go to stderr):

```bash
C=corpus/evasion_corpus_v3.jsonl
mkdir -p results/v3
.venv/Scripts/python -m benchmarks.run_wrapper $C > results/v3/wrapper.jsonl
.venv/Scripts/python -m benchmarks.run_raw_promptguard2 $C > results/v3/raw_promptguard2.jsonl
.venv-llamafirewall/Scripts/python -m benchmarks.run_llamafirewall $C > results/v3/llamafirewall.jsonl
.venv-llmguard/Scripts/python -m benchmarks.run_llm_guard $C > results/v3/llm_guard.jsonl
.venv-llmguard/Scripts/python -m benchmarks.run_raw_deberta $C > results/v3/raw_deberta.jsonl
```

Check each command's exit status: a runner that fails partway leaves a truncated results file.
The scorer rejects one anyway, since results must cover the corpus exactly.
`results/` is gitignored.

**3. Regenerate `RESULTS.md`.**

```bash
.venv/Scripts/python -m benchmarks.results_doc --update RESULTS.md $C \
    "LLMWarden=results/v3/wrapper.jsonl" \
    "raw PG2-22M=results/v3/raw_promptguard2.jsonl" \
    "LlamaFirewall=results/v3/llamafirewall.jsonl" \
    "LLM Guard=results/v3/llm_guard.jsonl" \
    "raw DeBERTa=results/v3/raw_deberta.jsonl"
```

`--update` replaces everything above the `<!-- historical: v1 -->` marker and keeps the v1
section below it byte-for-byte. Don't redirect the output with `>`: that would empty the file before
the v1 section is read. For a quick look at the tables without touching `RESULTS.md`, use
`python -m benchmarks.scorer $C "NAME=results.jsonl" ...`.

## Rebuild the corpus from source

The committed corpus files are frozen for reproducibility. Never write builder output over them.
Rebuild into a scratch file and compare:

```bash
# v2 (LLMWarden's own tests/prose + garak-derived cases)
python benchmarks/extract_corpus.py > corpus/_new.jsonl
PYTHONPATH=. python benchmarks/generate_garak_cases.py >> corpus/_new.jsonl
cmp corpus/_new.jsonl corpus/evasion_corpus_v2.jsonl   # no output = identical

# v3 (= v2 + the external slice). Needs the build-corpus extra:
pip install --require-hashes -r requirements-build-corpus.lock.txt
python -m benchmarks.build_external_slice corpus/_evasion_corpus_v3.draft.jsonl
cmp corpus/_evasion_corpus_v3.draft.jsonl corpus/evasion_corpus_v3.jsonl
```

The v3 builder downloads the four external datasets at pinned revisions and applies
`corpus/v3_review_rejections.json`, the rows removed at human review. The v2 generator can no longer
reproduce v1: v2 replaced the garak-derived `classifier`-target trigger phrase, which scored 0.047
as plaintext and so couldn't be caught through any encoding, with one that scores 0.81.

## What's in the corpus (v3)

277 cases (148 malicious / 129 benign), three sources:

- **`prompt-firewall:`** (56 cases). Extracted from LLMWarden's own test suite and README/security.md
  prose: leetspeak, base64 variants, zero-width/BOM/bidi-control insertion, full-width homoglyphs,
  truncation/windowing bypass. Exact provenance (test name) per case is in `benchmarks/extract_corpus.py`.
  The prefix keeps LLMWarden's former name so the committed files stay byte-stable.
- **`garak:`** (21 cases). [NVIDIA/garak](https://github.com/NVIDIA/garak)'s encoding-probe
  *transforms* (base16/hex, base32, ascii85, raw hex, uuencode, ROT13, atbash, morse, NATO phonetic,
  Unicode tag-character smuggling), reimplemented stdlib-only in `benchmarks/garak_transforms.py` and
  round-trip tested. They are applied to LLMWarden's own malicious trigger phrases, plus one benign garak payload.
- **`external:`** (200 cases, new in v3). Sampled from four MIT-licensed Hugging Face datasets that
  LLMWarden was not tuned on, each pinned to a dataset commit:
  - in-the-wild jailbreaks and regular prompts (TrustAIRLab);
  - SPML chatbot prompt injections;
  - Lakera's Gandalf "ignore instructions" set;
  - NotInject (benign prompts containing trigger words).

  Rows are deduplicated against v2 and against the two datasets LLMWarden was tuned or scored on,
  then human-reviewed for label correctness and content. This slice exists to offset the home-field
  advantage of the first two sources.

Schema and version history: `corpus/SCHEMA.md`, `corpus/CHANGELOG.md`. Attributions: `NOTICE`.

## Scope boundary

**Only direct-input injection/jailbreak detection is compared.** LLMWarden's `scan_output()` (PII),
`scan_secrets()` and `ToolCallValidator` have no equivalent in the other systems, so evasion cases for
those surfaces are not in this corpus.

## Methodology in brief

Every system scores the identical `text` per case, in two views:
- **own shipped default:** each system's decision at the threshold it ships with. Raw models ship none.
- **LLMWarden thresholds:** strict 0.1 / balanced 0.25 / permissive 0.7 applied to every system's
  score, to separate detection ability from the choice of decision boundary.

`RESULTS.md` has the full methodology, the exact description of each system, and a Limitations
section covering what the corpus does and doesn't establish.

## Quality

```bash
ruff check .
basedpyright benchmarks/
bandit -r benchmarks/
pytest   # integration tests need the model environments and skip with a reason otherwise
```
