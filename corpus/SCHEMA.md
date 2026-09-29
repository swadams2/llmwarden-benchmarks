# Corpus schema

Each line in `evasion_corpus_v{N}.jsonl` is one JSON object:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable identifier. Never reused or repurposed once a version is published. |
| `text` | string | The literal input fed to `PromptGuard2Classifier.score()` / `LLMWarden.scan()`. |
| `label` | `"malicious"` \| `"benign"` | Ground truth, judged by content/intent -- independent of whether either scored system currently catches it. A known accepted gap in LLMWarden itself (e.g. triple-encoded base64) is still labeled by what the content *is*, not by what the current implementation returns. |
| `technique` | string | One of: `leetspeak`, `base64_standard`, `base64_urlsafe`, `base64_double`, `base64_triple`, `zero_width`, `full_width_homoglyph`, `truncation_padding`, `plaintext_control`, `base16_hex`, `base32`, `ascii85`, `raw_hex`, `uuencode`, `rot13`, `atbash`, `morse`, `nato_phonetic`, `unicode_tag_smuggling`, `high_perplexity_benign`; and, for the v3 external slice, `jailbreak_in_the_wild`, `direct_injection`, `benign_trigger_words`, `benign_natural`. |
| `target_surface` | `"fast_path"` \| `"classifier"` \| `"fast_path_or_classifier"` | Which part of LLMWarden's pipeline this case is meant to exercise. Informational only -- both scored systems get the same `text` regardless. |
| `source` | string | Provenance. `prompt-firewall:` prefix (LLMWarden's name before v0.7.0; kept as-is so the committed corpus files stay byte-stable) = extracted from LLMWarden's own tests/README/security.md, with the exact test name. `garak:` prefix = a garak-derived encoding transform applied to an LLMWarden trigger phrase, or a garak benign payload string. `external:<HF dataset id>@<40-hex revision>` prefix (v3+) = a row sampled from a third-party dataset LLMWarden was never tuned on, pinned to an exact dataset commit; its `notes` field records the upstream row (`upstream row <ref>`) and sampling stratum. This prefix drives the by-source breakdown in `RESULTS.md`. |
| `notes` | string \| `null` | Free-text context -- why a case is labeled the way it is, known accepted gaps, empirical numbers from LLMWarden's own regression tests, etc. |

## Scope boundary

Only cases targeting LLMWarden's fast-path scanner and/or escalation classifier
(the direct-input injection/jailbreak detection surface) are included. Raw Prompt Guard 2
has no equivalent to LLMWarden's `scan_output()` (PII), `scan_secrets()`, or
`ToolCallValidator` -- comparing those would not be a meaningful capability comparison, so
whitespace-despacing-against-SSN/secrets, marker-collision, and tool-argument-nesting cases
that exist in LLMWarden's own test suite are intentionally excluded here.

## Versioning

A published version's file is immutable -- corrections or additions go into a new
`evasion_corpus_v{N+1}.jsonl`, never an in-place edit of a version that's already been used
to generate published results. See `CHANGELOG.md`.

## External slice (v3+)

`evasion_corpus_v3.jsonl` = the v2 file byte-for-byte, followed by 200 rows sampled from four
MIT-licensed datasets (see `CHANGELOG.md` and `NOTICE`). Built by
`benchmarks/build_external_slice.py` from pinned dataset revisions, then passed through a human
review gate: rejected rows are listed in `corpus/v3_review_rejections.json` (upstream row
references and reasons only) and the build refills their slots deterministically. Rebuilding
from the pinned revisions and that file reproduces `evasion_corpus_v3.jsonl` byte-for-byte.
