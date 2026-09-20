# COBOLEval for AnyEval

`eval-coboleval==1.0.0` packages all **146 COBOLEval tasks and 821 COBOL test callers** as the Inspect task **`coboleval/coboleval`**. It measures all-tests pass@1 with one generation and one epoch. Compilation evidence appears only in each score explanation; there is no model judge or separate CSR score.

The dataset and original chat/evaluation protocol come from [zorse-project/COBOLEval](https://github.com/zorse-project/COBOLEval), pinned to [`0bb96c3114bb2bb28e221e9d6000614781f8609d`](https://github.com/zorse-project/COBOLEval/tree/0bb96c3114bb2bb28e221e9d6000614781f8609d). Original IDs such as `HumanEval/0` are retained exactly, including gaps. No dataset download, transpilation, or reference-program execution occurs at evaluation time. `canonical_solution` is Python, informational only, and never used to generate or grade candidates.

## Install and run

Requires Python 3.11+, Inspect 0.3.260, and an external sandbox. Kubernetes additionally requires inspect-k8s-sandbox 0.13.0. Install the package and relevant extras:

```bash
python -m pip install '.[anyeval,test]'
inspect eval coboleval/coboleval --model provider/model --temperature 0 --max-tokens 32768
inspect eval coboleval/coboleval -T sandbox_type=docker --model provider/model --temperature 0 --max-tokens 32768
```

Kubernetes is the default; `sandbox_type` accepts only `k8s` or `docker`. The task uses the packaged AnyEval chart and defaults `INSPECT_K8S_DEFAULT_NAMESPACE` to `anyeval-sandbox`. `anyeval_chart=False` explicitly selects the provider's built-in chart instead. That exception may introduce the provider's CoreDNS image; the default chart contains only one Pod and one NetworkPolicy.

For one literal sample and a local publication bundle:

```bash
python run.py --sample-id HumanEval/0 --model provider/model --sandbox-type docker --bundle .build/bundle.json
```

The runner rejects wildcard and unknown IDs. It records only the selected sample's status, verdict, and sanitized explanation; absent serving receipts and live provenance remain null. `--token-limit` is an Inspect total sample budget, default 32768. Generation temperature and output limits otherwise come from the caller; upstream's default temperature is 0.0. No tools, feedback, repair loop, or extra attempts are given to the model.

## Prompt and program assembly

The prompt is the exact `OPENAI_SYSTEM_PROMPT.format(record['prompt'])` from upstream `scripts/generate.py`, including the unlabeled fence and instruction to terminate with `GOBACK`. Upstream `OpenAIChat.solve` sends **one system message and no user message**. This package sends the same text byte-for-byte as **one user message with no system message** because OpenAI-compatible endpoints reject system-only conversations (HTTP 400: "messages must contain at least one user message"). Only the role changes. The record's prompt includes its program header, linkage declarations, public docstring/examples, completion instruction and working-storage header. Caller code, expected results and the Python canonical solution never enter model input, targets, or sample metadata.

The first Markdown fenced block is selected, irrespective of language label. Later blocks are ignored. Standard CommonMark tilde, nested and EOF-terminated fences are accepted; unfenced responses score INCORRECT without starting the sandbox. An empty fenced block is still assembled and submitted to the compiler, matching upstream construction.

Assembly mirrors `OpenAIChat.construct` and `swap_sections`:

1. If the stripped completion starts with the exact uppercase `WORKING-STORAGE SECTION.`, remove every exact occurrence of that header from the completion, as upstream does.
2. Append a newline and the completion to the original record prompt, unconditionally.
3. Collect lines into beginning, working-storage, linkage and procedure sections, recognizing headers case-insensitively. Emit them in that order. Replace each procedure header with `       PROCEDURE DIVISION USING LINKED-ITEMS.`.

**Whole-program responses are also appended to the prompt.** Duplicate identification, linkage or working-storage sections may therefore remain and fail compilation. They are not automatically repaired or substituted for the prompt. No `END PROGRAM` is synthesized and the translation template's extra indentation cleaner is not applied: both would change the upstream chat path.

## Execution and scoring

Each caller runs in its own fresh sandbox working directory. The reviewed Java-to-COBOL template's supervisor is reused. The host sends source files and shell-free argv, not expected answers:

```text
cobc -w -fformat=variable -x call.cbl solution.cbl
./call
```

Compilation has a 60-second timeout and execution a separate 30-second timeout. The program must produce `<ENTRY-POINT-UPPER-DASHES>.TXT`, e.g. `has_close_elements` maps to `HAS-CLOSE-ELEMENTS.TXT`. Captured stdout is not the answer channel. Only a regular, single-link, candidate-owned output file is read; symlinks, FIFOs and missing files fail. Captured streams and the result file have a 1 MiB limit.

The host parses the TXT lines using upstream `parse` and `is_equal` rules. Expected values use `ast.literal_eval` in place of `eval`; every packaged value is a valid literal. Tuples become lists. Booleans are true only for stripped `1`; `p` and `y` prefixes represent negative numbers; strings are stripped. Lists are parsed fully then truncated to the expected length. Float comparison retains `math.isclose(..., abs_tol=0.001)` with its default relative tolerance. Float-list comparison intentionally retains upstream's `zip` behavior, including its missing-length-check quirk. Empty output always fails.

A sample is CORRECT only if every caller compiles, runs and compares successfully. Compilation failure, runtime error, wrong result, timeout, output overflow or missing authenticated receipt is INCORRECT. Scoring stops at the first failure, as in the reviewed template. Explanations report `Compiled: yes/no` for the failing caller (all earlier callers passed), `yes` for all callers on success, `unknown` if no authenticated report was received, or `not attempted` for missing code. Later callers are not claimed to have compiled. A compiler that exits zero but exceeds the output limit records compilation success while still failing the sample. These diagnostics are not a standalone reproduction of paper CSR.

The root Linux supervisor drops compiler and candidate processes to reserved UID/GID 65532, protects its memory and file descriptors, and authenticates completion receipts with HMAC. An independent bounded UID sweep and quiescence check runs before reusing the sandbox, including error and cancellation paths. Cleanup failures abort scoring as sanitized infrastructure errors. Compilation and generated programs run only in the external sandbox.

## Sandbox and publication

The default image is `us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0`. The shared Dockerfile uses `python:3.12-slim-trixie`, GnuCOBOL and OpenJDK 21; Java is retained for compatibility with the shared image but is unused by this task. Docker builds the same definition as `eval-cobol-sandbox:local`.

The Kubernetes chart uses gVisor, spot-node selection, a disabled service-account token, restricted capabilities, 1 CPU, 2 GiB memory and 1 GiB ephemeral storage. Its release-specific NetworkPolicy denies ingress and all egress, including DNS. Docker uses no networking and limits memory, CPU and process count. No external access is needed by the task after image provisioning.

Grading data stays in the scorer closure and package data. `private_grading` suppresses private sandbox transcript events and provider diagnostics using APIs pinned to the declared Inspect/provider versions, without suppressing public provenance from other contexts. Exceptions are sanitized before publication. `redaction.yaml` documents the additional export policy; runtime privacy does not depend on a publisher applying that file. `tests/test_publication.py` exercises Inspect's event proxy and, where available, the actual AnyEval publication redactor.

## Dataset integrity and differences

`CobolEval.jsonl` is retained as the source snapshot. `scripts/build_dataset.py` deterministically writes `coboleval/data/problems.jsonl.gz` and its manifest with the source/artifact/ID SHA-256 hashes, original ordered IDs, commit, record count and caller count. The installed wheel loads these resources offline and rejects an artifact hash or ID mismatch.

Differences from the upstream harness are explicit:

- The upstream prompt text is unchanged, but its role is changed from system to user for compatibility with endpoints that reject system-only conversations.
- Standard CommonMark fence parsing uses `markdown-it-py` instead of Marko; the first-fence selection policy is retained. Parser-specific edge behavior is not asserted byte-identical for every possible Markdown document.
- Missing fenced code becomes INCORRECT instead of an extraction exception causing a skipped generation. There are no upstream API retries or joblib generation cache.
- Upstream leaves the execution call commented out. Here it runs in a sandbox with shell-free argv, independent 60/30-second deadlines, output bounds and authenticated receipts; upstream's general shell helper uses a 5-second timeout.
- Evaluation stops on the first failure; upstream iterates every caller. Pass/fail requires all callers in both cases. Compilation diagnostics are scoped to attempted callers.
- `literal_eval`, closure-only grading records and transcript suppression replace unsafe literal evaluation and plaintext result logging.
- The shared Debian image determines its installed GnuCOBOL version; upstream documents GnuCOBOL 3.2.0. Generation settings are supplied by the caller. Record the image digest and model settings when comparing runs.

The package is MIT (`LICENSE`); the upstream MIT license is unchanged in `UPSTREAM-LICENSE`. Reused reviewed-template portions retain their Apache-2.0 license and notice in `TEMPLATE-LICENSE` and `TEMPLATE-NOTICE.md`; see `NOTICE.md`.

## Reported baselines

These are source-reported results, **not results produced by this package**. The [pinned upstream README](https://github.com/zorse-project/COBOLEval/blob/0bb96c3114bb2bb28e221e9d6000614781f8609d/README.md) reports GPT-4 pass@1 `0.10273972602739725`, approximately **10.3%**.

The local [COBOL-Coder README](https://github.com/COBOL-Coder/COBOL-Coder#cobol-code-generation), accompanying [Dau et al., 2026](https://arxiv.org/abs/2604.03986), reports zero-shot, temperature-0 results averaged over three runs:

| Model | COBOLEval CSR (%) | COBOLEval Pass@1 (%) |
|---|---:|---:|
| COBOL-Coder-7B | 73.80 | 44.70 |
| COBOL-Coder-14B | 73.95 | 49.33 |
| GPT-4 | 24.12 | 15.75 |
| GPT-4o | 41.80 | 16.40 |

The two sources report different GPT-4 pass rates. Preserve their separate attribution; model versions, generation paths and compiler environments can differ. CSR is a separate reported quantity and is not interchangeable with all-tests pass@1.

## Build, test and publication

Use the requested environment locally:

```bash
PY=/Users/jperla/josh/repos/anyeval-app/.venv/bin/python
"$PY" scripts/build_dataset.py
"$PY" -m pytest -q
"$PY" -m pip wheel --no-deps --no-build-isolation --no-index -w .build/dist .
"$PY" -m pip install --no-deps --no-index --target .build/wheel-env/site-packages .build/dist/eval_coboleval-1.0.0-py3-none-any.whl
"$PY" scripts/verify_wheel.py .build/wheel-env/site-packages
```

Tests need Helm 3 or 4 on PATH. Install an official [Helm release](https://github.com/helm/helm/releases/tag/v3.19.0), verifying the archive against its release checksum. Helm is required, not silently skipped: tests run strict lint, render the actual chart, validate the resource/security contract and reject deliberately malformed template copies. The wheel test builds and installs into a temporary `site-packages`, then verifies cold task discovery and resources from an empty working directory with network blocked.

Most tests need neither a container engine nor model access. Supervisor tests execute authored Python fixtures with host credential changes and UID sweeps stubbed; they do not demonstrate Linux containment. The two real containment regressions require a disposable root Linux environment with unused UID 65532 and explicit `CJT_LINUX_CONTAINMENT=1`. Never set that flag on a shared host. A real compiler/container smoke test and model baseline must be run separately in the provisioned sandbox.

`anyeval.json` declares `sandbox-k8s`, 146 samples and the external image. Publishing this repository alone does not deploy it into AnyEval: the application still needs the version/commit pin, catalog entry for `coboleval/coboleval` with deterministic grading, built problem-index shard, pinned image digest, application tests and worker/application deployment. This package does not modify that application or publish an image.
