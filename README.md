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

A sample is CORRECT only if every caller compiles, runs and compares successfully. Compilation failure, runtime error, wrong result, timeout, aggregate memory or disk exhaustion, output overflow, undecodable output, or supervisor-reported cleanup/execution failure in an authenticated receipt is INCORRECT. Raw candidate output is base64-encoded before signing; the host authenticates and validates supervisor fields before decoding it. Invalid UTF-8 or malformed output fields cannot turn an authenticated candidate failure into a missing receipt. A missing or unverifiable receipt (including a lost, timed-out or output-limited sandbox exec) is a harness failure: Inspect records a sample error, and AnyEval refuses to publish the run, so it never enters the published pass rate. Scoring stops at the first failure, as in the reviewed template. Explanations report `Compiled: yes/no` for the failing caller (all earlier callers passed), `yes` for all callers on success, or `not attempted` for missing code. Later callers are not claimed to have compiled. A compiler that exits zero but exceeds the output limit records compilation success while still failing the sample. These diagnostics are not a standalone reproduction of paper CSR.

The root Linux supervisor drops compiler and candidate processes to reserved UID/GID 65532, protects its memory and file descriptors, and authenticates completion receipts with HMAC. The supervisor kills process groups and sweeps `/proc` directly without spawning cleanup processes, and catches post-run exceptions before signing failure flags. The supervisor builds, writes and flushes the complete receipt, then calls `os._exit(0)` immediately; it never deletes the work directory. Independent bounded execs sweep the UID, verify quiescence, and delete `/tmp/cjt-*` with a 5-second kill deadline, including error and cancellation paths. The scorer resolves the signed verdict first. If independent cleanup fails, an authenticated failure remains INCORRECT with its original reason; an otherwise passing candidate becomes INCORRECT with “candidate left processes that could not be cleaned up,” and no later caller starts. Cleanup failure with no authenticated receipt remains a sanitized harness error. Each pod belongs to one sample and is discarded afterwards, with no reuse across samples. Compilation and generated programs run only in the external sandbox.

## Sandbox and publication

The default image is `us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0`. The shared Dockerfile uses `python:3.12-slim-trixie`, GnuCOBOL and OpenJDK 21; Java is retained for compatibility with the shared image but is unused by this task. Docker builds the same definition as `eval-cobol-sandbox:local`.

The Kubernetes chart uses gVisor, spot-node selection, a disabled service-account token, restricted capabilities, 1 CPU, 2 GiB memory and 1 GiB ephemeral storage. Its release-specific NetworkPolicy denies ingress and all egress, including DNS. Equal CPU/memory requests and limits provide Guaranteed QoS. Both `cobc` and generated COBOL executables receive hard `RLIMIT_AS` and `RLIMIT_DATA` ceilings of 1 GiB (or a tighter inherited ceiling). While each candidate step runs, a supervisor thread checks `/proc/<pid>/status` every 50 ms and sums `VmRSS` for all UID 65532 processes, including escaped sessions. Above 768 MiB it kills the candidate group and UID processes and signs `memory_exceeded=true`, which scores INCORRECT as “memory limit exceeded.” The supervisor still sets inherited `oom_score_adj=1000`, but gVisor records this without using it for host sandbox OOM selection; aggregate monitoring supplies the memory protection. gVisor reports full per-process RSS for shared copy-on-write pages, so a 64-child fork attack may hit the memory watchdog before the process limit; legitimate compiler/JVM chains with a handful of processes remain far below 768 MiB. Candidate `RLIMIT_NPROC=64` leaves slots below Docker’s 128-process ceiling. Core dumps are disabled and `RLIMIT_FSIZE` enforces the per-file output limit.

Both chart paths share `values.yaml` and, like Compose and the Docker regression commands, drop all capabilities and add only `SETUID`, `SETGID`, `KILL`, `CHOWN`, `DAC_OVERRIDE`, and `SYS_PTRACE`. The root supervisor needs `SYS_PTRACE` to follow `/proc/<pid>/fd` magic links across UIDs (the kernel's `PTRACE_MODE_READ` check); without it, descriptor accounting cannot work. Children set `PR_SET_NO_NEW_PRIVS`, set `PR_SET_KEEPCAPS=0`, clear supplementary groups and drop all real/effective/saved IDs to 65532. This clears effective/permitted capabilities before candidate code executes and prevents privilege gains on exec.

Before returning a key or launching any candidate, SETUP executes a trusted, short-lived script as UID 65532 using the same `restrict_child` function. The probe writes a file in the actual work directory under `/tmp` and executes from that mount, checking both write access and executable mounts. The supervisor verifies it can stat the probe's `/proc/<pid>/fd/0`, read its status with UID 65532 and `VmRSS`, enumerate `/proc`, and write `/proc/self/oom_score_adj`. Any failure exits SETUP nonzero with the fixed message `sandbox prerequisites unavailable`; the scorer raises the withheld harness error, so infrastructure failures never enter the published pass rate as INCORRECT. Unit tests stub these prerequisites; deployment regressions exercise them in the actual runtime.

The sandbox root filesystem and `/dev/shm` are read-only in both chart paths and Docker Compose. Writable memory-backed filesystem space is zero. The `/dev/shm` mount is an empty memory-backed volume mounted read-only; Java receives `JAVA_TOOL_OPTIONS=-XX:-UsePerfData` in the shared image and supervisor environment. Writable `/tmp` (compiler scratch files, work directories and captures) is disk-backed: Kubernetes uses an `emptyDir` with a 512 MiB eviction backstop within the pod's 1 GiB ephemeral-storage budget; Compose uses an anonymous disk volume. Compose cannot impose a portable size limit on that disk volume (a `tmpfs` size would make it memory-backed), so the watchdog supplies the actual byte and entry bounds.

The disk watchdog scans `/tmp`, `/var/tmp` and `/dev/shm`, then every `/proc/<pid>/fd` for UID 65532, every 100 ms between scans. It sums allocated `st_blocks * 512` for regular files, de-duplicated by `(st_dev, st_ino)` across directory entries and descriptors. Directory traversal does not follow symlinks; descriptor stats deliberately follow proc magic links, accounting for unlinked-but-open files and unmapped memfds. Candidate hard `RLIMIT_NOFILE` is 256 for native steps and 1024 for `java`/`javac`, across at most 64 candidate processes (16,384 native or 65,536 Java descriptor slots). More than 256 MiB of directory-visible plus descriptor-retained bytes, or more than 10,000 directory entries, triggers immediate group/UID kills and signed `disk_exceeded=true` (INCORRECT, “disk limit exceeded”). Individual process, descriptor or directory-entry `PermissionError`, `FileNotFoundError` and `ProcessLookupError` failures are skipped while scanning continues; inability to enumerate `/proc` remains a fatal monitor failure. Residual post-launch supervisor failures remain authenticated INCORRECT outcomes. Every entry checks cancellation and the running budget; over-budget scans stop early. After the candidate exits, the runner signals stop and joins each daemon watchdog for at most 0.2 seconds, then proceeds to signing even if a scan is stalled. A still-running monitor marks a supervisor failure and prevents another step; `os._exit` terminates daemon threads after flushing the receipt.

The 2 GiB memory budget allows 768 MiB aggregate candidate RSS plus one 50 ms allocation burst, up to 256 MiB of descriptor-retained memfds plus a disk scan/100 ms write burst, and supervisor overhead. Writable memory-backed filesystem space contributes zero; memfds remain possible and share the disk watchdog's 256 MiB budget with disk-backed files. Disk storage similarly budgets 256 MiB plus a scan/write burst. These are sampled limits, with filesystem sizeLimit and pod storage limits providing eviction backstops. The regressions verify signed failures, independent cleanup and continued sandbox usability. No external access is needed by the task after image provisioning.

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

Most tests need neither a container engine nor model access. Supervisor tests execute authored Python fixtures with host credential changes and UID sweeps stubbed; they do not demonstrate Linux containment. The two real containment regressions require a disposable root Linux environment with unused UID 65532 and explicit `CJT_LINUX_CONTAINMENT=1`. Never set that flag on a shared host. The operator-run `scripts/linux_regressions.py` uses only the standard library and invokes the actual `SETUP` and `RUNNER` sources with HMAC verification and the scorer's shared INCORRECT gate. It checks a real GnuCOBOL compile/run, then invalid UTF-8, detached children that exhaust `fork`, and, with Docker, three children each attempting 600 MiB allocations, unbounded 1 MiB files until the disk watchdog kills the writer, a successful parent leaving a sleeping `setsid` child, 300 unlinked one-MiB files retained across four workers, 300 MiB of retained memfds, 50,000 empty files, a denied `/dev/shm` write, and denied stats of `/proc/1/fd/0` and the supervisor’s fd 0. The ptrace case requires an authenticated nonzero exit and a witness that both accesses raised `PermissionError`, proving the candidate did not retain ptrace access. It prints stage, returncode and flags; failures also identify the step, exception class and an allowlisted assertion label, without exception text or candidate output. Nested runs print each case’s flags before the summary, and the outer run validates and relays those records even when the child fails. Run it as root only in a disposable reference image with unused UID 65532:

```bash
gcloud builds submit --config=scripts/cloudbuild-linux-regressions.yaml \
  --substitutions=_IMAGE=us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0 .
```

Prefer an immutable image digest for release validation. The Cloud Build service account needs pull access. The build copies the Docker CLI into `/workspace/.linux-regressions-bin/docker`, passes that path via `--docker-cli`, and runs the script in the reference image with the Docker socket, then the aggregate-memory, disk, detached-child and four storage attack cases in a separate container of that same image with `--memory=2g --memory-swap=2g --pids-limit=128 --read-only --mount type=volume,target=/tmp --tmpfs /dev/shm:ro,size=16m`. The repository is mounted at the same absolute `/workspace` path so the nested daemon can access it. If Docker is absent, `python3 scripts/linux_regressions.py` instead runs the memory supervisor under a 384 MiB hard `prlimit` address-space/data budget. This fallback checks inherited limits and receipt survival; it skips the Docker-only aggregate-memory, disk, detached-child and storage attack cases. Docker does not establish gVisor behavior; an available but broken Docker setup fails rather than falling back. These Linux checks are separate from the default macOS pytest suite. A model baseline must still be run in the provisioned sandbox.

For production-runtime validation, use the operator’s configured Kubernetes credentials:

```bash
KUBECONFIG=/path/to/operator/kubeconfig inspect eval scripts/k8s_regressions.py --model mockllm/model
```

This standalone Inspect task is not registered by the package. It uses the package task’s exact k8s chart/values and runs the real `SETUP` and `RUNNER` against all ten synthetic cases: invalid UTF-8, fork exhaustion, three 600 MiB children, unbounded files first in the work directory and then directly under `/tmp`, a parent exiting zero with a sleeping detached child, 300 retained unlinked one-MiB files across four workers under `/tmp`, 300 MiB of memfds, 50,000 empty files, a denied `/dev/shm` write, and denied access to PID 1 and supervisor descriptors. The ptrace check requires a signed exit 1 with a `PermissionError` witness for both paths. The three new storage exhaustion cases require signed `disk_exceeded` receipts; the read-only write requires exit 1 with no flags. Empty-file receipts must arrive within the outer exec deadline, as must all other receipts. The fork case accepts either exit 1 with a fork-count witness or a signed memory-limit failure. The disk writer caps its work-directory files below the budget, then fills a second directory directly under `/tmp`, proving the watchdog covers the whole mount; cleanup verifies both directories are removed. Its scorer returns CORRECT only when every case has an authenticated receipt with the expected flags, independent cleanup succeeds, and the pod remains usable. It prints a JSON summary of flags only, without candidate output or receipt keys. Run it on the target gVisor cluster to validate that runtime’s RSS reporting and disk watchdog behavior; the default host unit suite cannot prove those properties.

`anyeval.json` declares `sandbox-k8s`, 146 samples and the external image. Publishing this repository alone does not deploy it into AnyEval: the application still needs the version/commit pin, catalog entry for `coboleval/coboleval` with deterministic grading, built problem-index shard, pinned image digest, application tests and worker/application deployment. This package does not modify that application or publish an image.
