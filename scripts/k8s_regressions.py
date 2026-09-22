"""Operator-only production-runtime regressions; absent from the package registry.

KUBECONFIG=/path/to/config inspect eval scripts/k8s_regressions.py --model mockllm/model --max-samples 1
"""
import asyncio
import json
from pathlib import Path
import re
import runpy
import time

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, accuracy, scorer
from inspect_ai.solver import solver
from inspect_ai.util import sandbox

from coboleval import coboleval
from coboleval.publication import private_grading
from coboleval.receipts import receipt_failure, verify_receipt
from coboleval.sandbox_runner import RUNNER, SETUP
from coboleval.scoring import cleanup_candidate, kernel_failure_score
from coboleval.sandbox_state import MEMORY_EXHAUSTED, sandbox_failure, sandbox_identity

CASES = runpy.run_path(str(Path(__file__).with_name('regression_cases.py')))
PYTHON = CASES['PYTHON']
KERNEL_CASES = CASES['KERNEL_CASES']
REGULAR_CASES = tuple(name for name in CASES['CASES'] if name not in KERNEL_CASES)
SAMPLE_IDS = ('runtime-regressions',) + KERNEL_CASES


def sample_cases(state):
    name = str(state.sample_id)
    if name == 'runtime-regressions':
        return REGULAR_CASES
    if name in KERNEL_CASES:
        return (name,)
    raise ValueError('Unknown regression sample')


async def bounded_exec(env, source, *args, timeout=5, input=None):
    async with asyncio.timeout(timeout + 5):
        return await env.exec(
            ['timeout', '-s', 'KILL', f'{timeout}s', PYTHON, '-I', '-c', source, *args],
            cwd='/', input=input, timeout=timeout, timeout_retry=False,
        )


async def run_cases(state):
    summary = {}
    evidence = {}
    with private_grading(sandbox()) as env:
        for name in sample_cases(state):
            flags = {flag: False for flag in CASES['FLAGS']}
            flags.update(signed=False, expected=False, cleanup_succeeded=False, pod_usable=False,
                         oom_killed=False, candidate_incorrect=False, sysv_refused=False)
            cleanup_after = 0
            setup_succeeded = False
            identity = None
            runner_failed_at = None
            try:
                setup = await bounded_exec(env, SETUP, input=json.dumps(CASES['request_for_case'](name)))
                if setup.returncode != 0:
                    raise RuntimeError("Sandbox setup failed")
                launch = json.loads(setup.stdout)
                work, key = launch['cwd'], bytes.fromhex(launch['key'])
                if len(key) != 32 or not re.fullmatch(r'/tmp/cjt-[a-zA-Z0-9_-]+', work):
                    raise ValueError('Invalid setup')
                setup_succeeded = True
                identity = sandbox_identity(env)
                cleanup_after = asyncio.get_running_loop().time() + 40
                # The outer deadline includes signing; empty-file traversal
                # must never extend it. All cases use this bound.
                try:
                    result = await bounded_exec(env, RUNNER, work, timeout=35)
                finally:
                    # Also covers an exec response with no authentic receipt.
                    runner_failed_at = time.monotonic()
                receipt = verify_receipt(result.stdout, key)
                if receipt is not None and receipt['cwd'] == work:
                    cleanup_after = 0
                    flags['signed'] = True
                    flags['sysv_refused'] = CASES['sysv_refused'](name, receipt)
                    flags.update({flag: receipt.get(flag, False) for flag in CASES['FLAGS']})
                    flags['expected'] = CASES['expected_receipt'](name, receipt, receipt_failure)
            except Exception:
                # No captured bytes, keys or exception text leave this frame.
                pass
            finally:
                try:
                    await cleanup_candidate(env, cleanup_after)
                    flags['cleanup_succeeded'] = True
                except Exception:
                    pass
            if setup_succeeded and not flags['signed']:
                evidence[name] = {}
                failure = await sandbox_failure(env, identity=identity, evidence=evidence[name],
                                                runner_failed_at=runner_failed_at)
            if name in KERNEL_CASES and setup_succeeded and not flags['signed']:
                # Retain the historical flag name for attributed memory loss,
                # including same-UID, non-evicted container exit 137/signal 9.
                flags['oom_killed'] = failure == MEMORY_EXHAUSTED
                verdict = kernel_failure_score(failure)
                flags['candidate_incorrect'] = verdict is not None and verdict.value == INCORRECT
                flags['expected'] = flags['oom_killed'] and flags['candidate_incorrect']
            try:
                probe = await bounded_exec(env, "import glob, tempfile; assert not glob.glob('/tmp/cjt-*'); f = tempfile.TemporaryFile(dir='/tmp'); f.write(b'ok'); f.close()")
                flags['pod_usable'] = probe.returncode == 0
            except Exception:
                pass
            summary[name] = flags
            if not flags['cleanup_succeeded'] or not flags['pod_usable']:
                # Do not start another case in a contaminated or lost pod.
                break
    state.metadata['regression_flags'] = summary
    state.metadata['regression_evidence'] = evidence
    return state


@solver
def run_regressions():
    # Inspect can schedule samples concurrently. Gate their execution in dataset
    # order so potentially fatal cases always run LAST, each in its own pod.
    completed = [asyncio.Event() for _ in SAMPLE_IDS]

    async def solve(state, generate):
        index = SAMPLE_IDS.index(str(state.sample_id))
        if index:
            await completed[index - 1].wait()
        try:
            return await run_cases(state)
        finally:
            completed[index].set()
    return solve


@scorer(metrics=[accuracy()])
def regression_scorer():
    async def score(state, target):
        summary = state.metadata.get('regression_flags', {})
        expected_cases = sample_cases(state)
        passed = set(summary) == set(expected_cases) and all(
            flags.get('expected', False) and (
                (name in KERNEL_CASES and flags.get('signed', False))
                or (flags.get('oom_killed', False) and flags.get('candidate_incorrect', False)
                 and name in KERNEL_CASES and not flags.get('signed', False))
                or all(flags.get(flag, False) for flag in
                       ('signed', 'cleanup_succeeded', 'pod_usable')))
            for name, flags in summary.items()
        )
        print(json.dumps(summary, sort_keys=True), flush=True)
        return Score(value=CORRECT if passed else INCORRECT,
                     explanation='All runtime regressions passed.' if passed else 'Runtime regression failed.')
    return score


@task
def k8s_regressions():
    # Reuse the exact production chart, values and provider configuration.
    return Task(dataset=[Sample(id=name, input='Synthetic containment regressions')
                         for name in SAMPLE_IDS],
                solver=run_regressions(), scorer=regression_scorer(),
                sandbox=coboleval().sandbox, model='mockllm/model', epochs=1, fail_on_error=True)
