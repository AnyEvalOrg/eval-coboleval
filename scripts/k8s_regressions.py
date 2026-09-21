"""Operator-only production-runtime regressions; absent from the package registry.

KUBECONFIG=/path/to/config inspect eval scripts/k8s_regressions.py --model mockllm/model
"""
import asyncio
import json
from pathlib import Path
import re
import runpy

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, accuracy, scorer
from inspect_ai.solver import solver
from inspect_ai.util import sandbox

from coboleval import coboleval
from coboleval.publication import private_grading
from coboleval.receipts import receipt_failure, verify_receipt
from coboleval.sandbox_runner import RUNNER, SETUP
from coboleval.scoring import cleanup_candidate

CASES = runpy.run_path(str(Path(__file__).with_name('regression_cases.py')))
PYTHON = CASES['PYTHON']


async def bounded_exec(env, source, *args, timeout=5, input=None):
    async with asyncio.timeout(timeout + 5):
        return await env.exec(
            ['timeout', '-s', 'KILL', f'{timeout}s', PYTHON, '-I', '-c', source, *args],
            cwd='/', input=input, timeout=timeout, timeout_retry=False,
        )


@solver
def run_regressions():
    async def solve(state, generate):
        summary = {}
        with private_grading(sandbox()) as env:
            for name in CASES['CASES']:
                flags = {flag: False for flag in CASES['FLAGS']}
                flags.update(signed=False, expected=False, cleanup_succeeded=False, pod_usable=False)
                cleanup_after = 0
                try:
                    setup = await bounded_exec(env, SETUP, input=json.dumps(CASES['request_for_case'](name)))
                    if setup.returncode != 0:
                        raise RuntimeError("Sandbox setup failed")
                    launch = json.loads(setup.stdout)
                    work, key = launch['cwd'], bytes.fromhex(launch['key'])
                    if len(key) != 32 or not re.fullmatch(r'/tmp/cjt-[a-zA-Z0-9_-]+', work):
                        raise ValueError('Invalid setup')
                    cleanup_after = asyncio.get_running_loop().time() + 40
                    # The outer deadline includes signing; empty-file traversal
                    # must never extend it. All cases use this bound.
                    result = await bounded_exec(env, RUNNER, work, timeout=35)
                    receipt = verify_receipt(result.stdout, key)
                    if receipt is not None and receipt['cwd'] == work:
                        cleanup_after = 0
                        flags['signed'] = True
                        flags.update({flag: receipt.get(flag, False) for flag in CASES['FLAGS']})
                        flags['expected'] = CASES['expected_receipt'](name, receipt, receipt_failure)
                except Exception:
                    # Only flags leave this frame; no captured bytes, keys or errors.
                    pass
                finally:
                    try:
                        await cleanup_candidate(env, cleanup_after)
                        flags['cleanup_succeeded'] = True
                    except Exception:
                        pass
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
        return state
    return solve


@scorer(metrics=[accuracy()])
def regression_scorer():
    async def score(state, target):
        summary = state.metadata.get('regression_flags', {})
        passed = set(summary) == set(CASES['CASES']) and all(
            all(flags.get(flag, False) for flag in ('signed', 'expected', 'cleanup_succeeded', 'pod_usable'))
            for flags in summary.values()
        )
        print(json.dumps(summary, sort_keys=True), flush=True)
        return Score(value=CORRECT if passed else INCORRECT,
                     explanation='All runtime regressions passed.' if passed else 'Runtime regression failed.')
    return score


@task
def k8s_regressions():
    # Reuse the exact production chart, values and provider configuration.
    return Task(dataset=[Sample(id='runtime-regressions', input='Synthetic containment regressions')],
                solver=run_regressions(), scorer=regression_scorer(),
                sandbox=coboleval().sandbox, model='mockllm/model', epochs=1)
