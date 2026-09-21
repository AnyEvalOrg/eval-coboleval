"""Offline orchestration tests; production containment needs the operator run."""
import asyncio
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest
from inspect_ai.model import ModelName
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

from coboleval import coboleval
from coboleval.sandbox_runner import CLEANUP_COMMAND, QUIESCENCE_COMMAND, DIRECTORY_CLEANUP_COMMAND
from scripts import k8s_regressions as regression
from test_scoring import result, signed_receipt


def test_production_regression_uses_exact_package_sandbox():
    task = regression.k8s_regressions()
    assert task.sandbox == coboleval().sandbox
    assert task.sandbox.type == 'k8s'
    assert str(ModelName(task.model)) == 'mockllm/model'
    assert len(task.dataset) == 1
    assert len(regression.CASES['CASES']) == 5


@pytest.mark.parametrize('fault', [None, 'unsigned', 'memory_flag', 'disk_flag', 'cleanup', 'pod_lost'])
def test_production_regression_requires_receipts_flags_cleanup_and_usable_pod(monkeypatch, capsys, fault):
    class FakeSandbox:
        def __init__(self):
            self.index = 0
            self.calls = []
            self.case_names = list(regression.CASES['CASES'])
            self.key = bytes(range(32))

        async def exec(self, cmd, **kwargs):
            self.calls.append(cmd)
            assert kwargs['timeout_retry'] is False
            assert cmd[:3] == ['timeout', '-s', 'KILL']
            if regression.SETUP in cmd:
                self.name = self.case_names[self.index]
                self.index += 1
                self.work = f'/tmp/cjt-regression_{self.index}'
                assert json.loads(kwargs['input']) == regression.CASES['request_for_case'](self.name)
                return result(json.dumps({'cwd': self.work, 'key': self.key.hex()}))
            if regression.RUNNER in cmd:
                if fault == 'unsigned':
                    return result('')
                code = {'invalid_utf8': 1, 'fork_exhaustion': 1, 'memory_aggregate': -9,
                        'disk': -9, 'detached_child': 0}[self.name]
                return result(signed_receipt(self.key, self.work,
                    output={'invalid_utf8': b'\xff', 'fork_exhaustion': 'forks=63',
                            'disk': 'disk-direct-tmp'}.get(self.name, ''), returncode=code,
                    memory_exceeded=self.name == 'memory_aggregate' and fault != 'memory_flag',
                    disk_exceeded=self.name == 'disk' and fault != 'disk_flag'))
            if cmd in (CLEANUP_COMMAND, QUIESCENCE_COMMAND, DIRECTORY_CLEANUP_COMMAND):
                return result('', returncode=2 if fault == 'cleanup' else 0)
            # Liveness includes a fresh writable tmpfile after cleanup.
            assert 'tempfile.TemporaryFile' in cmd[-1]
            return result('', returncode=1 if fault == 'pod_lost' else 0)

    async def no_sleep(delay):
        pass
    monkeypatch.setattr(asyncio, 'sleep', no_sleep)
    fake = FakeSandbox()
    monkeypatch.setattr(regression, 'sandbox', lambda: SandboxEnvironmentProxy(fake))
    state = SimpleNamespace(metadata={})
    state = asyncio.run(regression.run_regressions()(state, None))
    score = asyncio.run(regression.regression_scorer()(state, Target('')))
    assert score.value == (CORRECT if fault is None else INCORRECT)
    summary = json.loads(capsys.readouterr().out)
    assert summary == state.metadata['regression_flags']
    assert all(type(flag) is bool for flags in summary.values() for flag in flags.values())
    assert ('detached_child' in summary) == (fault not in {'cleanup', 'pod_lost'})
    assert any(cmd == CLEANUP_COMMAND for cmd in fake.calls)


def test_linux_docker_regressions_have_real_aggregate_and_disk_budgets():
    script = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/linux_regressions.py'))
    command = script['docker_command']('synthetic-image')
    assert '--memory=2g' in command and '--memory-swap=2g' in command
    assert '--read-only' in command
    assert 'type=volume,target=/tmp' in command and '/dev/shm:size=16m' in command
    assert script['CASES']['CASES'] == regression.CASES['CASES']


@pytest.mark.parametrize('code,memory,output,expected', [
    (1, False, 'forks=63\n', True), (-9, True, '', True),
    (1, False, '', False), (1, False, 'forks=0', False),
    (1, False, 'forks=65', False), (2, False, 'forks=63', False),
    (0, True, '', False),
])
def test_fork_accepts_limit_witness_or_memory_failure(code, memory, output, expected):
    receipt = dict(stage='run', returncode=code, memory_exceeded=memory,
                   output=output, timeout=False, overflow=False)
    assert regression.CASES['expected_receipt']('fork_exhaustion', receipt,
                                               regression.receipt_failure) is expected


@pytest.mark.parametrize('code,disk,output,expected', [
    (-9, True, 'disk-direct-tmp\n', True), (28, False, 'disk-direct-tmp', False),
    (0, True, 'disk-direct-tmp', False), (-9, True, '', False),
])
def test_disk_requires_signed_limit_and_direct_tmp_witness(code, disk, output, expected):
    receipt = dict(stage='run', returncode=code, disk_exceeded=disk,
                   output=output, timeout=False, overflow=False)
    assert regression.CASES['expected_receipt']('disk', receipt,
                                               regression.receipt_failure) is expected
