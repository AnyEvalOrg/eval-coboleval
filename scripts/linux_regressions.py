#!/usr/bin/env python3
"""Root-only, stdlib-only regressions in the disposable reference Linux image.

Load sources without importing coboleval's Inspect entry point: the reference
image intentionally has no host-side scoring dependencies. receipt_failure is
exactly the INCORRECT gate used by scoring.py, before answer comparison.
"""
import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = runpy.run_path(str(ROOT / 'coboleval/sandbox_runner.py'))
RECEIPTS = runpy.run_path(str(ROOT / 'coboleval/receipts.py'))
FLAGS = ('timeout', 'overflow', 'cleanup_failed', 'supervisor_error', 'output_error')
PYTHON = '/usr/local/bin/python3'

INVALID_UTF8 = "import os; os.write(1, b'\\xff'); raise SystemExit(1)"
FORK_EXHAUSTION = '''import errno, os, time
while True:
    try:
        pid = os.fork()
    except OSError as error:
        if error.errno != errno.EAGAIN:
            raise SystemExit(2)
        raise SystemExit(1)
    if pid == 0:
        os.setsid()
        while True:
            time.sleep(60)
'''
MEMORY_EXHAUSTION = '''blocks = []
while True:
    blocks.append(bytearray(8 * 1024 * 1024))
'''
CHECK_LIMITS = '''import os, resource
assert os.getresuid() == (65532,) * 3
assert resource.getrlimit(resource.RLIMIT_NPROC) == (64, 64)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (4096, 4096)
for kind in (resource.RLIMIT_AS, resource.RLIMIT_DATA):
    soft, hard = resource.getrlimit(kind)
    assert 0 < soft == hard <= 1024**3
assert open('/proc/self/oom_score_adj').read().strip() == '1000'
'''


def captured(command, *, data=None, timeout=40):
    # Never forward candidate output or exception text to operator logs.
    return subprocess.run(command, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)


def no_candidates():
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            status = dict(line.split(':', 1) for line in (directory / 'status').read_text().splitlines())
            if status['Uid'].split()[0] == '65532' and status['State'].split()[0] not in {'Z', 'X'}:
                return False
        except (FileNotFoundError, ProcessLookupError):
            pass
    return True


def invoke(request, *, budget=False):
    assert no_candidates(), 'reserved UID must be unused'
    setup_result = captured(['timeout', '-s', 'KILL', '5s', PYTHON, '-I', '-c', SUPERVISOR['SETUP']],
                            data=json.dumps(request).encode(), timeout=6)
    assert setup_result.returncode == 0
    setup = json.loads(setup_result.stdout)
    try:
        command = ['timeout', '-s', 'KILL', '30s', PYTHON, '-I', '-c', SUPERVISOR['RUNNER'], setup['cwd']]
        if budget:
            # A per-process fallback, not an emulation of a cgroup OOM kill.
            # The supervisor and children inherit this hard ceiling; restrict_child
            # must retain it instead of trying to raise it back to 1 GiB.
            command = ['prlimit', '--as=402653184:402653184',
                       '--data=402653184:402653184', '--'] + command
        result = captured(command, timeout=35)
        assert result.returncode == 0
        receipt = RECEIPTS['verify_receipt'](result.stdout, bytes.fromhex(setup['key']))
        assert receipt is not None and receipt['cwd'] == setup['cwd']
        assert no_candidates(), 'supervisor left running descendants'
        assert not Path(setup['cwd']).exists()
        return receipt
    finally:
        # Same independent cleanup path as the scorer, even on missing receipts.
        for name in ('CLEANUP_COMMAND', 'QUIESCENCE_COMMAND'):
            result = captured(SUPERVISOR[name], timeout=6)
            assert result.returncode in ((0, 1) if name == 'CLEANUP_COMMAND' else (0,))
        shutil.rmtree(setup['cwd'], ignore_errors=True)


def request_for(code):
    return dict(files={}, argv=[PYTHON, '-I', '-c', CHECK_LIMITS],
                run_argv=[PYTHON, '-I', '-c', CHECK_LIMITS + '\n' + code],
                timeout=5, run_timeout=15, output_limit=4096)


def failure_case(code, *, budget=False):
    receipt = invoke(request_for(code), budget=budget)
    # Use the actual scorer's failure gate: a valid receipt alone is insufficient.
    verdict = 'INCORRECT' if RECEIPTS['receipt_failure'](receipt) is not None else 'CORRECT'
    assert verdict == 'INCORRECT'
    assert receipt['stage'] == 'run' and receipt['returncode'] != 0
    assert not any(receipt.get(flag, False) for flag in FLAGS if flag != 'output_error')
    if code == INVALID_UTF8:
        assert receipt['output_error'] and receipt['returncode'] == 1
    elif code == FORK_EXHAUSTION:
        assert receipt['returncode'] == 1
    elif code == MEMORY_EXHAUSTION:
        assert receipt['returncode'] in (1, -9)  # MemoryError or kernel OOM kill.
    return {name: receipt[name] for name in ('stage', 'returncode')} | {
        'flags': {flag: receipt.get(flag, False) for flag in FLAGS}}


def cobol_smoke():
    receipt = invoke(dict(files={'smoke.cbl': '''       identification division.
       program-id. smoke.
       procedure division.
           display "ok".
           stop run.
'''}, argv=['cobc', '-x', '-o', 'smoke', 'smoke.cbl'], run_argv=['./smoke'],
                          timeout=10, run_timeout=5, output_limit=1024 * 1024))
    assert RECEIPTS['receipt_failure'](receipt) is None and receipt['output'].strip() == 'ok'


def docker_command(image):
    # The daemon must see ROOT at the same absolute path. Cloud Build's /workspace
    # volume satisfies this for both the outer and nested containers.
    return ['docker', 'run', '--rm', '--init', '--network=none', '--memory=512m',
            '--memory-swap=512m', '--pids-limit=128', '--user=0:0',
            '--mount', f'type=bind,source={ROOT},target={ROOT},readonly',
            image, PYTHON, str(ROOT / 'scripts/linux_regressions.py'), '--memory-child']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', help='reference image tag/digest for the nested memory regression')
    parser.add_argument('--memory-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    assert sys.platform == 'linux' and os.geteuid() == 0
    if args.memory_child:
        print(json.dumps(failure_case(MEMORY_EXHAUSTION)), flush=True)
        return
    cobol_smoke()
    for code in (INVALID_UTF8, FORK_EXHAUSTION):
        print(json.dumps(failure_case(code)), flush=True)
    if shutil.which('docker'):
        # If the CLI exists but the daemon/image is broken, fail; never silently
        # downgrade the cgroup regression to the weaker prlimit fallback.
        assert args.image, '--image is required when docker is available'
        result = captured(docker_command(args.image), timeout=90)
        assert result.returncode == 0
        summary = json.loads(result.stdout)
        assert set(summary) == {'stage', 'returncode', 'flags'}
        assert summary['stage'] == 'run' and summary['returncode'] in (1, -9)
        assert set(summary['flags']) == set(FLAGS)
        assert all(type(value) is bool and not value for value in summary['flags'].values())
        print(json.dumps(summary), flush=True)
    else:
        assert shutil.which('prlimit'), 'prlimit is required without docker'
        print(json.dumps(failure_case(MEMORY_EXHAUSTION, budget=True)), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Captured bytes/keys/tracebacks must never be printed, even on failure.
        print(json.dumps({'stage': 'regression', 'returncode': 1, 'flags': {'failed': True}}), flush=True)
        raise SystemExit(1) from None
