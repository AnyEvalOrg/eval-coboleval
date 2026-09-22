#!/usr/bin/env python3
"""Root-only, stdlib-only regressions in the disposable reference Linux image.

Load sources without importing coboleval's Inspect entry point: the reference
image intentionally has no host-side scoring dependencies. receipt_failure is
exactly the INCORRECT gate used by scoring.py, before answer comparison.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = runpy.run_path(str(ROOT / 'coboleval/sandbox_runner.py'))
RECEIPTS = runpy.run_path(str(ROOT / 'coboleval/receipts.py'))
CASES = runpy.run_path(str(Path(__file__).with_name('regression_cases.py')))
FLAGS = CASES['FLAGS']
KERNEL_CASES = CASES['KERNEL_CASES']
PYTHON = '/usr/local/bin/python3'
NESTED_CASES = ('memory_aggregate', 'disk', 'detached_child',
                'unlinked_files', 'memfd', 'empty_files', 'readonly_shm', 'ptrace_denied')
STEPS = frozenset(('startup', 'cobol_smoke', 'invalid_utf8', 'fork_exhaustion',
                   'memory_exhaustion', 'docker') + NESTED_CASES + KERNEL_CASES)
LABELS = frozenset((
    'unexpected-error', 'linux-root', 'reserved-uid-unused', 'setup-completed',
    'runner-completed', 'authenticated-receipt', 'descendants-stopped',
    'directory-retained', 'cleanup-completed', 'quiescence-completed',
    'directory-cleanup-completed', 'directory-deleted', 'incorrect-verdict',
    'compile-completed', 'failure-returncode', 'expected-flags',
    'invalid-utf8-receipt', 'fork-exhaustion-receipt', 'memory-exhaustion-receipt',
    'smoke-succeeded', 'smoke-output', 'expected-receipt', 'docker-image-required',
    'docker-completed', 'docker-output', 'docker-summary', 'prlimit-required',
    'docker-inspect', 'docker-cleanup',
))
# Nested stdout is untrusted. Only these class names may be relayed from it.
ERROR_CLASSES = frozenset((
    'AssertionError', 'TimeoutExpired', 'JSONDecodeError', 'UnicodeDecodeError',
    'OSError', 'FileNotFoundError', 'PermissionError', 'ProcessLookupError',
    'ValueError', 'TypeError', 'KeyError', 'IndexError', 'AttributeError',
    'MemoryError', 'OverflowError', 'RecursionError', 'RuntimeError', 'Exception',
))


@contextmanager
def step(name):
    try:
        yield
    except Exception as error:
        # Preserve the innermost step, e.g. a smoke failure after a disk case.
        if not hasattr(error, 'regression_step'):
            error.regression_step = name
        raise


def require(condition, label):
    if not condition:
        error = AssertionError()
        error.regression_label = label if label in LABELS else 'unexpected-error'
        raise error


def failure_report(error):
    name = getattr(error, 'regression_step', 'startup')
    label = getattr(error, 'regression_label', 'unexpected-error')
    return dict(stage='regression', step=name if name in STEPS else 'startup',
                error=type(error).__name__,
                label=label if label in LABELS else 'unexpected-error',
                returncode=1, flags={'failed': True})


def emit(record):
    print(json.dumps(record), flush=True)


INVALID_UTF8 = CASES['INVALID_UTF8']
FORK_EXHAUSTION = CASES['FORK_EXHAUSTION']
MEMORY_EXHAUSTION = '''blocks = []
while True:
    blocks.append(bytearray(8 * 1024 * 1024))
'''
CHECK_LIMITS = '''import os, resource
assert os.getresuid() == (65532,) * 3
assert resource.getrlimit(resource.RLIMIT_NPROC) == (64, 64)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (256, 256)
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


def invoke(request, *, budget=False, allow_oom=False):
    require(no_candidates(), 'reserved-uid-unused')
    setup_result = captured(['timeout', '-s', 'KILL', '5s', PYTHON, '-I', '-c', SUPERVISOR['SETUP']],
                            data=json.dumps(request).encode(), timeout=6)
    require(setup_result.returncode == 0, 'setup-completed')
    setup = json.loads(setup_result.stdout)
    if allow_oom:
        emit({'setup_succeeded': True})
    try:
        command = ['timeout', '-s', 'KILL', '30s', PYTHON, '-I', '-c', SUPERVISOR['RUNNER'], setup['cwd']]
        if budget:
            # A per-process fallback, not an emulation of a cgroup OOM kill.
            # The supervisor and children inherit this hard ceiling; restrict_child
            # must retain it instead of trying to raise it back to 1 GiB.
            command = ['prlimit', '--as=402653184:402653184',
                       '--data=402653184:402653184', '--'] + command
        result = captured(command, timeout=35)
        receipt = RECEIPTS['verify_receipt'](result.stdout, bytes.fromhex(setup['key']))
        if allow_oom and receipt is None and result.returncode in (-9, 137):
            # Preserve the killed RUNNER status for the outer Docker assertion.
            raise SystemExit(137)
        require(result.returncode == 0, 'runner-completed')
        require(receipt is not None and receipt['cwd'] == setup['cwd'], 'authenticated-receipt')
        require(no_candidates(), 'descendants-stopped')
        require(Path(setup['cwd']).exists(), 'directory-retained')
        return receipt
    finally:
        # Same independent cleanup path as the scorer, even on missing receipts.
        for name, label in (('CLEANUP_COMMAND', 'cleanup-completed'),
                            ('QUIESCENCE_COMMAND', 'quiescence-completed'),
                            ('DIRECTORY_CLEANUP_COMMAND', 'directory-cleanup-completed')):
            result = captured(SUPERVISOR[name], timeout=6)
            require(result.returncode in ((0, 1) if name == 'CLEANUP_COMMAND' else (0,)), label)
        require(not Path(setup['cwd']).exists(), 'directory-deleted')
        require(not Path(setup['cwd'] + '-disk').exists(), 'directory-deleted')


def request_for(code):
    return dict(files={}, argv=[PYTHON, '-I', '-c', CHECK_LIMITS],
                run_argv=[PYTHON, '-I', '-c', CHECK_LIMITS + '\n' + code],
                timeout=5, run_timeout=15, output_limit=4096)


def failure_case(code, *, budget=False):
    receipt = invoke(request_for(code), budget=budget)
    # Use the actual scorer's failure gate: a valid receipt alone is insufficient.
    verdict = 'INCORRECT' if RECEIPTS['receipt_failure'](receipt) is not None else 'CORRECT'
    require(verdict == 'INCORRECT', 'incorrect-verdict')
    require(receipt['stage'] == 'run', 'compile-completed')
    require(receipt['returncode'] != 0, 'failure-returncode')
    allowed = {'output_error', 'memory_exceeded'} if code == FORK_EXHAUSTION else {'output_error'}
    require(not any(receipt.get(flag, False) for flag in FLAGS if flag not in allowed), 'expected-flags')
    if code == INVALID_UTF8:
        require(receipt['output_error'] and receipt['returncode'] == 1, 'invalid-utf8-receipt')
    elif code == FORK_EXHAUSTION:
        require(CASES['expected_receipt']('fork_exhaustion', receipt, RECEIPTS['receipt_failure']),
                'fork-exhaustion-receipt')
    elif code == MEMORY_EXHAUSTION:
        require(receipt['returncode'] in (1, -9), 'memory-exhaustion-receipt')
    return {name: receipt[name] for name in ('stage', 'returncode')} | {
        'flags': {flag: receipt.get(flag, False) for flag in FLAGS}}


@step('cobol_smoke')
def cobol_smoke():
    # PROGRAM-ID main collides with GnuCOBOL's generated C entry point.
    receipt = invoke(dict(files={'smoke.cbl': '''       identification division.
       program-id. smoke.
       procedure division.
           display "ok".
           stop run.
'''}, argv=['cobc', '-x', '-o', 'smoke', 'smoke.cbl'], run_argv=['./smoke'],
                          timeout=10, run_timeout=5, output_limit=1024 * 1024))
    require(receipt['stage'] == 'run', 'compile-completed')
    require(RECEIPTS['receipt_failure'](receipt) is None, 'smoke-succeeded')
    require(receipt['output'].strip() == 'ok', 'smoke-output')


def aggregate_and_disk_cases():
    summaries = {}
    for name in NESTED_CASES:
        with step(name):
            receipt = invoke(CASES['request_for_case'](name))
            summaries[name] = {flag: bool(receipt.get(flag, False)) for flag in FLAGS}
            emit({'case': name, 'flags': summaries[name]})
            require(CASES['expected_receipt'](name, receipt, RECEIPTS['receipt_failure']), 'expected-receipt')
            # Demonstrate usability after cleanup, including disk exhaustion.
            cobol_smoke()
    return summaries


def docker_command(image, docker_cli='docker', *, kernel_case=None, container_name=None):
    # The daemon must see ROOT at the same absolute path. Cloud Build's /workspace
    # volume satisfies this for both the outer and nested containers.
    # /tmp is writable despite --read-only: SETUP uses /tmp/cjt-* and cobc
    # writes scratch files there. An anonymous disk volume permits ./smoke and
    # is removed with --rm or explicit rm -v after inspecting kernel cases.
    lifecycle = ['--name', container_name] if container_name else ['--rm']
    return [docker_cli, 'run', *lifecycle, '--init', '--network=none', '--memory=2g',
            '--memory-swap=2g', '--read-only', '--mount', 'type=volume,target=/tmp',
            '--tmpfs', '/dev/shm:ro,size=16m', '--pids-limit=128', '--user=0:0',
            '--cap-drop=ALL', '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=KILL',
            '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=SYS_PTRACE',
            '--security-opt=no-new-privileges:true',
            '--mount', f'type=bind,source={ROOT},target={ROOT},readonly',
            image, PYTHON, str(ROOT / 'scripts/linux_regressions.py')] + (
                ['--kernel-child', kernel_case] if kernel_case else ['--memory-child'])


def valid_flags(flags):
    return (type(flags) is dict and set(flags) == set(FLAGS)
            and all(type(value) is bool for value in flags.values()))


def relay_nested_output(data):
    """Rebuild allowlisted JSON records; never forward raw subprocess output."""
    receipts = {}
    summary = None
    failed = False
    for line in data.splitlines():
        require(summary is None and not failed, 'docker-output')
        record = json.loads(line)
        require(type(record) is dict, 'docker-output')
        if set(record) == {'case', 'flags'}:
            name = record['case']
            require(len(receipts) < len(NESTED_CASES)
                    and name == NESTED_CASES[len(receipts)]
                    and valid_flags(record['flags']), 'docker-output')
            receipts[name] = {flag: record['flags'][flag] for flag in FLAGS}
            emit({'case': name, 'flags': receipts[name]})
        elif record.get('stage') == 'regression':
            require(set(record) == {'stage', 'step', 'error', 'label', 'returncode', 'flags'}
                    and record['step'] in STEPS and record['error'] in ERROR_CLASSES
                    and record['label'] in LABELS
                    and type(record['returncode']) is int and record['returncode'] == 1
                    and record['flags'] == {'failed': True}
                    and type(record['flags']['failed']) is bool, 'docker-output')
            emit(dict(stage='regression', step=record['step'], error=record['error'],
                      label=record['label'], returncode=1, flags={'failed': True}))
            failed = True
        else:
            require(set(record) == set(NESTED_CASES)
                    and all(valid_flags(flags) for flags in record.values())
                    and record == receipts, 'docker-summary')
            summary = record
    return summary


def kernel_child(name):
    receipt = invoke(CASES['request_for_case'](name), allow_oom=True)
    flags = {flag: bool(receipt.get(flag, False)) for flag in FLAGS}
    flags.update(signed=True, expected=CASES['expected_receipt'](name, receipt, RECEIPTS['receipt_failure']),
                 sysv_refused=CASES['sysv_refused'](name, receipt))
    emit(flags)
    require(flags['expected'], 'expected-receipt')


def kernel_flags():
    return dict.fromkeys((*FLAGS, 'signed', 'expected', 'sysv_refused',
                          'exit_137', 'oom_killed'), False)


def kernel_docker_flags(result, *, oom_killed=False, flags=None):
    """Accept a signed watchdog receipt or Docker sandbox death; flags only."""
    if flags is None:
        flags = kernel_flags()
    flags.update(exit_137=result.returncode == 137, oom_killed=oom_killed)
    if flags['exit_137'] or flags['oom_killed']:
        # PID 1 can die before flushing even the SETUP marker. No child output
        # is needed or relayed for this outcome, including partial JSON.
        flags['expected'] = True
        return flags
    lines = result.stdout.splitlines()
    require(result.returncode == 0 and len(lines) == 2, 'docker-completed')
    require(json.loads(lines[0]) == {'setup_succeeded': True}, 'docker-output')
    report = json.loads(lines[1])
    expected_keys = set(FLAGS) | {'signed', 'expected', 'sysv_refused'}
    require(type(report) is dict and set(report) == expected_keys
            and all(type(value) is bool for value in report.values()), 'docker-output')
    flags.update(report)
    flags['expected'] = (report['signed'] and report['expected'] and
                         (report['memory_exceeded'] or report['disk_exceeded']))
    require(flags['expected'], 'expected-receipt')
    return flags


def kernel_docker_cases(image, docker_cli):
    # One fresh container each, LAST: retained SysV segments need pod/container
    # teardown even after the UID sweep, and any of these cases may kill PID 1.
    for name in KERNEL_CASES:
        with step(name):
            container_name = f'linux-regression-{name}-{uuid.uuid4().hex}'
            flags = kernel_flags()
            returncode = None
            try:
                result = captured(docker_command(image, docker_cli, kernel_case=name,
                                                 container_name=container_name), timeout=60)
                returncode = result.returncode
                flags['exit_137'] = returncode == 137
                inspected = captured([docker_cli, 'inspect', '--format',
                                      '{{.State.OOMKilled}}', container_name], timeout=10)
                require(inspected.returncode == 0 and inspected.stdout.strip() in (b'true', b'false'),
                        'docker-inspect')
                kernel_docker_flags(result, oom_killed=inspected.stdout.strip() == b'true', flags=flags)
                require(not flags['sysv_refused'] or name == 'sysv_shm', 'expected-flags')
            finally:
                emit({'case': name, 'returncode': returncode, 'flags': flags})
                # Remove the container and its anonymous /tmp volume even when
                # parsing, inspection, or the run itself fails. Keep the first
                # failure's attribution if cleanup fails as well.
                failed = sys.exc_info()[0] is not None
                try:
                    cleaned = captured([docker_cli, 'rm', '-f', '-v', container_name], timeout=10)
                    require(cleaned.returncode == 0, 'docker-cleanup')
                except Exception:
                    if not failed:
                        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', help='reference image tag/digest for the nested memory and disk regressions')
    parser.add_argument('--docker-cli', help='Docker CLI path in the outer container (fails closed if unavailable)')
    parser.add_argument('--memory-child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--kernel-child', choices=KERNEL_CASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'linux-root')
    if args.kernel_child:
        kernel_child(args.kernel_child)
        return
    if args.memory_child:
        emit(aggregate_and_disk_cases())
        return
    cobol_smoke()
    for name, code in (('invalid_utf8', INVALID_UTF8), ('fork_exhaustion', FORK_EXHAUSTION)):
        with step(name):
            emit(failure_case(code))
    docker_cli = args.docker_cli or shutil.which('docker')
    if docker_cli:
        # If the CLI exists but the daemon/image is broken, fail; never silently
        # downgrade the cgroup regression to the weaker prlimit fallback.
        with step('docker'):
            require(args.image, 'docker-image-required')
            result = captured(docker_command(args.image, docker_cli), timeout=240)
            # Relay completed cases and the sanitized child error even on exit 1.
            summary = relay_nested_output(result.stdout)
            require(result.returncode == 0, 'docker-completed')
            require(summary is not None, 'docker-summary')
            for name, flags in summary.items():
                require(flags['memory_exceeded'] == (name == 'memory_aggregate')
                        and flags['disk_exceeded'] == (name in CASES['DISK_CASES'])
                        and not any(value for flag, value in flags.items()
                                    if flag not in {'memory_exceeded', 'disk_exceeded'}),
                        'expected-flags')
            emit(summary)
        kernel_docker_cases(args.image, docker_cli)
    else:
        with step('memory_exhaustion'):
            require(shutil.which('prlimit'), 'prlimit-required')
            emit(failure_case(MEMORY_EXHAUSTION, budget=True))


def entrypoint():
    try:
        main()
    except Exception as error:
        # Captured bytes/keys/tracebacks must never be printed, even on failure.
        emit(failure_report(error))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(entrypoint())
