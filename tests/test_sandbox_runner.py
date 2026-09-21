"""Authored fixtures only. macOS stubs test protocol mechanics, not containment."""
import ast
from functools import partial
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest
from coboleval.sandbox_runner import SETUP, RUNNER, CLEANUP_COMMAND, QUIESCENCE_COMMAND, DIRECTORY_CLEANUP_COMMAND
from coboleval.scoring import verify_receipt


def prepare(request):
    result = subprocess.run([sys.executable, '-I', '-c', SETUP], input=json.dumps(request),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    return json.loads(result.stdout)


def run_fixture(compile_code='pass', run_code="print('ok')", timeout=1, output_file=None,
                real_supervisor=False, transform=lambda source: source):
    request = dict(files={'fixture.txt': 'safe authored input'}, argv=[sys.executable, '-I', '-c', compile_code],
                   run_argv=[sys.executable, '-I', '-c', run_code], timeout=timeout, run_timeout=timeout, output_limit=4096)
    if output_file:
        request['output_file'] = output_file
    setup = prepare(request)
    source = RUNNER
    if not real_supervisor:
        # Never perform credential changes or UID sweeps on the developer host.
        # Keep file-size limits, overflow detection, and stage gating intact.
        source = source.replace('libc = ctypes.CDLL(None, use_errno=True)', 'libc = type("Stub", (), {"prctl": lambda *args: 0})()')
        source = source.replace('os.getuid() != 0', 'False')
        source = source.replace('with open("/proc/self/oom_score_adj", "w") as f:', 'with open(os.devnull, "w") as f:')
        if sys.platform != 'linux':
            source = source.replace('resource.setrlimit(kind, (budget, budget))', 'pass')
        source = source.replace('os.setgroups([])', 'pass')
        source = source.replace('os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)', 'pass')
        source = source.replace('os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)', 'pass')
        source = source.replace('os.chown(candidate_work, CANDIDATE_UID, CANDIDATE_GID)', 'pass')
        source = source.replace('info.st_uid != CANDIDATE_UID', 'info.st_uid != os.getuid()')
        source = source.replace('os.killpg(pgid, sig)', 'os.kill(pgid, sig)')
        source = source.replace('def candidate_rss():', 'def candidate_rss():\n    return 0\n')
        source = source.replace('def disk_bytes(roots=("/tmp", "/dev/shm")):', 'def disk_bytes(roots=("/tmp", "/dev/shm")):\n    return 0\n')
        start, end = source.index('def sweep_uid():'), source.index('def run_step(')
        source = source[:start] + 'def sweep_uid():\n    pass\n\n\n' + source[end:]
    source = transform(source)
    try:
        result = subprocess.run([sys.executable, '-I', '-c', source, setup['cwd']],
                                capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, result.stderr
        receipt = verify_receipt(result.stdout, bytes.fromhex(setup['key']))
        assert receipt is not None
        assert Path(setup['cwd']).exists()  # Deletion belongs to independent cleanup.
        return receipt
    finally:
        shutil.rmtree(setup['cwd'], ignore_errors=True)


@pytest.fixture
def output_limit_runner():
    """Use the real supervisor under the Linux containment suite's opt-in."""
    real = sys.platform == 'linux' and os.geteuid() == 0 and os.environ.get('CJT_LINUX_CONTAINMENT') == '1'
    if real:
        result = subprocess.run(['/usr/bin/pgrep', '-u', '65532'], capture_output=True, timeout=5)
        assert result.returncode == 1, 'candidate UID must be unused before containment tests'
    try:
        yield partial(run_fixture, real_supervisor=real)
    finally:
        if real:
            for command in (CLEANUP_COMMAND, QUIESCENCE_COMMAND, DIRECTORY_CLEANUP_COMMAND):
                result = subprocess.run(command, capture_output=True, timeout=6)
                assert result.returncode in ((0, 1) if command == CLEANUP_COMMAND else (0,))


def overflowing_writer(target):
    # Attempt twice the 4096-byte request limit. Ignore SIGXFSZ and handle EFBIG
    # so a successful child exit forces the supervisor to detect the overflow.
    # Report stderr's size via stdout, since stderr is absent from the receipt.
    return f'''import errno, os, signal
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
fd = {target}
remaining = b'x' * 8192
try:
    while remaining:
        remaining = remaining[os.write(fd, remaining):]
except OSError as exc:
    if exc.errno != errno.EFBIG:
        raise
if fd == 2:
    print(os.fstat(fd).st_size)
'''


@pytest.mark.parametrize('stream, expected_output', [('stdout', 'x' * 4096), ('stderr', '4096\n')],
                         ids=['stdout', 'stderr'])
def test_compile_output_limit_blocks_execution(output_limit_runner, stream, expected_output):
    receipt = output_limit_runner(
        compile_code=overflowing_writer('1' if stream == 'stdout' else '2'),
        run_code="print('MUST_NOT_RUN')",
    )
    assert receipt['returncode'] == 0 and not receipt['timeout']
    assert receipt['overflow'] is True
    assert receipt['stage'] == 'compile'
    assert 'MUST_NOT_RUN' not in receipt['output']
    assert receipt['output'] == expected_output


def test_result_file_output_limit(output_limit_runner):
    receipt = output_limit_runner(
        run_code=overflowing_writer("os.open('OUT.TXT', os.O_WRONLY | os.O_CREAT, 0o600)"),
        output_file='OUT.TXT',
    )
    assert receipt['returncode'] == 0 and not receipt['timeout']
    assert receipt['stage'] == 'run'
    assert receipt['overflow'] is True
    assert receipt['output'] == 'x' * 4096


def test_setup_atomic_private_dirs_and_keys():
    setups = [prepare(dict(files={}, argv=['true'], timeout=1, output_limit=4096)) for _ in range(2)]
    try:
        assert len({s['cwd'] for s in setups}) == len({s['key'] for s in setups}) == 2
        for s in setups:
            assert Path(s['cwd']).stat().st_mode & 0o777 == 0o700
            assert (Path(s['cwd'])/'request.json').is_file()
    finally:
        for s in setups:
            shutil.rmtree(s['cwd'])


def test_separate_steps_share_workdir_and_request_is_unlinked():
    receipt = run_fixture("open('artifact','w').write('ok')", "import os; assert not os.path.exists('../request.json'); print(open('artifact').read())")
    assert receipt['returncode'] == 0 and receipt['stage'] == 'run'
    assert receipt['output'] == 'ok\n'


def test_compile_failure_never_executes_run_step():
    receipt = run_fixture('raise SystemExit(7)', "print('MUST_NOT_RUN')")
    assert receipt['stage'] == 'compile' and receipt['returncode'] == 7
    assert 'MUST_NOT_RUN' not in receipt['output']


def test_forged_marker_cannot_override_exit():
    receipt = run_fixture(run_code="print('<completed-sentinel-value-0>'); raise SystemExit(7)")
    assert receipt['stage'] == 'run' and receipt['returncode'] == 7


@pytest.mark.parametrize('stage', ['compile', 'run'])
def test_each_stage_has_independent_timeout(stage):
    kwargs = {'compile_code' if stage == 'compile' else 'run_code': 'while True: pass'}
    receipt = run_fixture(timeout=0.1, **kwargs)
    assert receipt['timeout'] and receipt['stage'] == stage
    assert receipt['returncode'] != 0


def test_output_file_receipt():
    receipt = run_fixture(run_code="open('OUT.TXT','w').write('p23\\n')", output_file='OUT.TXT')
    assert receipt['output'] == 'p23\n' and receipt['returncode'] == 0


@pytest.mark.parametrize('code', ["import os; os.symlink('/etc/passwd','OUT.TXT')", "import os; os.mkfifo('OUT.TXT')", 'pass'])
def test_unsafe_or_missing_output_files_fail_without_reading(code):
    receipt = run_fixture(run_code=code, output_file='OUT.TXT')
    assert receipt['returncode'] != 0 and receipt['output'] == ''


def test_supervisor_preserves_required_security_contract():
    tree = ast.parse(RUNNER)
    restrict = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'restrict_child')
    calls = [ast.unparse(n.value) for n in restrict.body if isinstance(n, ast.Expr)]
    assert calls.index('os.setgroups([])') < calls.index('os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)') < calls.index('os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)') < calls.index('resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))')
    for text in ['libc.prctl(4, 0, 0, 0, 0)', 'libc.prctl(38, 1, 0, 0, 0)', 'libc.prctl(8, 0, 0, 0, 0)', 'libc.prctl(36, 1, 0, 0, 0)', 'os.killpg(pgid, sig)', 'os.O_NOFOLLOW', 'sweep_uid()', 'close_fds=True', 'start_new_session=True', 'preexec_fn=restrict_child', 'os.unlink(request_path)']:
        assert text in RUNNER
    assert 'shell=True' not in RUNNER and 'bash' not in RUNNER
    assert CLEANUP_COMMAND[-4:] == ['/usr/bin/pkill', '-KILL', '-u', '65532']


@pytest.mark.parametrize('output_file', [None, 'OUT.TXT'])
def test_non_utf8_output_is_an_authenticated_failure(output_file):
    code = ("open('OUT.TXT','wb').write(b'\\xff')" if output_file else
            "import os; os.write(1,b'\\xff'); raise SystemExit(1)")
    receipt = run_fixture(run_code=code, output_file=output_file)
    assert receipt['stage'] == 'run' and receipt['output_error'] is True
    from coboleval.receipts import receipt_failure
    assert receipt_failure(receipt) == 'output not decodable'


def test_receipt_does_not_depend_on_post_exit_spawns():
    # A post-candidate spawn would raise EAGAIN under a full PID budget. The
    # actual sweep uses /proc+kill; execute it against an empty fake /proc here.
    sweep = RUNNER[RUNNER.index('def sweep_uid():'):RUNNER.index('def run_step(')]
    def transform(source):
        source = source.replace('def sweep_uid():\n    pass', sweep)
        return source.replace('stage = "compile"\nstatus =', '''
def forbidden_spawn(*args, **kwargs):
    raise OSError(11, "synthetic process exhaustion after candidate exit")
subprocess.run = forbidden_spawn
os.listdir = lambda path: []
stage = "compile"
status =''')
    receipt = run_fixture(compile_code='raise SystemExit(1)', transform=transform)
    assert receipt['returncode'] == 1 and not receipt['cleanup_failed']


@pytest.mark.parametrize('operation', ['sweep', 'kill_group', 'read'])
def test_post_exit_exceptions_still_sign_failure(operation):
    def transform(source):
        if operation == 'sweep':
            return source.replace('def sweep_uid():\n    pass', '''def sweep_uid():
    subprocess.run(["synthetic-cleanup"])

def fail_spawn(*args, **kwargs):
    raise OSError(11, "synthetic fork failure")
subprocess.run = fail_spawn''')
        if operation == 'kill_group':
            return source.replace('            kill_group(child.pid)', '            raise OSError("synthetic kill failure")')
        if operation == 'read':
            return source.replace('            stdout.seek(0)', '            raise OSError("synthetic output failure")')
    receipt = run_fixture(compile_code='raise SystemExit(1)', transform=transform)
    assert receipt['returncode'] == 1
    assert receipt['supervisor_error'] if operation == 'read' else receipt['cleanup_failed']
    from coboleval.receipts import receipt_failure
    assert receipt_failure(receipt) is not None


@pytest.mark.parametrize('inherited', [-1, 384 * 1024 * 1024])
def test_actual_preexec_limits_and_oom_preference(inherited):
    import io
    import resource
    from types import SimpleNamespace
    from unittest.mock import Mock
    tree = ast.parse(RUNNER)
    restrict = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'restrict_child')
    calls = []
    resources = SimpleNamespace(**{name: getattr(resource, name) for name in (
        'RLIMIT_AS', 'RLIMIT_DATA', 'RLIMIT_NPROC', 'RLIMIT_FSIZE', 'RLIMIT_CORE', 'RLIM_INFINITY')})
    resources.RLIM_INFINITY = -1  # Linux's value, regardless of the test host.
    resources.getrlimit = lambda kind: (inherited, inherited)
    resources.setrlimit = lambda kind, limits: calls.append((kind, limits))
    stream = Mock(wraps=io.StringIO())
    context = Mock()
    context.__enter__ = Mock(return_value=stream)
    context.__exit__ = Mock(return_value=False)
    opener = Mock(return_value=context)
    namespace = dict(os=Mock(), libc=SimpleNamespace(prctl=lambda *args: 0),
                     resource=resources, CANDIDATE_UID=65532, CANDIDATE_GID=65532,
                     limit=4096, open=opener)
    exec(compile(ast.Module(body=[restrict], type_ignores=[]), '<limits>', 'exec'), namespace)
    namespace['restrict_child']()
    budget = 1024**3 if inherited == -1 else inherited
    assert dict(calls) == {resource.RLIMIT_NPROC: (64, 64),
                           resource.RLIMIT_AS: (budget, budget),
                           resource.RLIMIT_DATA: (budget, budget),
                           resource.RLIMIT_FSIZE: (4096, 4096), resource.RLIMIT_CORE: (0, 0)}
    opener.assert_called_once_with('/proc/self/oom_score_adj', 'w')
    stream.write.assert_called_once_with('1000')


@pytest.mark.parametrize('rss_kib,exceeded', [(384 * 1024, False), (384 * 1024 + 1, True)])
def test_watchdog_sums_reserved_uid_rss_and_kills_all_sessions(rss_kib, exceeded):
    import io
    import signal
    from types import SimpleNamespace
    from unittest.mock import Mock
    names = ['1', '2', '3', '4', '5', '6', 'self']
    proc = {
        '1': 'Uid:\t0 0 0 0\nVmRSS:\t999999999 kB\n',
        '2': f'Uid:\t65532 65532 65532 65532\nVmRSS:\t{rss_kib} kB\n',
        '3': f'Uid:\t65532 65532 65532 65532\nVmRSS:\t{rss_kib} kB\n',
        '4': 'Uid:\t65532 65532 65532 65532\nState:\tZ (zombie)\n',
    }
    def opener(path):
        pid = path.split('/')[2]
        if pid not in proc:
            raise FileNotFoundError(path)
        return io.StringIO(proc[pid])
    process_api = SimpleNamespace(listdir=Mock(return_value=names), kill=Mock(), killpg=Mock())
    stopped = Mock()
    stopped.is_set.return_value = False
    stopped.wait.return_value = True
    status = dict(memory_exceeded=False, supervisor_error=False, cleanup_failed=False)
    namespace = dict(os=process_api, open=opener, signal=signal, CANDIDATE_UID=65532,
                     MEMORY_BUDGET=768 * 1024**2, MEMORY_INTERVAL=0.05)
    tree = ast.parse(RUNNER)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and
                 n.name in {'candidate_rss', 'kill_candidate', 'watch_memory'}]
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<watchdog>', 'exec'), namespace)
    namespace['watch_memory'](42, stopped, status)
    assert status['memory_exceeded'] is exceeded
    assert not status['supervisor_error'] and not status['cleanup_failed']
    if exceeded:
        process_api.killpg.assert_called_once_with(42, signal.SIGKILL)
        assert [call.args for call in process_api.kill.call_args_list] == [
            (2, signal.SIGKILL), (3, signal.SIGKILL), (4, signal.SIGKILL)]
        stopped.wait.assert_not_called()
    else:
        process_api.killpg.assert_not_called()
        process_api.kill.assert_not_called()
        stopped.wait.assert_called_once_with(0.05)


def test_memory_flag_is_signed_and_blocks_next_stage():
    def transform(source):
        return source.replace('def candidate_rss():\n    return 0',
                              'def candidate_rss():\n    return MEMORY_BUDGET + 1').replace(
                                  'def kill_candidate(pgid):',
                                  'def kill_candidate(pgid):\n    os.kill(pgid, signal.SIGKILL)\n    return')
    receipt = run_fixture(compile_code='import time; time.sleep(1)', transform=transform)
    assert receipt['memory_exceeded'] and receipt['stage'] == 'compile'
    from coboleval.receipts import receipt_failure
    assert receipt_failure(receipt) == 'memory limit exceeded'


def disk_namespace(**overrides):
    import errno
    import stat
    namespace = dict(os=os, errno=errno, stat=stat, DISK_BUDGET=256 * 1024**2,
                     DISK_INTERVAL=0.1)
    namespace.update(overrides)
    functions = [n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
                 and n.name in {'disk_bytes', 'watch_disk'}]
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<disk-watchdog>', 'exec'), namespace)
    return namespace


@pytest.mark.parametrize('exceeded', [False, True])
def test_disk_watchdog_counts_allocated_blocks_across_roots(tmp_path, exceeded):
    from unittest.mock import Mock
    roots = [tmp_path / 'tmp', tmp_path / 'shm']
    work = roots[0] / 'work' / 'candidate'
    other = roots[0] / 'outside-work'
    for directory in (work, other, roots[1]):
        directory.mkdir(parents=True)
    files = [work / 'one', other / 'two', roots[1] / 'three']
    for path in files:
        path.write_bytes(b'x' * 8192)
    sparse = work / 'sparse'
    with sparse.open('wb') as stream:
        stream.truncate(1024**3)
    files.append(sparse)
    outside = tmp_path / 'not-mounted'
    outside.mkdir()
    (outside / 'ignored').write_bytes(b'x' * 32768)
    (other / 'dir-link').symlink_to(outside, target_is_directory=True)
    (other / 'file-link').symlink_to(files[0])
    (other / 'cycle').symlink_to(roots[0], target_is_directory=True)
    os.mkfifo(other / 'fifo')
    namespace = disk_namespace(kill_candidate=Mock())
    total = sum(path.stat().st_blocks * 512 for path in files)
    measure = namespace['disk_bytes']
    assert measure(roots) == total
    namespace['disk_bytes'] = lambda: measure(roots)
    namespace['DISK_BUDGET'] = total - 1 if exceeded else total
    stopped = Mock()
    stopped.is_set.return_value = False
    stopped.wait.return_value = True
    status = dict(disk_exceeded=False, supervisor_error=False, cleanup_failed=False)
    namespace['watch_disk'](42, stopped, status)
    assert status == dict(disk_exceeded=exceeded, supervisor_error=False, cleanup_failed=False)
    if exceeded:
        namespace['kill_candidate'].assert_called_once_with(42)
        stopped.wait.assert_not_called()
    else:
        namespace['kill_candidate'].assert_not_called()
        stopped.wait.assert_called_once_with(0.1)


@pytest.mark.parametrize('replacement', ['removed', 'symlink'])
def test_disk_walk_tolerates_directory_replacement_without_following_symlinks(tmp_path, replacement):
    from types import SimpleNamespace
    root = tmp_path / 'tmp'
    child = root / 'raced'
    child.mkdir(parents=True)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'ignored').write_bytes(b'x' * 8192)
    original_open = os.open
    def raced_open(path, flags, **kwargs):
        if path == 'raced':
            child.rmdir()
            if replacement == 'symlink':
                child.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, **kwargs)
    api = SimpleNamespace(**{name: getattr(os, name) for name in
        ('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK', 'scandir', 'close')}, open=raced_open)
    assert disk_namespace(os=api)['disk_bytes']([root, tmp_path / 'missing']) == 0


@pytest.mark.parametrize('kill_fails', [False, True])
def test_disk_monitor_error_fails_closed(kill_fails):
    from unittest.mock import Mock
    kill = Mock(side_effect=OSError('kill failed') if kill_fails else None)
    namespace = disk_namespace(kill_candidate=kill)
    namespace['disk_bytes'] = Mock(side_effect=PermissionError('scan failed'))
    stopped = Mock()
    stopped.is_set.return_value = False
    status = dict(disk_exceeded=False, supervisor_error=False, cleanup_failed=False)
    namespace['watch_disk'](42, stopped, status)
    assert status == dict(disk_exceeded=False, supervisor_error=True, cleanup_failed=kill_fails)
    kill.assert_called_once_with(42)


def test_disk_flag_is_signed_and_blocks_next_stage():
    def transform(source):
        return source.replace('def disk_bytes(roots=("/tmp", "/dev/shm")):\n    return 0',
                              'def disk_bytes(roots=("/tmp", "/dev/shm")):\n    return DISK_BUDGET + 1').replace(
                                  'def kill_candidate(pgid):',
                                  'def kill_candidate(pgid):\n    os.kill(pgid, signal.SIGKILL)\n    return')
    receipt = run_fixture(compile_code='import time; time.sleep(1)', transform=transform)
    assert receipt['disk_exceeded'] and receipt['stage'] == 'compile'
    assert receipt['returncode'] != 0
    from coboleval.receipts import receipt_failure
    assert receipt_failure(receipt) == 'disk limit exceeded'


@pytest.mark.parametrize('hanging', [False, True], ids=['ordering', 'hanging-deletion'])
def test_complete_receipt_precedes_any_directory_deletion(tmp_path, hanging):
    marker = tmp_path / 'deleted'
    def transform(source):
        # This would record (or hang on) any deletion in the runner, including
        # Python shutdown hooks. Only independent cleanup may delete work.
        hook = f'''
import shutil, atexit

def forbidden_delete(*args, **kwargs):
    open({str(marker)!r}, 'w').write('deletion attempted')
    {'time.sleep(60)' if hanging else 'raise RuntimeError("deletion before receipt")'}
shutil.rmtree = forbidden_delete
atexit.register(forbidden_delete)
'''
        return source.replace('stage = "compile"\nstatus =', hook + '\nstage = "compile"\nstatus =')
    receipt = run_fixture(transform=transform)
    assert receipt['stage'] == 'run' and receipt['returncode'] == 0
    assert not marker.exists()
    # The independent exec is explicitly bounded, including shell globbing.
    assert DIRECTORY_CLEANUP_COMMAND[:4] == ['timeout', '-s', 'KILL', '5s']
    assert DIRECTORY_CLEANUP_COMMAND[-1] == 'exec rm -rf -- /tmp/cjt-*'
