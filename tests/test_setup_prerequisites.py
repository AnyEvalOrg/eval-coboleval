"""Exercise the actual SETUP source without changing host credentials."""
import ast
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from coboleval.sandbox_runner import SETUP, RUNNER


@pytest.fixture
def setup_probe(monkeypatch, tmp_path):
    work = tmp_path / 'work'
    work.mkdir()
    api = SimpleNamespace(**{name: getattr(os, name) for name in
        ('path', 'chmod', 'stat')}, getuid=lambda: 0, chown=Mock(), listdir=Mock(return_value=['1', '42']))
    child = SimpleNamespace(pid=42, stdout=io.BytesIO(b'ready\n'), kill=Mock(), wait=Mock())
    status = 'Uid:\t65532 65532 65532 65532\nVmRSS:\t4096 kB\n'
    real_open = open
    def opener(path, *args, **kwargs):
        if path == '/proc/self/oom_score_adj':
            return io.StringIO()
        if path == '/proc/42/status':
            return io.StringIO(status)
        return real_open(path, *args, **kwargs)
    original_stat = api.stat
    api.stat = Mock(side_effect=lambda path: None if path == '/proc/42/fd/0' else original_stat(path))
    launched = []
    def popen(argv, **kwargs):
        script = Path(argv[0])
        launched.append(script.read_text())
        assert script.stat().st_mode & 0o111 == 0o111
        assert kwargs['cwd'] == str(script.parent)
        return child
    process = SimpleNamespace(Popen=Mock(side_effect=popen), DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE)
    ns = dict(os=api, subprocess=process, tempfile=SimpleNamespace(
        mkdtemp=Mock(return_value=str(work)), TemporaryDirectory=tempfile.TemporaryDirectory),
        sys=SimpleNamespace(stdin=io.StringIO(json.dumps({'output_limit': 4096})),
                            stdout=io.StringIO(), executable=sys.executable),
        json=json, secrets=secrets, open=opener, libc=SimpleNamespace(prctl=Mock(return_value=0)),
        CANDIDATE_UID=65532, CANDIDATE_GID=65532, restrict_child=Mock())
    functions = [n for n in ast.parse(SETUP).body if isinstance(n, ast.FunctionDef)
                 and n.name in {'self_check', 'setup'}]
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<setup-test>', 'exec'), ns)
    return SimpleNamespace(ns=ns, api=api, child=child, process=process, work=work, launched=launched)


def test_setup_prerequisites_happy_path(setup_probe):
    p = setup_probe
    p.ns['setup']()
    receipt = json.loads(p.ns['sys'].stdout.getvalue())
    assert receipt['cwd'] == str(p.work) and len(bytes.fromhex(receipt['key'])) == 32
    assert json.loads((p.work / 'request.json').read_text())['key'] == receipt['key']
    assert p.work.stat().st_mode & 0o777 == 0o700
    assert list(p.work.iterdir()) == [p.work / 'request.json']
    p.api.listdir.assert_called_once_with('/proc')
    p.api.stat.assert_called_once_with('/proc/42/fd/0')
    options = p.process.Popen.call_args.kwargs
    assert options['preexec_fn'] is p.ns['restrict_child']
    assert options['close_fds'] and options['start_new_session']
    assert options['stdin'] == subprocess.DEVNULL
    assert p.launched[0].startswith('#!' + sys.executable + '\n')
    assert "with open('writable', 'x')" in p.launched[0]
    assert 'time.sleep(2)' in p.launched[0]
    p.child.kill.assert_called_once()
    p.child.wait.assert_called_once_with(timeout=1)
    assert p.child.stdout.closed


@pytest.mark.parametrize('fault', [
    'not_root', 'dumpable', 'proc_list', 'oom_open', 'oom_write', 'work_create',
    'work_write', 'chmod', 'exec', 'child_write', 'fd_stat', 'status_read',
    'wrong_uid', 'missing_rss',
])
def test_setup_prerequisite_failure_has_fixed_error_and_no_receipt(setup_probe, monkeypatch, fault):
    p = setup_probe
    error = PermissionError('PRIVATE_INFRASTRUCTURE_DETAILS')
    if fault == 'not_root':
        monkeypatch.setattr(p.api, 'getuid', lambda: 65532)
    elif fault == 'dumpable':
        p.ns['libc'].prctl.return_value = -1
    elif fault == 'proc_list':
        p.api.listdir.side_effect = error
    elif fault == 'work_create':
        p.ns['tempfile'].mkdtemp.side_effect = error
    elif fault == 'chmod':
        monkeypatch.setattr(p.api, 'chmod', Mock(side_effect=error))
    elif fault == 'exec':
        p.process.Popen.side_effect = error
    elif fault == 'child_write':
        p.child.stdout = io.BytesIO(b'')
    elif fault == 'fd_stat':
        p.api.stat.side_effect = error
    else:
        original_open = p.ns['open']
        class Unwritable(io.StringIO):
            def write(self, text):
                raise error
        def opener(path, *args, **kwargs):
            if path == '/proc/self/oom_score_adj':
                if fault == 'oom_open':
                    raise error
                if fault == 'oom_write':
                    return Unwritable()
            if str(path).endswith('/check') and fault == 'work_write':
                raise error
            if path == '/proc/42/status':
                if fault == 'status_read':
                    raise error
                if fault == 'wrong_uid':
                    return io.StringIO('Uid:\t0 0 0 0\nVmRSS:\t4096 kB\n')
                if fault == 'missing_rss':
                    return io.StringIO('Uid:\t65532 65532 65532 65532\n')
            return original_open(path, *args, **kwargs)
        monkeypatch.setitem(p.ns, 'open', opener)
    with pytest.raises(SystemExit) as raised:
        p.ns['setup']()
    assert raised.value.code == 'sandbox prerequisites unavailable'
    assert p.ns['sys'].stdout.getvalue() == ''
    assert not (p.work / 'request.json').exists()
    if p.launched:
        p.child.kill.assert_called_once()
        p.child.wait.assert_called_once_with(timeout=1)
        assert p.child.stdout.closed


@pytest.mark.parametrize('source', [SETUP, RUNNER], ids=['setup', 'runner'])
@pytest.mark.parametrize('failure', [None, 38, 8])
def test_restrict_child_irreversibly_drops_capabilities_in_order(source, failure):
    from unittest.mock import mock_open
    calls = Mock()
    calls.prctl.side_effect = lambda option, *args: -1 if option == failure else 0
    calls._exit.side_effect = SystemExit
    resources = Mock()
    resources.getrlimit.return_value = (-1, -1)
    resources.RLIM_INFINITY = -1
    opener = mock_open()
    calls.attach_mock(opener, 'open')
    ns = dict(os=calls, libc=calls, resource=resources, open=opener,
              CANDIDATE_UID=65532, CANDIDATE_GID=65532, limit=4096)
    restrict = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)
                    and n.name == 'restrict_child')
    exec(compile(ast.Module(body=[restrict], type_ignores=[]), '<restrict-test>', 'exec'), ns)
    if failure:
        with pytest.raises(SystemExit):
            ns['restrict_child']()
        calls.setresuid.assert_not_called()
        resources.setrlimit.assert_not_called()
        return
    ns['restrict_child']()
    from unittest.mock import call
    assert calls.mock_calls[:2] == [call.prctl(38, 1, 0, 0, 0), call.prctl(8, 0, 0, 0, 0)]
    ordered = calls.mock_calls
    assert (ordered.index(call.open('/proc/self/oom_score_adj', 'w'))
            < ordered.index(call.setgroups([]))
            < ordered.index(call.setresgid(65532, 65532, 65532))
            < ordered.index(call.setresuid(65532, 65532, 65532)))
    assert ast.dump(restrict) == ast.dump(next(n for n in ast.parse(RUNNER).body
        if isinstance(n, ast.FunctionDef) and n.name == 'restrict_child'))
