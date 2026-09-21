"""Safe diagnostics and nested Docker orchestration without host containment."""
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from scripts import linux_regressions as regression


SECRET = 'candidate bytes / private receipt key / exception text'


def receipt(*, stage='run', returncode=0, output='ok', **flags):
    return dict(stage=stage, returncode=returncode, output=output,
                **{flag: flags.get(flag, False) for flag in regression.FLAGS})


def records(capsys):
    captured = capsys.readouterr()
    assert not captured.err
    assert SECRET not in captured.out
    return [json.loads(line) for line in captured.out.splitlines()]


@pytest.mark.parametrize(('stage', 'returncode', 'label'), [
    ('compile', 1, 'compile-completed'),
    ('run', 1, 'smoke-succeeded'),
    ('run', 0, 'smoke-output'),
])
def test_smoke_names_compile_run_and_output_failures(monkeypatch, capsys, stage, returncode, label):
    def invoke(request):
        assert set(request['files']) == {'smoke.cbl'}
        assert 'program-id. smoke.' in request['files']['smoke.cbl']
        assert request['argv'] == ['cobc', '-x', '-o', 'smoke', 'smoke.cbl']
        assert request['run_argv'] == ['./smoke']
        return receipt(stage=stage, returncode=returncode, output=SECRET)

    monkeypatch.setattr(regression, 'invoke', invoke)
    monkeypatch.setattr(regression, 'main', regression.cobol_smoke)
    assert regression.entrypoint() == 1
    assert records(capsys) == [dict(stage='regression', step='cobol_smoke',
                                   error='AssertionError', label=label,
                                   returncode=1, flags={'failed': True})]


@pytest.mark.parametrize('error', [
    AssertionError(SECRET),
    subprocess.TimeoutExpired(SECRET, 1, output=SECRET.encode(), stderr=SECRET.encode()),
    OSError(SECRET),
])
def test_exception_class_without_exception_text(monkeypatch, capsys, error):
    def invoke(request):
        raise error

    monkeypatch.setattr(regression, 'invoke', invoke)
    monkeypatch.setattr(regression, 'main', regression.cobol_smoke)
    assert regression.entrypoint() == 1
    report, = records(capsys)
    assert report['step'] == 'cobol_smoke'
    assert report['error'] == type(error).__name__
    assert report['label'] == 'unexpected-error'


def test_assertion_message_cannot_supply_a_label():
    assert regression.failure_report(AssertionError('compile-completed'))['label'] == 'unexpected-error'
    with pytest.raises(AssertionError) as raised:
        regression.require(False, SECRET)
    assert regression.failure_report(raised.value)['label'] == 'unexpected-error'


@pytest.mark.parametrize('fault', [None, 'case', 'smoke'])
def test_child_emits_case_flags_before_checks_and_summary(monkeypatch, capsys, fault):
    case_index = 0

    def invoke(request):
        nonlocal case_index
        if request['files']:
            return receipt(stage='compile' if fault == 'smoke' and case_index == 2 else 'run',
                           output='ok')
        name = regression.NESTED_CASES[case_index]
        case_index += 1
        code = 0 if name == 'detached_child' else 1 if name in {'readonly_shm', 'ptrace_denied'} else -9
        if fault == 'case' and name == 'disk':
            code = 0
        return receipt(returncode=code, output={'disk': 'disk-direct-tmp', 'ptrace_denied': 'ptrace-denied'}.get(name, SECRET),
                       memory_exceeded=name == 'memory_aggregate', disk_exceeded=name in regression.CASES['DISK_CASES'])

    monkeypatch.setattr(regression, 'invoke', invoke)
    monkeypatch.setattr(regression.sys, 'argv', ['linux_regressions.py', '--memory-child'])
    monkeypatch.setattr(regression.sys, 'platform', 'linux')
    monkeypatch.setattr(regression.os, 'geteuid', lambda: 0)
    assert regression.entrypoint() == (0 if fault is None else 1)
    output = records(capsys)
    cases = output[:-1]
    assert [item['case'] for item in cases] == list(regression.NESTED_CASES[:len(cases)])
    assert all(set(item) == {'case', 'flags'} and regression.valid_flags(item['flags']) for item in cases)
    if fault is None:
        assert len(cases) == len(regression.NESTED_CASES)
        assert output[-1] == {item['case']: item['flags'] for item in cases}
    else:
        assert len(cases) == 2
        assert output[-1]['step'] == ('disk' if fault == 'case' else 'cobol_smoke')
        assert output[-1]['label'] == ('expected-receipt' if fault == 'case' else 'compile-completed')


@pytest.fixture
def outer(monkeypatch):
    monkeypatch.setattr(regression.sys, 'argv', [
        'linux_regressions.py', '--image', 'synthetic-image', '--docker-cli', '/workspace/bin/docker'])
    monkeypatch.setattr(regression.sys, 'platform', 'linux')
    monkeypatch.setattr(regression.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regression.shutil, 'which', lambda name: None)
    monkeypatch.setattr(regression, 'cobol_smoke', lambda: None)
    monkeypatch.setattr(regression, 'failure_case', lambda code: {'flags': {}})


def nested_records():
    return [{'case': name, 'flags': {flag: (flag == 'memory_exceeded' and name == 'memory_aggregate')
                                    or (flag == 'disk_exceeded' and name in regression.CASES['DISK_CASES'])
                                    for flag in regression.FLAGS}}
            for name in regression.NESTED_CASES]


@pytest.mark.parametrize('failed', [False, True])
def test_outer_relays_child_json_lines_even_on_failure(monkeypatch, capsys, outer, failed):
    child = nested_records()
    if failed:
        child = child[:1] + [dict(stage='regression', step='disk', error='AssertionError',
                                 label='setup-completed', returncode=1, flags={'failed': True})]
    else:
        child.append({item['case']: item['flags'] for item in child})

    def captured(command, *, timeout):
        assert command[0] == '/workspace/bin/docker'
        assert command[-1] == '--memory-child'
        return SimpleNamespace(returncode=int(failed), stderr=SECRET.encode(),
                               stdout='\n'.join(json.dumps(item) for item in child).encode())

    monkeypatch.setattr(regression, 'captured', captured)
    assert regression.entrypoint() == int(failed)
    output = records(capsys)[2:]
    assert output[:len(child)] == child
    if failed:
        assert output[-1]['step'] == 'docker'
        assert output[-1]['label'] == 'docker-completed'
    else:
        assert len(output) == len(child)


@pytest.mark.parametrize('fault', ['text', 'flag', 'extra', 'label', 'class', 'missing-summary'])
def test_outer_rejects_unsafe_or_incomplete_child_output(monkeypatch, capsys, outer, fault):
    child = nested_records()[:1]
    if fault == 'text':
        data = SECRET.encode()
    else:
        if fault == 'flag':
            child[0]['flags']['output_error'] = SECRET
        elif fault == 'extra':
            child[0]['output'] = SECRET
        elif fault in ('label', 'class'):
            child = [dict(stage='regression', step='disk', error='AssertionError',
                          label='setup-completed', returncode=1, flags={'failed': True})]
            child[0]['label' if fault == 'label' else 'error'] = SECRET
        data = '\n'.join(json.dumps(item) for item in child).encode()
    monkeypatch.setattr(regression, 'captured', lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=data, stderr=SECRET.encode()))
    assert regression.entrypoint() == 1
    output = records(capsys)
    assert output[-1]['step'] == 'docker'
    assert output[-1]['label'] in {'unexpected-error', 'docker-output', 'docker-summary'}


def test_explicit_missing_cli_fails_without_prlimit_fallback(monkeypatch, capsys, outer):
    def captured(*args, **kwargs):
        raise FileNotFoundError(SECRET)

    monkeypatch.setattr(regression, 'captured', captured)
    assert regression.entrypoint() == 1
    report = records(capsys)[-1]
    assert report['step'] == 'docker'
    assert report['error'] == 'FileNotFoundError'


def test_cloud_build_passes_the_copied_cli_explicitly():
    path = Path(regression.__file__).with_name('cloudbuild-linux-regressions.yaml')
    config = yaml.safe_load(path.read_text())
    script = config['steps'][0]['args'][-1]
    cli = '/workspace/.linux-regressions-bin/docker'
    assert f'cp "$$(command -v docker)" {cli}' in script
    assert f'--docker-cli {cli}' in script
    assert '--image' in script and '/var/run/docker.sock' in script
    assert '--read-only --mount type=volume,target=/tmp --tmpfs /dev/shm:ro,size=16m' in script
    command = regression.docker_command('synthetic-image', cli)
    assert command[0] == cli
    assert '--read-only' in command and 'type=volume,target=/tmp' in command
    assert command[command.index('--tmpfs') + 1] == '/dev/shm:ro,size=16m'
    assert 'dir="/tmp"' in regression.SUPERVISOR['SETUP']


def test_docker_and_cloudbuild_capabilities_match_production():
    command = regression.docker_command('synthetic-image')
    script = Path(regression.__file__).with_name('cloudbuild-linux-regressions.yaml').read_text()
    expected = {'SETUID', 'SETGID', 'KILL', 'CHOWN', 'DAC_OVERRIDE', 'SYS_PTRACE'}
    assert {arg.split('=', 1)[1] for arg in command if arg.startswith('--cap-add=')} == expected
    assert '--cap-drop=ALL' in command and '--cap-drop=ALL' in script
    assert '--security-opt=no-new-privileges:true' in command
    for capability in expected:
        assert '--cap-add=' + capability in script
    assert 'ptrace_denied' in regression.NESTED_CASES
