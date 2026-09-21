import asyncio
import json
from types import SimpleNamespace

import pytest
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.util import ExecResult, OutputLimitExceededError

import coboleval.scoring as scoring


class FakeSandbox:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []
        self.requests = []
        self.paths = []
        self.key = bytes(range(32))

    async def exec(self, cmd, input=None, **kwargs):
        self.calls.append((cmd, dict(kwargs, input=input)))
        if cmd[-1] == scoring.SETUP:
            self.requests.append(json.loads(input))
            self.paths.append(f"/tmp/cjt-fresh_{len(self.paths) + 1}")
            return result(json.dumps({"cwd": self.paths[-1], "key": self.key.hex()}))
        if cmd == scoring.CLEANUP_COMMAND:
            return result("", returncode=1)
        if cmd in (scoring.QUIESCENCE_COMMAND, scoring.DIRECTORY_CLEANUP_COMMAND):
            return result("", returncode=0)
        response = next(self.results)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, str):
            # An untrusted response, e.g. forged provider completion status.
            return result(response)
        return result(signed_receipt(self.key, self.paths[-1], response.stdout,
                                     returncode=response.returncode))


def signed_receipt(key, cwd, output="2", **kwargs):
    import base64
    import hashlib
    import hmac
    body = json.dumps(dict(returncode=kwargs.get("returncode", 0),
                           timeout=kwargs.get("timeout", False),
                           overflow=kwargs.get("overflow", False), stage=kwargs.get("stage", "run"), cwd=cwd,
                           memory_exceeded=kwargs.get("memory_exceeded", False),
                           disk_exceeded=kwargs.get("disk_exceeded", False),
                           cleanup_failed=kwargs.get("cleanup_failed", False),
                           supervisor_error=kwargs.get("supervisor_error", False),
                           output=base64.b64encode(output if isinstance(output, bytes) else output.encode()).decode()))
    return json.dumps({"body": body, "tag": hmac.new(key, body.encode(), hashlib.sha256).hexdigest()})


def state(completion=None):
    if completion is None:
        completion = '```cobol\n       synthetic candidate\n```'
    return SimpleNamespace(sample_id="fixture", output=SimpleNamespace(completion=completion), metadata={})


def record(expected="2", test_input="PRIVATE_CALLER"):
    return dict(task_id="fixture", entry_point="fixture", prompt="PUBLIC_SKELETON",
                canonical_solution="PRIVATE_PYTHON_SOLUTION",
                tests=[dict(test=test_input, result=dict(value=expected, type_="Int")) for _ in range(2)])


@pytest.fixture(autouse=True)
def synthetic_records(monkeypatch):
    monkeypatch.setattr(scoring, "load_records", lambda: [record()])
    # No wall-clock waits in fake provider tests; Linux tests use real deadlines.
    async def no_sleep(delay):
        pass
    monkeypatch.setattr(scoring.asyncio, "sleep", no_sleep)


def install_sandbox(monkeypatch, fake):
    from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy
    monkeypatch.setattr(scoring, "sandbox", lambda: SandboxEnvironmentProxy(fake))


WITHHELD_ERROR = "Private sandbox operation failed; details withheld."


def assert_private_sandbox_error():
    with pytest.raises(RuntimeError) as raised:
        asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert str(raised.value) == WITHHELD_ERROR
    assert raised.value.args == (WITHHELD_ERROR,)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert raised.value.__suppress_context__ is True


def result(stdout="2", returncode=0):
    return ExecResult(success=returncode == 0, returncode=returncode, stdout=stdout, stderr="")


@pytest.mark.parametrize("outcome", ["correct", "runtime", "compile", "timeout", "overflow", "incomplete"])
def test_scorer_results_with_fake_sandbox(monkeypatch, outcome):
    fields = dict(stage='compile' if outcome in {'compile', 'incomplete'} else 'run',
                  returncode=1 if outcome in {'runtime', 'compile'} else 0,
                  timeout=outcome == 'timeout', overflow=outcome == 'overflow')
    response = signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1', **fields)
    responses = [response]
    if outcome == 'correct':
        responses.append(signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_2'))
    fake = FakeSandbox(responses)
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == (CORRECT if outcome == 'correct' else INCORRECT)
    compiled = 'yes' if outcome in {'correct', 'runtime', 'timeout', 'overflow', 'incomplete'} else 'no'
    assert f'Compiled: {compiled}' in score.explanation
    assert not score.metadata and not score.answer
    count = 2 if outcome == 'correct' else 1
    assert len(fake.calls) == count * 5
    assert len(set(fake.paths)) == count
    for setup, run, cleanup in zip(fake.calls[::5], fake.calls[1::5], fake.calls[2::5]):
        assert cleanup[0] == scoring.CLEANUP_COMMAND
        assert setup[0][:4] == ['timeout', '-s', 'KILL', '5s']
        assert run[0][:4] == ['timeout', '-s', 'KILL', '100s']
        assert run[1]['timeout'] == 100
        assert run[1]['timeout_retry'] is False
    for request in fake.requests:
        assert request['timeout'] == 60 and request['run_timeout'] == 30
        assert isinstance(request['argv'], list) and isinstance(request['run_argv'], list)
        assert 'bash' not in request['argv'] and 'sh' not in request['argv']


def test_every_cobol_test_must_pass(monkeypatch):
    fake = FakeSandbox([result(), result('9')])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT
    assert score.explanation.startswith('Test 2: wrong answer.')
    assert 'Compiled: yes' in score.explanation






def test_expected_cobol_output_stays_on_host(monkeypatch):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1', timeout=True)])
    install_sandbox(monkeypatch, fake)
    monkeypatch.setattr(scoring, 'load_records', lambda: [record(expected='"EXPECTED_SECRET"')])
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert 'EXPECTED_SECRET' not in json.dumps(fake.calls) + score.explanation


def test_empty_test_suite_is_an_error(monkeypatch):
    empty = record()
    empty['tests'] = []
    monkeypatch.setattr(scoring, 'load_records', lambda: [empty])
    with pytest.raises(RuntimeError, match='details withheld'):
        asyncio.run(scoring.coboleval_scorer()(state(), Target('')))


@pytest.mark.parametrize("failure", [ConnectionError("private connection details"),
                                     TimeoutError("private timeout details")])
def test_lost_supervisor_response_is_an_error(monkeypatch, failure):
    fake = FakeSandbox([failure])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


def test_output_limit_is_an_error(monkeypatch):
    fake = FakeSandbox([OutputLimitExceededError("fixture limit", None)])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()


@pytest.mark.parametrize("forgery", [
    "2<completed-sentinel-value-0>",
    signed_receipt(b"wrong key", "/tmp/cjt-fresh_1"),
    signed_receipt(bytes(range(32)), "/tmp/cjt-fresh_1").replace('run', 'compile'),
    '{"returncode":0,"output":"2"}',
], ids=['completion-marker', 'wrong-hmac-key', 'tampered-body', 'unsigned-receipt'])
def test_forged_completion_marker_or_receipt_is_an_error(monkeypatch, forgery):
    # A valid second response makes accidental acceptance score CORRECT instead
    # of hiding behind an exhausted iterator on the second caller.
    fake = FakeSandbox([forgery, result()])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()
    assert fake.paths == ['/tmp/cjt-fresh_1']  # No second setup after rejection.
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


def test_marker_inside_captured_candidate_output_cannot_hide_failure(monkeypatch):
    fake = FakeSandbox([result("2<completed-sentinel-value-0>", returncode=1)])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target("")))
    assert score.value == INCORRECT
    assert "run error (exit 1)" in score.explanation


def test_provider_really_strips_the_forged_marker():
    execute = pytest.importorskip("k8s_sandbox._pod.execute")
    output, status = execute.ExecuteOperation._filter_sentinel_and_returncode(
        None, b"2<completed-sentinel-value-0>"
    )
    assert output == b"2" and status == 0


@pytest.mark.parametrize("field,value", [("timeout", True), ("overflow", True), ("returncode", 137)])
def test_authenticated_failure_channels(monkeypatch, field, value):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), "/tmp/cjt-fresh_1", **{field: value})])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target("")))
    assert score.value == INCORRECT


def test_setup_timeout_is_bounded_and_errors(monkeypatch):
    class HungSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd in (scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND, scoring.DIRECTORY_CLEANUP_COMMAND):
                return await super().exec(cmd, **kwargs)
            assert cmd[:4] == ["timeout", "-s", "KILL", "5s"]
            assert kwargs["timeout"] == 5
            raise TimeoutError("private material")
    install_sandbox(monkeypatch, HungSetup([]))
    assert_private_sandbox_error()


@pytest.mark.parametrize('response', [result(), result('3'), result(returncode=7), '',
                                      TimeoutError(), ConnectionError(),
                                      OutputLimitExceededError('synthetic', None)])
def test_uid_cleanup_is_a_separate_exec_on_every_run_outcome(monkeypatch, response):
    fake = FakeSandbox([response, response])
    install_sandbox(monkeypatch, fake)
    if isinstance(response, Exception) or response == '':
        assert_private_sandbox_error()
    else:
        asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    runs = [i for i, (cmd, _) in enumerate(fake.calls) if scoring.RUNNER in cmd]
    assert runs
    for index in runs:
        cmd, kwargs = fake.calls[index + 1]
        assert cmd == scoring.CLEANUP_COMMAND
        assert cmd[-4:] == ['/usr/bin/pkill', '-KILL', '-u', '65532']
        assert kwargs['input'] is None and kwargs['cwd'] == '/'
        assert kwargs['timeout'] == 5 and kwargs['timeout_retry'] is False


def test_missing_receipt_waits_through_host_deadline_before_uid_sweep(monkeypatch):
    events = []

    async def wait(delay):
        assert 104 <= delay <= 105  # compile + run + supervisor overhead + host grace
        events.append('deadline')

    class MissingSupervisor(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.CLEANUP_COMMAND:
                assert events == ['deadline']
                events.append('sweep')
            return await super().exec(cmd, **kwargs)

    monkeypatch.setattr(scoring.asyncio, 'sleep', wait)
    fake = MissingSupervisor([''])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()
    assert events == ['deadline', 'sweep']


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError(), result('', returncode=2)])
def test_cleanup_failure_aborts_before_next_test(monkeypatch, failure):
    class FailedCleanup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.CLEANUP_COMMAND:
                self.calls.append((cmd, kwargs))
                if isinstance(failure, Exception):
                    raise failure
                return failure
            return await super().exec(cmd, **kwargs)

    fake = FailedCleanup([result()])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT
    assert "candidate left processes that could not be cleaned up" in score.explanation
    assert len(fake.paths) == 1
    assert fake.calls[-1][0] == scoring.CLEANUP_COMMAND


def test_scorer_cancellation_still_awaits_independent_uid_sweep(monkeypatch):
    class CancelledRun(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.RUNNER in cmd:
                raise asyncio.CancelledError()
            return await super().exec(cmd, **kwargs)

    fake = CancelledRun([])
    install_sandbox(monkeypatch, fake)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError(),
                                     OutputLimitExceededError('private setup output', None)])
def test_setup_failure_also_issues_uid_cleanup(monkeypatch, failure):
    class FailedSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.SETUP in cmd:
                raise failure
            return await super().exec(cmd, **kwargs)

    fake = FailedSetup([])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


def test_cleanup_requires_quiescence_before_reusing_sandbox(monkeypatch):
    class StillRunning(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.QUIESCENCE_COMMAND:
                self.calls.append((cmd, kwargs))
                return result('', returncode=2)
            return await super().exec(cmd, **kwargs)
    fake = StillRunning([result()])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT
    assert "candidate left processes that could not be cleaned up" in score.explanation
    assert len(fake.paths) == 1
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


def test_receipt_for_another_directory_is_an_error(monkeypatch):
    # The signature is valid; only binding to this caller's directory rejects it.
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/cjt-other'), result()])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()
    assert fake.paths == ['/tmp/cjt-fresh_1']  # No second setup after rejection.
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


@pytest.mark.parametrize('operation', [scoring.SETUP, scoring.RUNNER], ids=['setup', 'runner'])
def test_exec_that_never_returns_is_bounded_and_errors(monkeypatch, operation):
    timeout = asyncio.timeout
    monkeypatch.setattr(scoring.asyncio, 'timeout', lambda delay: timeout(0.01))

    class HungExec(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if operation in cmd:
                self.calls.append((cmd, kwargs))
                await asyncio.Event().wait()
            return await super().exec(cmd, **kwargs)

    fake = HungExec([])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()
    assert fake.calls[-3][0] == scoring.CLEANUP_COMMAND
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


@pytest.mark.parametrize('response', [
    '',
    signed_receipt(b'wrong key', '/tmp/cjt-fresh_1'),
    signed_receipt(bytes(range(32)), '/tmp/cjt-other'),
    TimeoutError('PRIVATE_EXCEPTION_STDIN_STDOUT_STDERR'),
    OutputLimitExceededError('PRIVATE_EXCEPTION_STDIN_STDOUT_STDERR', None),
], ids=['missing', 'bad-signature', 'wrong-cwd', 'exec-timeout', 'output-limit'])
def test_receipt_rejection_is_an_inspect_sample_error(monkeypatch, tmp_path, response):
    from inspect_ai import Task, eval
    from inspect_ai._util import appdirs
    from inspect_ai.dataset import Sample
    from inspect_ai.model import ModelOutput, get_model

    monkeypatch.setattr(appdirs, 'user_data_path', lambda package: tmp_path / 'data')
    monkeypatch.setattr(appdirs, 'user_cache_path', lambda package: tmp_path / 'cache')
    fake = FakeSandbox([response])
    install_sandbox(monkeypatch, fake)
    task = Task(dataset=[Sample(id='fixture', input='Public prompt')],
                scorer=scoring.coboleval_scorer())
    model = get_model('mockllm/model', custom_outputs=[
        ModelOutput.from_content('mockllm/model', state().output.completion),
    ])
    log, = eval(task, model=model, log_dir=str(tmp_path), display='none',
                fail_on_error=False)
    sample, = log.samples
    assert sample.error is not None
    # Inspect stores repr(exception); the scorer exception itself has the exact
    # message asserted by assert_private_sandbox_error above.
    assert sample.error.message == repr(RuntimeError(WITHHELD_ERROR))
    assert not sample.scores
    for secret in ('PRIVATE_EXCEPTION_STDIN_STDOUT_STDERR', 'PRIVATE_CALLER',
                   'PRIVATE_PYTHON_SOLUTION', 'synthetic candidate'):
        assert secret not in sample.error.model_dump_json()
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


@pytest.mark.parametrize('completion', ['no code', '    indented source'])
def test_missing_fence_never_starts_sandbox(monkeypatch, completion):
    def forbidden():
        raise AssertionError('No sandbox should be requested')
    monkeypatch.setattr(scoring, 'sandbox', forbidden)
    score = asyncio.run(scoring.coboleval_scorer()(state(completion), Target('')))
    assert score.value == INCORRECT
    assert 'Compiled: not attempted' in score.explanation


@pytest.mark.parametrize('whole_program', [False, True])
def test_scorer_assembles_first_fence_with_record_prompt(monkeypatch, whole_program):
    from coboleval.cleaning import construct
    from test_cleaning import PROMPT
    fixture = record()
    fixture['prompt'] = PROMPT
    monkeypatch.setattr(scoring, 'load_records', lambda: [fixture])
    source = (PROMPT if whole_program else '') + '       PROCEDURE DIVISION.\n           GOBACK.\n'
    fake = FakeSandbox([result(), result()])
    install_sandbox(monkeypatch, fake)
    completion = '```\n' + source + '```\n```cobol\nIGNORED_SECOND_BLOCK\n```'
    score = asyncio.run(scoring.coboleval_scorer()(state(completion), Target('')))
    assert score.value == CORRECT
    assert len(fake.requests) == 2
    for request in fake.requests:
        assert request['files']['solution.cbl'] == construct(PROMPT, source)
        assert 'IGNORED_SECOND_BLOCK' not in request['files']['solution.cbl']


def test_compile_success_with_excess_output_is_still_incorrect(monkeypatch):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1',
                                      stage='compile', returncode=0, overflow=True)])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT
    assert 'Compiled: yes' in score.explanation


def resign(fields, key=bytes(range(32))):
    import hashlib
    import hmac
    body = json.dumps(fields)
    return json.dumps(dict(body=body, tag=hmac.new(key, body.encode(), hashlib.sha256).hexdigest()))


@pytest.mark.parametrize('output', [b'\xff', b'good\xffbad'])
def test_authenticated_non_utf8_is_incorrect(monkeypatch, output):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1', output)])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT
    assert 'output not decodable' in score.explanation
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND


@pytest.mark.parametrize('output', [None, 42, [], {}, '\u2603', '%%%','/w=='])
def test_candidate_output_shape_does_not_invalidate_authentication(monkeypatch, output):
    fields = json.loads(json.loads(signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1'))['body'])
    fields['output'] = output
    response = resign(fields)
    assert scoring.verify_receipt(response, bytes(range(32)))['output_error']
    assert scoring.verify_receipt(response, b'bad key') is None
    fake = FakeSandbox([response])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT and 'output not decodable' in score.explanation


def test_missing_output_is_authenticated_failure():
    fields = json.loads(json.loads(signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1'))['body'])
    del fields['output']
    assert scoring.verify_receipt(resign(fields), bytes(range(32)))['output_error']


@pytest.mark.parametrize('field,value', [('stage', []), ('stage', 'other'), ('returncode', True),
    ('timeout', 0), ('overflow', None), ('cwd', '/tmp/other'), ('cwd', []),
    ('cleanup_failed', 'yes'), ('supervisor_error', 1), ('memory_exceeded', 1), ('disk_exceeded', 1), ('disk_exceeded', None), ('disk_exceeded', 'yes')])
def test_supervisor_fields_still_require_strict_shapes(field, value):
    fields = json.loads(json.loads(signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1'))['body'])
    fields[field] = value
    assert scoring.verify_receipt(resign(fields), bytes(range(32))) is None


@pytest.mark.parametrize('flag', ['cleanup_failed', 'supervisor_error', 'memory_exceeded', 'disk_exceeded'])
def test_signed_post_run_failure_is_incorrect_and_independently_cleaned(monkeypatch, flag):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1', **{flag: True})])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT
    assert fake.calls[-3][0] == scoring.CLEANUP_COMMAND
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND
    assert len(fake.paths) == 1


@pytest.mark.parametrize('cleanup_command', [scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND,
                                           scoring.DIRECTORY_CLEANUP_COMMAND],
                         ids=['uid-sweep', 'quiescence', 'deletion'])
@pytest.mark.parametrize('outcome', ['signed-failure', 'signed-success', 'wrong-answer', 'no-receipt'])
@pytest.mark.parametrize('cleanup_error', [False, True], ids=['nonzero', 'timeout'])
def test_verdict_is_resolved_before_independent_cleanup(monkeypatch, cleanup_command, outcome, cleanup_error):
    events = []
    original = scoring.receipt_failure
    def verdict(receipt):
        events.append('verdict')
        return original(receipt)
    monkeypatch.setattr(scoring, 'receipt_failure', verdict)

    class FailedCleanup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == cleanup_command:
                events.append('cleanup')
                if cleanup_error:
                    raise TimeoutError('PRIVATE cleanup failure')
                return result('', returncode=2)
            return await super().exec(cmd, **kwargs)

    response = '' if outcome == 'no-receipt' else signed_receipt(
        bytes(range(32)), '/tmp/cjt-fresh_1',
        output='9' if outcome == 'wrong-answer' else '2', timeout=outcome == 'signed-failure')
    fake = FailedCleanup([response])
    install_sandbox(monkeypatch, fake)
    if outcome == 'no-receipt':
        assert_private_sandbox_error()
        assert events == ['cleanup']
    else:
        score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
        assert score.value == INCORRECT
        explanation = {'signed-failure': 'run timeout', 'wrong-answer': 'wrong answer',
                       'signed-success': 'candidate left processes that could not be cleaned up'}[outcome]
        assert explanation in score.explanation
        assert events == ['verdict', 'cleanup']
    assert len(fake.paths) == 1


def test_last_passing_test_with_failed_cleanup_is_incorrect(monkeypatch):
    single = record()
    single['tests'] = single['tests'][:1]
    monkeypatch.setattr(scoring, 'load_records', lambda: [single])
    class FailedCleanup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.QUIESCENCE_COMMAND:
                return result('', returncode=2)
            return await super().exec(cmd, **kwargs)
    install_sandbox(monkeypatch, FailedCleanup([result()]))
    score = asyncio.run(scoring.coboleval_scorer()(state(), Target('')))
    assert score.value == INCORRECT
    assert 'candidate left processes that could not be cleaned up' in score.explanation


@pytest.mark.parametrize('valid_json', [False, True])
def test_nonzero_setup_is_withheld_harness_error_and_never_launches_candidate(monkeypatch, valid_json):
    class FailedPrerequisites(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.SETUP in cmd:
                self.calls.append((cmd, kwargs))
                stdout = json.dumps({'cwd': '/tmp/cjt-probe', 'key': self.key.hex()}) if valid_json else ''
                return result(stdout, returncode=1)
            assert scoring.RUNNER not in cmd
            return await super().exec(cmd, **kwargs)
    fake = FailedPrerequisites([])
    install_sandbox(monkeypatch, fake)
    assert_private_sandbox_error()
    assert fake.calls[-1][0] == scoring.DIRECTORY_CLEANUP_COMMAND
