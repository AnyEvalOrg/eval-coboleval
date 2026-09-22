"""Offline kernel attribution; no cluster, credentials, or candidate execution."""
import asyncio
from types import SimpleNamespace as NS
from threading import Event
import time

import pytest
from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

from coboleval import sandbox_state as status


def pod(*, reason=None, last_reason=None, phase='Running', pod_reason=None,
        message=None, uid='sample-uid', container='default', exit_code=None, signal=None,
        last_exit_code=None, last_signal=None, termination_message=None):
    def state(reason, code, signal):
        return NS(terminated=NS(reason=reason, exit_code=code, signal=signal,
                                message=termination_message)
                  if any(value is not None for value in (reason, code, signal)) else None)
    return NS(metadata=NS(uid=uid), status=NS(
        phase=phase, reason=pod_reason, message=message,
        container_statuses=[NS(name=container, state=state(reason, exit_code, signal),
                              last_state=state(last_reason, last_exit_code, last_signal))]))


@pytest.mark.parametrize('kwargs,expected', [
    ({'reason': 'OOMKilled', 'phase': 'Failed'}, status.MEMORY_EXHAUSTED),
    ({'last_reason': 'OOMKilled'}, status.MEMORY_EXHAUSTED),
    ({'phase': 'Failed', 'pod_reason': 'Evicted',
      'message': 'Pod ephemeral-storage usage exceeds the total limit of containers'}, status.STORAGE_EXHAUSTED),
    ({'phase': 'Failed', 'pod_reason': 'Evicted',
      'message': 'Container default exceeded its local ephemeral-storage limit'}, status.STORAGE_EXHAUSTED),
    ({'phase': 'Failed', 'pod_reason': 'Evicted', 'message': 'The node was low on resource: ephemeral-storage.'}, None),
    ({'phase': 'Failed', 'pod_reason': 'Evicted', 'message': 'node pressure: memory'}, None),
    ({'phase': 'Failed', 'pod_reason': 'Evicted', 'message': 'DiskPressure: ephemeral-storage'}, None),
    ({'phase': 'Failed', 'pod_reason': 'Evicted', 'message': None}, None),
    ({'phase': 'Failed', 'pod_reason': 'Preempted', 'message': 'Spot preemption'}, None),
    ({'phase': 'Unknown', 'pod_reason': 'NodeNotReady'}, None),
    ({'phase': 'Failed', 'pod_reason': 'Shutdown'}, None),
    ({'reason': 'Error'}, None),
    ({'reason': 'Completed'}, None),
    ({}, None),  # Running, no termination: includes exec transport/timeout loss.
    ({'message': 'OOMKilled ephemeral-storage'}, None),  # Text alone is not evidence.
])
def test_classify_pod(kwargs, expected):
    assert status.classify_pod(pod(**kwargs)) == expected


def test_missing_pod_status_and_container_statuses():
    assert status.classify_pod(None) is None
    value = pod()
    value.status.container_statuses = None
    assert status.classify_pod(value) is None
    value.status = None
    assert status.classify_pod(value) is None


def test_sidecar_oom_is_not_candidate_container():
    assert status.classify_pod(pod(reason='OOMKilled', container='sidecar'), 'default') is None


@pytest.mark.parametrize('termination', [
    {'reason': 'Error', 'exit_code': 137}, {'reason': 'Error', 'signal': 9},
    {'last_reason': 'Error', 'last_exit_code': 137}, {'last_signal': 9},
])
@pytest.mark.parametrize('guard', ['same', 'replacement', 'no_identity', 'evicted', 'sidecar'])
def test_sigkill_requires_same_pod_and_non_evicted_candidate_container(termination, guard):
    value = pod(**termination, pod_reason='Evicted' if guard == 'evicted' else None,
                container='sidecar' if guard == 'sidecar' else 'default')
    uid = {'replacement': 'other-uid', 'no_identity': None}.get(guard, 'sample-uid')
    assert status.classify_pod(value, 'default', expected_uid=uid) == (
        status.MEMORY_EXHAUSTED if guard == 'same' else None)


@pytest.mark.parametrize('phase', ['Running', 'Unknown'])
def test_node_not_ready_without_termination_is_infrastructure(phase):
    assert status.classify_pod(pod(phase=phase, pod_reason='NodeNotReady'),
                               expected_uid='sample-uid') is None


@pytest.fixture
def environment():
    provider = pytest.importorskip('k8s_sandbox._sandbox_environment')
    env = object.__new__(provider.K8sSandboxEnvironment)
    env._pod = NS(info=NS(name='sample-default', namespace='sample-namespace',
                         context_name='sample-context', uid='sample-uid', default_container_name='default'))
    return SandboxEnvironmentProxy(env)


def test_identity_is_provider_identity_and_survives_cache_refresh(environment):
    identity = status.sandbox_identity(environment)
    assert identity == status.PodIdentity('sample-default', 'sample-namespace', 'sample-context',
                                          'sample-uid', 'default')
    environment._sandbox._pod.info.uid = 'replacement'
    assert identity.uid == 'sample-uid'
    assert status.sandbox_identity(object()) is None


@pytest.mark.parametrize('outcome', ['oom', 'sigkill', 'signal', 'storage', 'gone', 'forbidden',
                                     'connection', 'replaced', 'replaced_sigkill', 'running'])
def test_lookup_uses_provider_client_and_exact_identity(monkeypatch, environment, outcome, capsys):
    api = pytest.importorskip('k8s_sandbox._kubernetes_api')
    calls = []
    def read(**kwargs):
        calls.append(kwargs)
        if outcome in {'gone', 'forbidden'}:
            from kubernetes.client.exceptions import ApiException
            raise ApiException(status=404 if outcome == 'gone' else 403,
                               reason='PRIVATE API body or credential error')
        if outcome == 'connection':
            raise RuntimeError('PRIVATE API body or credential error')
        if outcome == 'storage':
            return pod(phase='Failed', pod_reason='Evicted', message='ephemeral-storage limit exceeded')
        return pod(reason='OOMKilled' if outcome in {'oom', 'replaced'} else None,
                   exit_code=137 if outcome in {'sigkill', 'replaced_sigkill'} else None,
                   signal=9 if outcome == 'signal' else None,
                   uid='replacement' if outcome in {'replaced', 'replaced_sigkill'} else 'sample-uid')
    def client(context):
        assert context == 'sample-context'
        return NS(read_namespaced_pod=read)
    monkeypatch.setattr(api, 'k8s_client', client)
    evidence = {}
    failure = asyncio.run(status.sandbox_failure(environment, evidence=evidence,
                                                runner_failed_at=time.monotonic() - 2))
    assert failure == {'oom': status.MEMORY_EXHAUSTED, 'sigkill': status.MEMORY_EXHAUSTED,
                       'signal': status.MEMORY_EXHAUSTED, 'storage': status.STORAGE_EXHAUSTED}.get(outcome)
    assert evidence['lookup_failed'] == (outcome in {'gone', 'forbidden', 'connection'})
    assert evidence['pod_gone'] == (outcome == 'gone')
    assert evidence['exception_class'] == (
        'ApiException' if outcome in {'gone', 'forbidden'} else
        'RuntimeError' if outcome == 'connection' else None)
    assert evidence['runner_failure_to_lookup_seconds'] >= 2
    assert 'PRIVATE' not in str(evidence)
    assert calls == [dict(name='sample-default', namespace='sample-namespace', _request_timeout=(1, 1))]
    assert capsys.readouterr().out == ''


def test_evidence_is_from_single_classified_lookup_and_allowlists_kubelet_fields(monkeypatch, environment):
    api = pytest.importorskip('k8s_sandbox._kubernetes_api')
    value = pod(reason='Error', exit_code=137, signal=9, last_reason='Completed',
                last_exit_code=0, phase='Failed', pod_reason='Test', message='k' * 250,
                termination_message='t' * 250)
    value.status.container_statuses += pod(container='sidecar').status.container_statuses
    value.spec = 'PRIVATE full pod'
    calls = []
    def read(**kwargs):
        calls.append(kwargs)
        assert len(calls) == 1
        return value
    monkeypatch.setattr(api, 'k8s_client', lambda context: NS(read_namespaced_pod=read))
    evidence = {}
    assert asyncio.run(status.sandbox_failure(environment, evidence=evidence)) == status.MEMORY_EXHAUSTED
    assert evidence['uid_matches'] is True
    assert evidence['pod'] == {
        'phase': 'Failed', 'reason': 'Test', 'message': 'k' * 200,
        'containerStatuses': [
            {'name': 'default',
             'state': {'terminated': {'reason': 'Error', 'exitCode': 137, 'signal': 9, 'message': 't' * 200}},
             'lastState': {'terminated': {'reason': 'Completed', 'exitCode': 0, 'signal': None, 'message': 't' * 200}}},
            {'name': 'sidecar', 'state': {'terminated': None}, 'lastState': {'terminated': None}},
        ],
    }


@pytest.mark.parametrize('diagnostics', [False, True])
def test_lookup_bound_includes_stuck_auth_and_loop_shutdown(monkeypatch, environment, diagnostics):
    release = Event()
    started = Event()
    finished = Event()
    def stuck(identity, evidence=None):
        started.set()
        release.wait(5)
        if evidence is not None:
            evidence['pod'] = {'message': 'late evidence'}
        finished.set()
        return status.MEMORY_EXHAUSTED
    monkeypatch.setattr(status, '_read_failure', stuck)
    monkeypatch.setattr(status, 'LOOKUP_TIMEOUT', 0.02)
    before = time.monotonic()
    evidence = {} if diagnostics else None
    try:
        assert asyncio.run(status.sandbox_failure(environment, evidence=evidence,
                                                 runner_failed_at=before - 2)) is None
        assert started.is_set()
        assert time.monotonic() - before < 0.5
        if diagnostics:
            assert evidence['lookup_failed'] is True
            assert evidence['exception_class'] == 'TimeoutError'
            assert evidence['pod_gone'] is False
            assert evidence['runner_failure_to_lookup_seconds'] >= 2
    finally:
        release.set()
    assert finished.wait(0.5)
    if diagnostics:
        assert evidence['pod'] is None


def test_lookup_thread_inherits_private_log_suppression(monkeypatch, environment, caplog):
    import logging
    from coboleval.publication import private_grading
    def read(identity):
        logging.getLogger('kubernetes.client.rest').warning('PRIVATE pod response')
        raise ValueError('PRIVATE error')
    monkeypatch.setattr(status, '_read_failure', read)
    with private_grading(environment) as private:
        assert asyncio.run(status.sandbox_failure(private)) is None
    assert 'PRIVATE' not in caplog.text


def test_failed_initial_identity_is_not_recaptured(monkeypatch):
    def forbidden(environment):
        pytest.fail('Must not recapture identity after a failed RUNNER')
    monkeypatch.setattr(status, 'sandbox_identity', forbidden)
    evidence = {}
    assert asyncio.run(status.sandbox_failure(object(), identity=None, evidence=evidence)) is None
    assert evidence['identity_available'] is False
    assert evidence['pod'] is None
    assert evidence['lookup_failed'] is False
    assert evidence['runner_failure_to_lookup_seconds'] is None
