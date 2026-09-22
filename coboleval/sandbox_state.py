"""Kernel-attributed backstop for missing receipts (inspect-k8s-sandbox 0.13.0).

Watchdogs preserve receipts for common sinks; they cannot enumerate all kernel
memory. Only Kubernetes resource-exhaustion evidence can replace a lost receipt.
Production scoring returns only fixed verdicts. Operator regressions can opt in
to allowlisted Kubernetes evidence; API bodies and exception text never escape.
"""
from __future__ import annotations

import asyncio
import re
import time
from contextvars import copy_context
from dataclasses import dataclass
from threading import Thread
from types import EllipsisType

from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

MEMORY_EXHAUSTED = 'sandbox memory exhausted during candidate execution'
STORAGE_EXHAUSTED = 'sandbox storage exhausted during candidate execution'
LOOKUP_TIMEOUT = 3.0


@dataclass(frozen=True)
class PodIdentity:
    name: str
    namespace: str
    context_name: str | None
    uid: str
    container: str


def sandbox_identity(environment) -> PodIdentity | None:
    """Capture before RUNNER: the provider may refresh its cached pod identity."""
    try:
        from k8s_sandbox._sandbox_environment import K8sSandboxEnvironment

        if isinstance(environment, SandboxEnvironmentProxy):
            environment = environment._sandbox
        if not isinstance(environment, K8sSandboxEnvironment):
            return None
        info = environment._pod.info
        return PodIdentity(info.name, info.namespace, info.context_name,
                           info.uid, info.default_container_name)
    except Exception:
        return None


def classify_pod(pod, container: str | None = None, *, expected_uid: str | None = None) -> str | None:
    """Classify Kubernetes V1Pod objects; all ambiguous states are infrastructure."""
    status = getattr(pod, 'status', None)
    if status is None:
        return None
    for entry in status.container_statuses or ():
        if container is not None and entry.name != container:
            continue
        for state in (entry.state, entry.last_state):
            terminated = getattr(state, 'terminated', None)
            if getattr(terminated, 'reason', None) == 'OOMKilled':
                return MEMORY_EXHAUSTED
            # A host-cgroup kill of runsc can reach containerd as Error/137,
            # without OOMKilled. Require actual container termination on the
            # captured pod, never the exec return code. Spot deletion (404) and
            # NodeNotReady (Running/Unknown without termination) give no verdict.
            if (terminated is not None and status.reason != 'Evicted'
                    and expected_uid
                    and getattr(getattr(pod, 'metadata', None), 'uid', None) == expected_uid
                    and (getattr(terminated, 'exit_code', None) == 137
                         or getattr(terminated, 'signal', None) == 9)):
                return MEMORY_EXHAUSTED
    if status.phase == 'Failed' and status.reason == 'Evicted':
        message = (status.message or '').lower()
        # Node-wide disk pressure is infrastructure even if its message names
        # ephemeral-storage; a pod/container storage budget eviction is distinct.
        if ('ephemeral-storage' in message
                and not re.search(r'\b(node|nodefs|diskpressure|memorypressure|pidpressure)\b', message)):
            return STORAGE_EXHAUSTED
    return None


def _pod_evidence(pod) -> dict:
    """Allowlist kubelet status text, never exec output or full API objects."""
    status = getattr(pod, 'status', None)

    def message(value):
        return value[:200] if isinstance(value, str) else None

    def state(value):
        terminated = getattr(value, 'terminated', None)
        return {'terminated': None if terminated is None else {
            'reason': getattr(terminated, 'reason', None),
            'exitCode': getattr(terminated, 'exit_code', None),
            'signal': getattr(terminated, 'signal', None),
            'message': message(getattr(terminated, 'message', None)),
        }}

    return {
        'phase': getattr(status, 'phase', None),
        'reason': getattr(status, 'reason', None),
        'message': message(getattr(status, 'message', None)),
        'containerStatuses': [
            {'name': entry.name, 'state': state(entry.state), 'lastState': state(entry.last_state)}
            for entry in (getattr(status, 'container_statuses', None) or ())
        ],
    }


def _read_failure(identity: PodIdentity, evidence: dict | None = None) -> str | None:
    # Use the provider's thread-local client factory: same kubeconfig, context,
    # credentials (including in-cluster auth), and refresh policy as sandbox exec.
    from k8s_sandbox._kubernetes_api import k8s_client

    pod = k8s_client(identity.context_name).read_namespaced_pod(
        name=identity.name, namespace=identity.namespace, _request_timeout=(1, 1),
    )
    if evidence is not None:
        evidence['pod'] = _pod_evidence(pod)
        evidence['uid_matches'] = pod.metadata.uid == identity.uid
    if pod.metadata.uid != identity.uid:
        return None  # A replacement pod cannot explain this execution.
    return classify_pod(pod, identity.container, expected_uid=identity.uid)


async def sandbox_failure(environment, *, identity: PodIdentity | None | EllipsisType = ...,
                          evidence: dict | None = None,
                          runner_failed_at: float | None = None) -> str | None:
    """Return only a fixed failure reason, or None on any lookup failure.

    Call only after valid SETUP and a RUNNER with no authenticated receipt.
    Operator regressions may supply an evidence dict for the same lookup and
    runner_failed_at from time.monotonic() to measure the pre-lookup delay.
    Production scoring leaves both unset and publishes only the fixed verdict.
    A daemon isolates blocking client/auth code; unlike asyncio.to_thread, stuck
    credential helpers cannot hold up loop/executor shutdown. The HTTP request
    has short connect/read bounds too. Never pass worker exceptions to the loop.
    """
    if identity is ...:
        identity = sandbox_identity(environment)
    if evidence is not None:
        evidence.update(pod=None, uid_matches=None, lookup_failed=False,
                        exception_class=None, pod_gone=False, identity_available=identity is not None,
                        runner_failure_to_lookup_seconds=None)
    if identity is None:
        return None
    loop = asyncio.get_running_loop()
    answer = loop.create_future()
    lookup_started_at = None

    def deliver(value):
        if not answer.done():
            answer.set_result(value)

    def lookup():
        nonlocal lookup_started_at
        # Keep worker data private until delivery: a timed-out lookup must not
        # mutate sample metadata later, even if client/auth code is stuck.
        details = {}
        lookup_started_at = time.monotonic()
        if evidence is not None and runner_failed_at is not None:
            details['runner_failure_to_lookup_seconds'] = lookup_started_at - runner_failed_at
        try:
            value = _read_failure(identity) if evidence is None else _read_failure(identity, details)
        except Exception as exc:
            value = None
            details.update(lookup_failed=True, exception_class=type(exc).__name__,
                           pod_gone=getattr(exc, 'status', None) == 404)
        try:
            loop.call_soon_threadsafe(deliver, (value, details))
        except RuntimeError:
            pass  # Host deadline elapsed and the loop has already closed.

    try:
        async with asyncio.timeout(LOOKUP_TIMEOUT):
            Thread(target=copy_context().run, args=(lookup,), daemon=True).start()
            value, details = await answer
            if evidence is not None:
                evidence.update(details)
            return value
    except Exception as exc:
        if evidence is not None:
            evidence.update(lookup_failed=True, exception_class=type(exc).__name__)
            if runner_failed_at is not None and lookup_started_at is not None:
                evidence['runner_failure_to_lookup_seconds'] = lookup_started_at - runner_failed_at
        return None
