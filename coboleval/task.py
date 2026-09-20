"""COBOLEval completion task, one generation and one epoch (pass@1)."""
import os
from importlib.resources import files
from pathlib import Path
from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.solver import generate
from inspect_ai.model import ChatMessageUser
from .dataset import load_records, manifest
from .prompts import system_prompt
from .scoring import coboleval_scorer


def record_to_sample(record: dict) -> Sample:
    return Sample(id=record['task_id'], input=[ChatMessageUser(content=system_prompt(record))],
                  metadata={'task_id': record['task_id'], 'entry_point': record['entry_point']})


def load_dataset() -> MemoryDataset:
    return MemoryDataset(name='COBOLEval',
                         samples=[record_to_sample(r) for r in load_records()])


@task
def coboleval(sandbox_type: str = "k8s", anyeval_chart: bool = True) -> Task:
    if sandbox_type not in {'k8s', 'docker'}:
        raise ValueError('sandbox_type must be k8s or docker')
    resources = files('coboleval')
    config = str(resources.joinpath('values.yaml' if sandbox_type == 'k8s' else 'compose.yaml'))
    if sandbox_type == 'k8s' and anyeval_chart:
        from k8s_sandbox import K8sSandboxEnvironmentConfig
        os.environ.setdefault('INSPECT_K8S_DEFAULT_NAMESPACE', 'anyeval-sandbox')
        config = K8sSandboxEnvironmentConfig(chart=str(resources.joinpath('chart')), values=Path(config))
    return Task(dataset=load_dataset(), solver=[generate()],
                scorer=coboleval_scorer(), sandbox=(sandbox_type, config), epochs=1, version='1.0.0',
                metadata={'metric': 'pass@1', 'dataset_provenance': {k: v for k, v in manifest().items() if k != 'task_ids'}})
