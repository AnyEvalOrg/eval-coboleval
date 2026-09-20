import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from coboleval.dataset import load_records, manifest
from coboleval.prompts import OPENAI_SYSTEM_PROMPT
from coboleval.task import load_dataset, record_to_sample


def test_all_records_and_ids_exactly_match_upstream():
    original = [json.loads(line) for line in Path('CobolEval.jsonl').read_text().splitlines()]
    packaged = load_records()
    assert len(packaged) == 146
    if packaged != original:
        pytest.fail('Packaged records differ from upstream')
    info = manifest()
    assert info['task_ids'] == [r['task_id'] for r in original]
    assert len(set(info['task_ids'])) == 146
    assert info['task_ids'][0] == 'HumanEval/0'
    assert hashlib.sha256(Path('CobolEval.jsonl').read_bytes()).hexdigest() == info['source_sha256']
    assert hashlib.sha256(('\n'.join(info['task_ids'])+'\n').encode()).hexdigest() == info['ids_sha256']
    assert [s.id for s in load_dataset()] == info['task_ids']


def test_prompt_uses_only_upstream_prompt_and_no_tests_or_results():
    for record in load_records():
        sample = record_to_sample(record)
        tainted = {k: v if k in {'prompt', 'task_id', 'entry_point'} else 'PRIVATE_SENTINEL'
                   for k, v in record.items()}
        other = record_to_sample(tainted)
        if [(m.role, m.content) for m in other.input] != [(m.role, m.content) for m in sample.input]:
            pytest.fail('Private target/test data changed prompt')
        assert 'PRIVATE_SENTINEL' not in other.model_dump_json()
        assert set(sample.metadata) == {'task_id', 'entry_point'}
        assert not sample.target
        assert len(sample.input) == 1
        assert sample.input[0].role == 'system'
        if sample.input[0].content != OPENAI_SYSTEM_PROMPT.format(record['prompt']):
            pytest.fail('Chat message differs from upstream')


def test_all_expected_values_are_safe_literals_and_all_callers_retained():
    records = load_records()
    tests = [t for r in records for t in r['tests']]
    assert all(r['tests'] for r in records)
    assert len(tests) == manifest()['cobol_test_count'] == 821
    for t in tests:
        ast.literal_eval(t['result']['value'])
        assert t['test']


def test_rebuild_is_deterministic():
    paths = [Path('coboleval/data') / name for name in ('problems.jsonl.gz', 'manifest.json')]
    before = [p.read_bytes() for p in paths]
    subprocess.run([sys.executable, 'scripts/build_dataset.py'], check=True, capture_output=True, timeout=10)
    assert before == [p.read_bytes() for p in paths]


def test_corrupt_dataset_fails_without_leaking_content(monkeypatch):
    import coboleval.dataset as dataset
    monkeypatch.setattr(dataset, 'manifest', lambda: {'artifact_sha256': 'INVALID_PRIVATE_VALUE'})
    with pytest.raises(RuntimeError, match='details withheld') as error:
        dataset.load_records()
    assert 'INVALID_PRIVATE_VALUE' not in str(error.value)
