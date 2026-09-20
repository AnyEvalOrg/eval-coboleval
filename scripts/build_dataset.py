"""Deterministically package all local upstream records; never uses the network."""
from __future__ import annotations
import gzip
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '0bb96c3114bb2bb28e221e9d6000614781f8609d'


def main():
    raw = (ROOT / 'CobolEval.jsonl').read_bytes()
    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    ids = [r['task_id'] for r in records]
    if len(records) != 146 or len(set(ids)) != 146:
        raise ValueError('Expected 146 distinct upstream task ids')
    data = b''.join((json.dumps(r, ensure_ascii=False, separators=(',', ':')) + '\n').encode() for r in records)
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode='wb', filename='', mtime=0, compresslevel=9) as stream:
        stream.write(data)
    artifact = out.getvalue()
    manifest = dict(dataset='COBOLEval', upstream_commit=COMMIT,
                    source_path='data/CobolEval.jsonl', license='MIT',
                    selection='All upstream records, original order and task_id values',
                    count=len(records), cobol_test_count=sum(len(r['tests']) for r in records),
                    source_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_sha256=hashlib.sha256(artifact).hexdigest(), artifact_bytes=len(artifact),
                    ids_sha256=hashlib.sha256(('\n'.join(ids)+'\n').encode()).hexdigest(), task_ids=ids)
    target = ROOT / 'coboleval/data'
    target.mkdir(parents=True, exist_ok=True)
    (target / 'problems.jsonl.gz').write_bytes(artifact)
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(f"Packaged {len(records)} records, {manifest['cobol_test_count']} COBOL tests, {len(artifact)} bytes")


if __name__ == '__main__':
    main()
