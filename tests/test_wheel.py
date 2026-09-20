"""Build and verify installed-wheel discovery without repo imports or network."""
from pathlib import Path
import subprocess
import sys


def test_built_wheel_loads_offline_without_checkout(tmp_path):
    root = Path(__file__).resolve().parents[1]
    dist = tmp_path / 'dist'
    installed = tmp_path / 'wheel-env/site-packages'
    commands = [
        [sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
         '--no-index', '--no-cache-dir', '--disable-pip-version-check', '-w', str(dist), str(root)],
        [sys.executable, '-m', 'pip', 'install', '--no-deps', '--no-index', '--no-cache-dir',
         '--disable-pip-version-check', '--target', str(installed),
         str(dist / 'eval_coboleval-1.0.0-py3-none-any.whl')],
        [sys.executable, str(root / 'scripts/verify_wheel.py'), str(installed)],
    ]
    for command in commands:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
    assert '1 task x 146 exact ids' in result.stdout
