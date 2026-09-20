"""Construct shell-free compile/run requests; never execute candidates on the host."""
import re

COMPILE_TIMEOUT = 60
RUN_TIMEOUT = 30
OUTPUT_LIMIT = 1024 * 1024


def execution_request(code: str, record: dict, test: dict) -> dict:
    request = dict(timeout=COMPILE_TIMEOUT, run_timeout=RUN_TIMEOUT, output_limit=OUTPUT_LIMIT)
    output_file = record['entry_point'].upper().replace('_', '-') + '.TXT'
    if not re.fullmatch(r'[A-Z0-9-]+\.TXT', output_file):
        raise ValueError('Invalid entry point')
    request.update(files={'call.cbl': test['test'], 'solution.cbl': code},
                   argv=['cobc', '-w', '-fformat=variable', '-x', 'call.cbl', 'solution.cbl'],
                   run_argv=['./call'], output_file=output_file)
    return request
