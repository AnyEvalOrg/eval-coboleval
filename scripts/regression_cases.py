"""Synthetic candidates shared by the operator-only Linux and gVisor checks."""
PYTHON = '/usr/local/bin/python3'
FLAGS = ('timeout', 'overflow', 'memory_exceeded', 'disk_exceeded', 'cleanup_failed',
         'supervisor_error', 'output_error')
INVALID_UTF8 = "import os; os.write(1, b'\\xff'); raise SystemExit(1)"
FORK_EXHAUSTION = '''import errno, os, time
count = 0
while True:
    try:
        pid = os.fork()
    except OSError as error:
        print('forks=' + str(count), flush=True)
        raise SystemExit(1 if error.errno == errno.EAGAIN else 2)
    if pid == 0:
        os.setsid()
        while True:
            time.sleep(60)
    count += 1
'''
MEMORY_AGGREGATE = '''import os, time
for _ in range(3):
    if os.fork() == 0:
        block = bytearray(600 * 1024 * 1024)
        time.sleep(60)
        os._exit(0)
for _ in range(3):
    os.wait()
'''
DISK = '''import os
block = b'x' * (1024 * 1024)
# Keep work-directory writes below the budget. Only a monitor covering all of
# /tmp can stop the unbounded second directory. Both match independent cleanup.
for i in range(8):
    with open(str(i), 'wb') as f:
        f.write(block)
outside = os.path.dirname(os.getcwd()) + '-disk'
os.mkdir(outside)
with open(os.path.join(outside, '0'), 'wb') as f:
    f.write(block)
print('disk-direct-tmp', flush=True)
i = 1
while True:
    with open(os.path.join(outside, str(i)), 'wb') as f:
        f.write(block)
    i += 1
'''
DETACHED_CHILD = '''import os, time
if os.fork() == 0:
    os.setsid()
    open('ready', 'w').close()
    time.sleep(60)
    os._exit(0)
while not os.path.exists('ready'):
    time.sleep(0.01)
os._exit(0)
'''
CASES = {'invalid_utf8': INVALID_UTF8, 'fork_exhaustion': FORK_EXHAUSTION,
         'memory_aggregate': MEMORY_AGGREGATE, 'disk': DISK,
         'detached_child': DETACHED_CHILD}


def request_for_case(name):
    return dict(files={}, argv=[PYTHON, '-I', '-c', 'pass'],
                run_argv=[PYTHON, '-I', '-c', CASES[name]],
                timeout=5, run_timeout=15, output_limit=2 * 1024 * 1024)


def expected_receipt(name, receipt, receipt_failure):
    if receipt is None or receipt['stage'] != 'run':
        return False
    expected = {flag: False for flag in FLAGS}
    if name == 'invalid_utf8':
        expected['output_error'] = True
    if name == 'memory_aggregate' or (name == 'fork_exhaustion' and receipt.get('memory_exceeded')):
        expected['memory_exceeded'] = True
    if name == 'disk':
        expected['disk_exceeded'] = True
    if any(receipt.get(flag, False) != value for flag, value in expected.items()):
        return False
    if expected['memory_exceeded']:
        return receipt['returncode'] != 0 and receipt_failure(receipt) == 'memory limit exceeded'
    if name == 'disk':
        return (receipt['returncode'] != 0 and receipt_failure(receipt) == 'disk limit exceeded'
                and receipt['output'].strip() == 'disk-direct-tmp')
    if name == 'fork_exhaustion':
        # gVisor counts shared COW RSS per process, so memory may win over NPROC.
        witness = receipt['output'].strip().removeprefix('forks=')
        return (receipt['returncode'] == 1 and receipt['output'].startswith('forks=')
                and witness.isascii() and witness.isdecimal() and 0 < int(witness) <= 64
                and receipt_failure(receipt) is not None)
    if name == 'detached_child':
        return receipt['returncode'] == 0 and receipt_failure(receipt) is None
    return receipt['returncode'] == 1 and receipt_failure(receipt) is not None
