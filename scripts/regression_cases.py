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
# Four workers retain 75 one-MiB descriptors each, below native NOFILE=256.
# The unlinked files are outside the candidate work directory under /tmp.
RETAINED_FILES = '''import os, tempfile, time
for _ in range(4):
    if os.fork() == 0:
        descriptors = []
        block = b'x' * (1024 * 1024)
        for i in range(75):
            fd, path = tempfile.mkstemp(prefix='cjt-retained-', dir='/tmp')
            os.unlink(path)
            descriptors.append(fd)
            remaining = block
            while remaining:
                remaining = remaining[os.write(fd, remaining):]
        time.sleep(60)
        os._exit(0)
for _ in range(4):
    os.wait()
'''
MEMFD = RETAINED_FILES.replace(
    "fd, path = tempfile.mkstemp(prefix='cjt-retained-', dir='/tmp')\n            os.unlink(path)",
    "fd = os.memfd_create('retained')")
EMPTY_FILES = '''import os, time
for i in range(50_000):
    fd = os.open(str(i), os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
time.sleep(60)
'''
READONLY_SHM = '''import errno, os
try:
    fd = os.open('/dev/shm/cjt-write', os.O_CREAT | os.O_WRONLY, 0o600)
except OSError as error:
    raise SystemExit(1 if error.errno == errno.EROFS else 2)
os.write(fd, b'x')
os.close(fd)
'''
DISK_CASES = ('disk', 'unlinked_files', 'memfd', 'empty_files')
PTRACE_DENIED = '''import os
# PID 1 is the container's root process; also check the actual supervisor.
# A witness distinguishes PermissionError from unrelated execution failures.
for path in ('/proc/1/fd/0', '/proc/' + str(os.getppid()) + '/fd/0'):
    try:
        os.stat(path)
    except PermissionError:
        continue
    raise SystemExit(2)
print('ptrace-denied', flush=True)
raise SystemExit(1)
'''
CASES = {'invalid_utf8': INVALID_UTF8, 'fork_exhaustion': FORK_EXHAUSTION,
         'memory_aggregate': MEMORY_AGGREGATE, 'disk': DISK,
         'detached_child': DETACHED_CHILD, 'unlinked_files': RETAINED_FILES,
         'memfd': MEMFD, 'empty_files': EMPTY_FILES, 'readonly_shm': READONLY_SHM,
         'ptrace_denied': PTRACE_DENIED}


def request_for_case(name):
    return dict(files={}, argv=[PYTHON, '-I', '-c', 'pass'],
                run_argv=[PYTHON, '-I', '-c', CASES[name]],
                timeout=5, run_timeout=15, output_limit=1024 * 1024)


def expected_receipt(name, receipt, receipt_failure):
    if receipt is None or receipt['stage'] != 'run':
        return False
    expected = {flag: False for flag in FLAGS}
    if name == 'invalid_utf8':
        expected['output_error'] = True
    if name == 'memory_aggregate' or (name == 'fork_exhaustion' and receipt.get('memory_exceeded')):
        expected['memory_exceeded'] = True
    if name in DISK_CASES:
        expected['disk_exceeded'] = True
    if any(receipt.get(flag, False) != value for flag, value in expected.items()):
        return False
    if expected['memory_exceeded']:
        return receipt['returncode'] != 0 and receipt_failure(receipt) == 'memory limit exceeded'
    if name == 'disk':
        return (receipt['returncode'] != 0 and receipt_failure(receipt) == 'disk limit exceeded'
                and receipt['output'].strip() == 'disk-direct-tmp')
    if name in DISK_CASES:
        return receipt['returncode'] != 0 and receipt_failure(receipt) == 'disk limit exceeded'
    if name == 'fork_exhaustion':
        # gVisor counts shared COW RSS per process, so memory may win over NPROC.
        witness = receipt['output'].strip().removeprefix('forks=')
        return (receipt['returncode'] == 1 and receipt['output'].startswith('forks=')
                and witness.isascii() and witness.isdecimal() and 0 < int(witness) <= 64
                and receipt_failure(receipt) is not None)
    if name == 'detached_child':
        return receipt['returncode'] == 0 and receipt_failure(receipt) is None
    if name == 'ptrace_denied':
        return (receipt['returncode'] == 1 and receipt['output'].strip() == 'ptrace-denied'
                and receipt_failure(receipt) is not None)
    return receipt['returncode'] == 1 and receipt_failure(receipt) is not None
