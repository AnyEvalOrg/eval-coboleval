"""Trusted supervisor source, executed ONLY in the external Linux sandbox.

A completed setup exec writes the request into a fresh directory. The supervisor
reads and unlinks it before starting the candidate. The setup Python process
generates the key locally; no ancestor shell receives it as stdin or an argument. The key is then memory-only.
The root supervisor drops the child to reserved UID/GID 65532 before exec.
PR_SET_DUMPABLE also protects supervisor memory/fds.
The child has separate stdio, no inherited supervisor descriptors, no core dumps,
no privilege gains, and bounded memory and process limits (compiler subprocesses are required).
Only the supervisor can authenticate the wait() status. Provider stdout markers
can truncate/destroy the receipt, but cannot manufacture a valid passing receipt.
"""

CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
# procps pkill returns 1 when there are no matching processes.
CLEANUP_COMMAND = ["timeout", "-s", "KILL", "5s",
                   "/usr/bin/pkill", "-KILL", "-u", str(CANDIDATE_UID)]

# Compilers need forks. After the template's independent
# pkill exec, verify quiescence with repeated UID sweeps (escaped sessions too).
# Ignore zombies: they cannot execute and belong to the container's reaper.
UID_QUIESCENCE = r'''
import os, subprocess, time
until = time.monotonic() + 3
while True:
    sweep = subprocess.run(["/usr/bin/pkill", "-KILL", "-u", "65532"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=1)
    if sweep.returncode not in (0, 1):
        raise SystemExit(2)
    active = False
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as stream:
                status = dict(line.split(":", 1) for line in stream if ":" in line)
            if status["Uid"].split()[0] == "65532" and status["State"].split()[0] not in {"Z", "X"}:
                active = True
        except FileNotFoundError:
            pass
    if not active:
        break
    if time.monotonic() >= until:
        raise SystemExit(2)
    time.sleep(0.02)
'''
QUIESCENCE_COMMAND = ["timeout", "-s", "KILL", "5s",
                      "/usr/local/bin/python3", "-I", "-c", UID_QUIESCENCE]

# Deletion is deliberately outside the receipt-producing process. The shell
# expands only this package's work prefix; timeout also bounds traversal/globbing.
DIRECTORY_CLEANUP_COMMAND = ["timeout", "-s", "KILL", "5s", "/bin/sh", "-c",
                             "exec rm -rf -- /tmp/cjt-*"]

# SETUP and RUNNER execute exactly the same irreversible child restrictions.
CHILD_RESTRICTIONS = r'''
def restrict_child(nofile=256):
    # No parent-death signal is trusted: the scorer independently kills this UID.
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        os._exit(125)
    if libc.prctl(8, 0, 0, 0, 0) != 0:  # PR_SET_KEEPCAPS = 0
        os._exit(125)
    # Still root in the supervisor's preexec child: set this before dropping UID
    # and before candidate code can allocate memory. Descendants inherit it.
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write("1000")
    os.setgroups([])
    os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)
    os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)
    # Set NPROC AFTER changing UID, avoiding execve's PF_NPROC_EXCEEDED trap.
    # These hard limits and the irreversible credential drop survive exec.
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    # COBOL compiler and executables fit comfortably below the 2 GiB pod limit.
    # Preserve a tighter inherited budget (also used by the Linux regression).
    for kind in (resource.RLIMIT_AS, resource.RLIMIT_DATA):
        hard = resource.getrlimit(kind)[1]
        budget = 1024 * 1024 * 1024
        if hard != resource.RLIM_INFINITY:
            budget = min(budget, hard)
        resource.setrlimit(kind, (budget, budget))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

'''

# Setup runs before any candidate exists. Both execs are bounded by the scorer.
SETUP = r'''
import ctypes, json, os, resource, secrets, subprocess, sys, tempfile
CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
libc = ctypes.CDLL(None, use_errno=True)
''' + CHILD_RESTRICTIONS + r'''

def self_check(work):
    if os.getuid() != 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
        raise RuntimeError()
    os.listdir("/proc")
    with open("/proc/self/oom_score_adj", "w") as stream:
        stream.write("1000")
    # Execute a trusted script on the actual work mount as the candidate UID.
    # This proves directory write access and detects noexec, including ACLs.
    os.chmod(work, 0o711)
    try:
        with tempfile.TemporaryDirectory(prefix="probe-", dir=work) as probe:
            os.chown(probe, CANDIDATE_UID, CANDIDATE_GID)
            script = os.path.join(probe, "check")
            with open(script, "x", encoding="utf-8") as stream:
                stream.write("#!" + sys.executable + "\n"
                             "import time\n"
                             "with open('writable', 'x') as f: f.write('ok')\n"
                             "print('ready', flush=True)\n"
                             "time.sleep(2)\n")
            os.chmod(script, 0o755)
            child = subprocess.Popen(
                [script], cwd=probe, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                close_fds=True, start_new_session=True, preexec_fn=restrict_child,
            )
            try:
                if child.stdout.readline() != b"ready\n":
                    raise RuntimeError()
                os.stat("/proc/" + str(child.pid) + "/fd/0")
                with open("/proc/" + str(child.pid) + "/status") as stream:
                    status = dict(line.split(":", 1) for line in stream if ":" in line)
                if (status["Uid"].split() != [str(CANDIDATE_UID)] * 4
                        or int(status["VmRSS"].split()[0]) <= 0):
                    raise RuntimeError()
            finally:
                child.kill()
                child.wait(timeout=1)
                child.stdout.close()
    finally:
        os.chmod(work, 0o700)


def setup():
    global limit
    try:
        request = json.load(sys.stdin)
        limit = request["output_limit"]
        work = tempfile.mkdtemp(prefix="cjt-", dir="/tmp")
        self_check(work)
        key = secrets.token_hex(32)
        request["key"] = key
        with open(os.path.join(work, "request.json"), "x", encoding="utf-8") as f:
            json.dump(request, f)
        sys.stdout.write(json.dumps({"cwd": work, "key": key}))
    except Exception:
        # No exception details, partial receipt or candidate launch on failure.
        raise SystemExit("sandbox prerequisites unavailable") from None

setup()
'''

# Kept as source: importing this module never starts a process or executes code.
RUNNER = r'''
import base64
import ctypes
import errno
import hashlib
import hmac
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
libc = ctypes.CDLL(None, use_errno=True)
if os.getuid() != 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
    raise RuntimeError("root Linux supervisor with protected memory required")
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    raise RuntimeError("subreaper required")
work = sys.argv[1]
request_path = os.path.join(work, "request.json")
with open(request_path, encoding="utf-8") as f:
    request = json.load(f)
os.unlink(request_path)
key = bytes.fromhex(request.pop("key"))
limit = request["output_limit"]
MEMORY_BUDGET = 768 * 1024 * 1024
MEMORY_INTERVAL = 0.05
DISK_BUDGET = 256 * 1024 * 1024
DISK_INTERVAL = 0.1
DISK_ENTRY_BUDGET = 10_000


''' + CHILD_RESTRICTIONS + r'''


def kill_group(pgid):
    # Kill the entire original session's process group, even if the leader exited.
    # An independent UID sweep below also kills descendants that change sessions.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            time.sleep(0.1)



def candidate_rss():
    # gVisor reports full per-process VmRSS for forked copy-on-write pages, so
    # summing RSS can stop a 64-child fork attack before NPROC does. Legitimate
    # compiler/JVM chains use only a handful of processes and remain far below
    # the 768 MiB aggregate budget.
    total = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as stream:
                status = dict(line.split(":", 1) for line in stream if ":" in line)
            if status["Uid"].split()[0] == str(CANDIDATE_UID):
                total += int(status.get("VmRSS", "0 kB").split()[0]) * 1024
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    return total


def kill_candidate(pgid):
    # No grace period on aggregate memory/disk exhaustion, and no fork or reaping
    # from this thread. Include descendants that escaped the original session.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as stream:
                status = dict(line.split(":", 1) for line in stream if ":" in line)
            if status["Uid"].split()[0] == str(CANDIDATE_UID):
                os.kill(int(name), signal.SIGKILL)
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass


def watch_memory(pgid, stopped, status):
    while not stopped.is_set():
        try:
            if candidate_rss() > MEMORY_BUDGET:
                status["memory_exceeded"] = True
                kill_candidate(pgid)
                return
        except Exception:
            # A failed monitor must not silently permit unbounded execution.
            status["supervisor_error"] = True
            try:
                kill_candidate(pgid)
            except Exception:
                status["cleanup_failed"] = True
            return
        if stopped.wait(MEMORY_INTERVAL):
            return


def disk_bytes(roots=("/tmp", "/var/tmp", "/dev/shm"), stopped=None, proc_root="/proc"):
    # No symlink traversal in the directory walk. /proc fd magic links are
    # deliberately followed to include unlinked files and unmapped memfds.
    # Check cancellation and budgets at every entry (N=1), including fd entries.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    raced = (errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.ESRCH)
    seen = set()
    total = 0
    count = 0

    def done():
        return total > DISK_BUDGET or (stopped is not None and stopped.is_set())

    def account(info):
        nonlocal total
        identity = (info.st_dev, info.st_ino)
        if stat.S_ISREG(info.st_mode) and identity not in seen:
            seen.add(identity)
            total += info.st_blocks * 512

    def walk(fd):
        nonlocal count, total
        with os.scandir(fd) as entries:
            for entry in entries:
                if done():
                    return
                count += 1
                if count > DISK_ENTRY_BUDGET:
                    total = DISK_BUDGET + 1  # Inode exhaustion uses disk_exceeded.
                    return
                try:
                    info = entry.stat(follow_symlinks=False)
                    account(info)
                    if stat.S_ISDIR(info.st_mode):
                        child_fd = os.open(entry.name, flags, dir_fd=fd)
                        try:
                            walk(child_fd)
                        finally:
                            os.close(child_fd)
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    continue
                except OSError as error:
                    if error.errno not in raced:
                        raise

    for root in roots:
        if done():
            return total
        try:
            fd = os.open(root, flags)
        except OSError as error:
            if error.errno in raced:
                continue
            raise
        try:
            walk(fd)
        finally:
            os.close(fd)
    if done():
        return total
    for name in os.listdir(proc_root):
        if done():
            return total
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, name, "status")) as stream:
                status = dict(line.split(":", 1) for line in stream if ":" in line)
            if status["Uid"].split()[0] != str(CANDIDATE_UID):
                continue
            with os.scandir(os.path.join(proc_root, name, "fd")) as descriptors:
                for descriptor in descriptors:
                    if done():
                        return total
                    try:
                        account(os.stat(descriptor.path))
                    except (PermissionError, FileNotFoundError, ProcessLookupError):
                        continue
                    except OSError as error:
                        if error.errno not in raced:
                            raise
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            if error.errno not in raced:
                raise
    return total


def watch_disk(pgid, stopped, status):
    while not stopped.is_set():
        try:
            if disk_bytes(stopped=stopped) > DISK_BUDGET:
                status["disk_exceeded"] = True
                kill_candidate(pgid)
                return
        except Exception:
            status["supervisor_error"] = True
            try:
                kill_candidate(pgid)
            except Exception:
                status["cleanup_failed"] = True
            return
        if stopped.wait(DISK_INTERVAL):
            return


def sweep_uid():
    # No fork/exec here: descendants may have exhausted their process budget.
    # Scan all sessions, then reap adopted children (this process is a subreaper).
    until = time.monotonic() + 3
    while True:
        active = False
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open("/proc/" + name + "/status") as stream:
                    status = dict(line.split(":", 1) for line in stream if ":" in line)
                if status["Uid"].split()[0] == str(CANDIDATE_UID) and status["State"].split()[0] not in {"Z", "X"}:
                    os.kill(int(name), signal.SIGKILL)
                    active = True
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
        if not active:
            return
        if time.monotonic() >= until:
            raise RuntimeError("UID sweep did not complete")
        time.sleep(0.02)


def run_step(argv, timeout, candidate_work):
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        raise ValueError("argv must be a nonempty string list")
    nofile = 1024 if os.path.basename(argv[0]) in {"java", "javac"} else 256
    with tempfile.TemporaryFile(dir=work) as stdout, tempfile.TemporaryFile(dir=work) as stderr:
        child = subprocess.Popen(
            argv, cwd=candidate_work,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": candidate_work, "TMPDIR": candidate_work,
                 "JAVA_TOOL_OPTIONS": "-XX:-UsePerfData"},
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True,
            start_new_session=True, preexec_fn=lambda: restrict_child(nofile),
        )
        status = dict(returncode=125, timeout=False, overflow=False,
                      cleanup_failed=False, supervisor_error=False, memory_exceeded=False,
                      disk_exceeded=False)
        output = b""
        stopped = threading.Event()
        watchdogs = [threading.Thread(target=monitor, args=(child.pid, stopped, status), daemon=True)
                     for monitor in (watch_memory, watch_disk)]
        try:
            # Start only after Popen: preexec_fn must never fork with our monitor
            # running. On exit, cancel scans before bounded descendant cleanup.
            for watchdog in watchdogs:
                watchdog.start()
            try:
                status["returncode"] = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                status["timeout"] = True
        except Exception:
            status["supervisor_error"] = True
        finally:
            stopped.set()
            # Every operation after launch is fallible. Preserve the wait status
            # and sign a failure even when cleanup, reaping or output reads fail.
            try:
                kill_group(child.pid)
            except Exception:
                status["cleanup_failed"] = True
            try:
                status["returncode"] = child.wait(timeout=1)
            except Exception:
                status["cleanup_failed"] = True
            try:
                sweep_uid()
            except Exception:
                status["cleanup_failed"] = True
            # Filesystem work must never block signing. Daemons still in a
            # syscall are abandoned and die at os._exit after the receipt.
            for watchdog in watchdogs:
                if watchdog.ident is not None:
                    watchdog.join(timeout=0.2)
                    if watchdog.is_alive():
                        status["supervisor_error"] = True
        try:
            stdout.seek(0)
            output = stdout.read(limit + 1)
            status["overflow"] = len(output) >= limit or os.fstat(stderr.fileno()).st_size >= limit
        except Exception:
            status["supervisor_error"] = True
        return status, output


stage = "compile"
status = dict(returncode=125, timeout=False, overflow=False,
              cleanup_failed=False, supervisor_error=False, memory_exceeded=False,
              disk_exceeded=False)
output = b""


try:
    # Keep launch/request directory root-owned; only its child is writable.
    candidate_work = os.path.join(work, "candidate")
    os.mkdir(candidate_work, 0o700)
    os.chown(candidate_work, CANDIDATE_UID, CANDIDATE_GID)
    os.chmod(work, 0o711)
    for name, content in request["files"].items():
        if not name or name in {".", ".."} or os.path.basename(name) != name:
            raise ValueError("Only plain filenames are allowed")
        path = os.path.join(candidate_work, name)
        with open(path, "x", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o644)
    status, output = run_step(request["argv"], request["timeout"], candidate_work)
    if (status["returncode"] == 0 and not any(status[flag] for flag in
            ("timeout", "overflow", "cleanup_failed", "supervisor_error", "memory_exceeded", "disk_exceeded")) and "run_argv" in request):
        stage = "run"
        status, output = run_step(request["run_argv"], request["run_timeout"], candidate_work)
        if "output_file" in request and status["returncode"] == 0 and not status["timeout"]:
            name = request["output_file"]
            if not name or name in {".", ".."} or os.path.basename(name) != name:
                raise ValueError("Invalid output filename")
            # Candidate-controlled symlinks/FIFOs/devices must never be read as root.
            try:
                fd = os.open(os.path.join(candidate_work, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as f:
                    info = os.fstat(f.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != CANDIDATE_UID or info.st_nlink != 1:
                        raise ValueError("Unsafe output file")
                    output = f.read(limit + 1)
                    status["overflow"] = status["overflow"] or len(output) >= limit
            except (OSError, ValueError):
                status["returncode"] = 125
                output = b""
except Exception:
    # Launch errors (e.g. EAGAIN), unsafe/missing output, and post-run I/O errors
    # must not erase a candidate outcome. Never include exception text or bytes.
    status["supervisor_error"] = True

# All candidate/post-run errors above become authenticated failures. There are
# no directory deletions here, including during Python shutdown. Independent
# cleanup runs in a separate bounded exec after the host authenticates this receipt.
body = json.dumps({**status, "stage": stage,
                  "output": base64.b64encode(output).decode("ascii"), "cwd": work}, separators=(",", ":"))
tag = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
sys.stdout.write(json.dumps({"body": body, "tag": tag}))
sys.stdout.flush()
os._exit(0)
'''
