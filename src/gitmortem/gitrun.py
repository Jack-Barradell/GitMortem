import contextlib
import os
import queue
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import weakref
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from contextlib import contextmanager
from enum import Enum, StrEnum
from pathlib import Path
from typing import IO, Any, Protocol, cast

MIN_GIT = (2, 34, 0)
DEFAULT_TIMEOUT = 120.0
CANCEL_POLL = 0.1
_CHUNK = 1 << 16
_STREAM_HELD = 16
_EXITING_SECONDS = 1.0
_GONE_SECONDS = 2.0
_FIRST_POLL = 0.0005
_LAST_POLL = 0.05
_WONT_START = frozenset({2, 3, 5, 11, 191, 192, 193, 216, 225, 740})
FILE_CLONE = ("protocol.file.allow", "user")
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
NO_FETCH_ENV = {"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""}


def safe_config(hooks: str) -> tuple[tuple[str, str], ...]:
    never = os.path.join(os.path.dirname(hooks), "no-signing-program")
    return (
        ("core.hooksPath", hooks),
        ("core.fsmonitor", "false"),
        ("protocol.allow", "never"),
        ("attr.tree", EMPTY_TREE),
        ("core.multiPackIndex", "false"),
        ("core.pager", "cat"),
        ("core.useReplaceRefs", "false"),
        ("core.commitGraph", "false"),
        ("log.showSignature", "false"),
        ("gpg.program", never),
        ("gpg.ssh.program", never),
        ("gpg.x509.program", never),
        ("i18n.logOutputEncoding", "UTF-8"),
        ("submodule.recurse", "false"),
    )


SAFE_CONFIG_KEYS = tuple(key for key, _ in safe_config(""))
CALLER_ENV = frozenset(
    {
        "BASH_ENV",
        "GIT_TRACE2_EVENT",
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_CONFIG",
        "GIT_INDEX_FILE",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_DATE",
    }
)
_TOP_LEVEL_OPTIONS = frozenset({"--version", "--exec-path"})

_CREATE_NEW_PROCESS_GROUP = 0x00000200
_VERSION = re.compile(r"git version (\d+)\.(\d+)(?:\.(\d+))?")
_NEW_PRIVATE_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
_READ_COMMONDIR = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)
_COMMONDIR_MAX = 4096


class GitError(Exception):
    def __init__(self, subcommand: str, returncode: int, message: str | None = None) -> None:
        super().__init__(message or f"git {subcommand} failed (exit {returncode})")
        self.subcommand = subcommand
        self.returncode = returncode


class GitTimeout(GitError):
    def __init__(self, subcommand: str, timeout: float, *, command: str | None = None) -> None:
        called = command or f"git {subcommand}"
        super().__init__(subcommand, -1, f"{called} timed out after {timeout:g}s")


class GitCancelled(GitError):
    def __init__(self, subcommand: str, *, command: str | None = None) -> None:
        super().__init__(subcommand, -1, f"{command or f'git {subcommand}'} was cancelled")


class GitOutputTooLarge(GitError):
    def __init__(self, subcommand: str, limit: int) -> None:
        super().__init__(subcommand, -1, f"git {subcommand} printed more than {limit} bytes")
        self.limit = limit


class GitUnavailable(Exception):
    pass


class ShadowRefused(Exception):
    pass


class NotStarted(OSError):
    pass


class WorktreesUnreadable(OSError):
    pass


class Discard(Enum):
    STREAM = "discard"


DISCARD = Discard.STREAM


class ShadowProblem(StrEnum):
    LINKED_WORKTREE = "linked_worktree"
    OWN_ALTERNATES = "own_alternates"
    OWN_HTTP_ALTERNATES = "own_http_alternates"
    SHALLOW = "shallow"
    NOT_SHA1 = "not_sha1"
    FOREIGN_COMMONDIR = "foreign_commondir"
    FETCHES = "fetches"
    REFS_OUTSIDE = "refs_outside"
    ODD_PATH = "odd_path"
    UNREADABLE = "unreadable"


SHADOW_PROBLEMS: dict[ShadowProblem, str] = {
    ShadowProblem.LINKED_WORKTREE: "the git dir is a linked worktree's: pass its common dir",
    ShadowProblem.OWN_ALTERNATES: "the repository has its own objects/info/alternates",
    ShadowProblem.OWN_HTTP_ALTERNATES: "the repository has its own objects/info/http-alternates",
    ShadowProblem.SHALLOW: "the repository is a shallow clone",
    ShadowProblem.NOT_SHA1: "the repository's object format is not sha1",
    ShadowProblem.FOREIGN_COMMONDIR: "a linked worktree's commondir names another git dir",
    ShadowProblem.FETCHES: "the repository's config would make git fetch or run a hook",
    ShadowProblem.REFS_OUTSIDE: "the repository's reftable names a table outside it",
    ShadowProblem.ODD_PATH: "the repository's path holds a line break",
    ShadowProblem.UNREADABLE: "the repository's git dir cannot be read",
}


def inherited_env(*, posix: bool) -> dict[str, str]:
    inherited = {"PATH": os.environ.get("PATH", os.defpath)}
    if not posix and "SYSTEMROOT" in os.environ:
        inherited["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return inherited


def _spawn_kwargs(*, posix: bool) -> dict[str, Any]:
    if posix:
        return {"start_new_session": True}
    return {
        "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", _CREATE_NEW_PROCESS_GROUP)
    }


class _Job(Protocol):
    def assign(self, proc: "subprocess.Popen[bytes]") -> None: ...

    def terminate(self) -> None: ...

    def until_empty(self, seconds: float) -> None: ...

    def close(self) -> None: ...


_JOBS: "weakref.WeakKeyDictionary[subprocess.Popen[bytes], _Job]" = weakref.WeakKeyDictionary()


def _new_job() -> _Job | None:
    if sys.platform == "win32":
        from gitmortem import winjob

        return winjob.Job()
    return None


def _system_directory() -> Path:
    if sys.platform == "win32":
        from gitmortem import winjob

        return winjob.system_directory()
    raise OSError("only Windows has a system directory to start taskkill from")


def _held_in_job(proc: "subprocess.Popen[bytes]", *, posix: bool) -> _Job | None:
    if posix:
        return None
    try:
        job = _new_job()
    except OSError:
        return None
    if job is None:
        return None
    try:
        job.assign(proc)
    except OSError:
        job.close()
        return None
    _JOBS[proc] = job
    return job


def _end_job(proc: "subprocess.Popen[bytes]", job: _Job) -> None:
    _JOBS.pop(proc, None)
    try:
        job.terminate()
        job.until_empty(_GONE_SECONDS)
    finally:
        job.close()


def _kill_tree(proc: "subprocess.Popen[bytes]", *, posix: bool) -> None:
    if sys.platform != "win32" and posix and proc.returncode is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError as refused:
            try:
                proc.wait(timeout=_EXITING_SECONDS)
            except subprocess.TimeoutExpired:
                raise refused from None
        proc.wait()
        _until_gone(proc.pid)
        return
    if not posix:
        job = _JOBS.get(proc)
        if job is not None:
            job.terminate()
            job.until_empty(_GONE_SECONDS)
        else:
            subprocess.run(  # noqa: S603
                [str(_system_directory() / "taskkill.exe"), "/T", "/F", "/PID", str(proc.pid)],
                check=False,
                capture_output=True,
            )
    proc.wait()


def _running_in_proc(proc_root: Path, pgid: int) -> bool | None:
    try:
        names = os.listdir(proc_root)
    except OSError:
        return None
    for name in names:
        if not name.isdigit():
            continue
        try:
            record = (proc_root / name / "stat").read_bytes()
        except OSError:
            continue
        fields = record[record.rfind(b")") + 1 :].split()
        if len(fields) >= 3 and fields[2] == b"%d" % pgid and fields[0] not in (b"Z", b"X"):
            return True
    return False


if sys.platform != "win32":

    def _group_running(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError):
            return False
        if sys.platform == "linux":
            running = _running_in_proc(Path("/proc"), pgid)
            if running is not None:
                return running
        return True

    def _until_gone(pgid: int) -> None:
        deadline = time.monotonic() + _GONE_SECONDS
        delay = _FIRST_POLL
        while _group_running(pgid):
            left = deadline - time.monotonic()
            if left <= 0:
                return
            delay = min(delay * 2, left, _LAST_POLL)
            time.sleep(delay)


def exited(proc: "subprocess.Popen[bytes]", timeout: float, *, posix: bool) -> None:
    if proc.returncode is not None:
        return
    if sys.platform != "win32" and posix:
        waitid = getattr(os, "waitid", None)
        if waitid is not None:
            _exited_by_waitid(proc, timeout, waitid)
            return
        if sys.platform != "linux" and sys.platform != "win32":
            if hasattr(select, "kqueue"):
                _exited_by_kqueue(proc, timeout)
                return
    proc.wait(timeout=timeout)


if sys.platform != "win32":

    def _exited_by_waitid(
        proc: "subprocess.Popen[bytes]", timeout: float, waitid: Callable[[int, int, int], object]
    ) -> None:
        deadline = time.monotonic() + timeout
        delay = _FIRST_POLL
        while waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise subprocess.TimeoutExpired("child", timeout)
            delay = min(delay * 2, left, _LAST_POLL)
            time.sleep(delay)


if sys.platform != "linux" and sys.platform != "win32":

    def _exited_by_kqueue(proc: "subprocess.Popen[bytes]", timeout: float) -> None:
        queue = select.kqueue()
        try:
            note = select.kevent(
                proc.pid,
                filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT,
            )
            try:
                queue.control([note], 0, 0)
            except ProcessLookupError:
                return
            if not queue.control(None, 1, timeout):
                raise subprocess.TimeoutExpired("child", timeout)
        finally:
            queue.close()


def wait[T](
    proc: "subprocess.Popen[bytes]",
    step: Callable[[float], T],
    *,
    subcommand: str,
    timeout: float,
    cancel: threading.Event | None,
    posix: bool,
    command: str | None = None,
) -> T:
    deadline = time.monotonic() + timeout
    try:
        while True:
            if cancel is not None and cancel.is_set():
                raise GitCancelled(subcommand, command=command)
            left = deadline - time.monotonic()
            if left <= 0:
                raise GitTimeout(subcommand, timeout, command=command)
            try:
                result = step(left if cancel is None else min(left, CANCEL_POLL))
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        _kill_tree(proc, posix=posix)
        raise
    if posix and proc.returncode is None:
        _kill_tree(proc, posix=posix)
    else:
        proc.wait()
    return result


def _kill_left_behind(proc: "subprocess.Popen[bytes]") -> None:
    if sys.platform != "win32":
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)


class _Pipes:
    def __init__(
        self,
        proc: "subprocess.Popen[bytes]",
        stdin: bytes | None,
        limit: int | None,
        subcommand: str,
        *,
        posix: bool,
        read: bool = True,
    ) -> None:
        self.proc = proc
        self.limit = limit
        self.subcommand = subcommand
        self.posix = posix
        self.read = read
        self.chunks: list[bytes] = []
        self.size = 0
        self.read_error: OSError | None = None
        self.write_error: OSError | None = None
        self.ended = threading.Event()
        self.released = threading.Event()
        self.held_open = False
        self.feeder: threading.Thread | None = None
        unowned: list[int] = []
        try:
            if read:
                out = cast(IO[bytes], proc.stdout)
                unowned.append(os.dup(out.fileno()))
                out.close()
                threading.Thread(target=self._read, args=(unowned[0],), daemon=True).start()
                unowned.clear()
            if stdin is not None:
                into = cast(IO[bytes], proc.stdin)
                unowned.append(os.dup(into.fileno()))
                into.close()
                self.feeder = threading.Thread(
                    target=self._feed, args=(unowned[0], stdin), daemon=True
                )
                self.feeder.start()
                unowned.clear()
        except BaseException:
            for fd in unowned:
                os.close(fd)
            try:
                _kill_tree(proc, posix=posix)
            finally:
                self.released.set()
            raise

    def __enter__(self) -> "_Pipes":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.released.set()

    def _read(self, fd: int) -> None:
        closed = False
        try:
            while self.limit is None or self.size <= self.limit:
                want = _CHUNK if self.limit is None else min(_CHUNK, self.limit - self.size + 1)
                chunk = os.read(fd, want)
                if not chunk:
                    closed = True
                    break
                self.chunks.append(chunk)
                self.size += len(chunk)
        except OSError as error:
            self.read_error = error
        finally:
            self.ended.set()
            if not closed:
                self.released.wait()
            os.close(fd)

    def _feed(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        try:
            while view:
                view = view[os.write(fd, view) :]
        except BrokenPipeError:
            pass
        except OSError as error:
            self.write_error = error
        finally:
            os.close(fd)

    def step(self, left: float) -> bytes:
        until = time.monotonic() + left
        if self.read:
            self._until_the_end_of_stdout(until, left)
            if self.limit is not None and self.size > self.limit:
                raise GitOutputTooLarge(self.subcommand, self.limit)
            if self.read_error is not None:
                raise self.read_error
        exited(self.proc, max(0.0, until - time.monotonic()), posix=self.posix)
        if self.feeder is not None:
            self.feeder.join(max(0.0, until - time.monotonic()))
            if self.feeder.is_alive():
                raise subprocess.TimeoutExpired(self.subcommand, left)
        if self.write_error is not None:
            raise self.write_error
        return b"".join(self.chunks)

    def _until_the_end_of_stdout(self, until: float, left: float) -> None:
        while not self.ended.wait(max(0.0, min(until - time.monotonic(), CANCEL_POLL))):
            if time.monotonic() >= until:
                raise subprocess.TimeoutExpired(self.subcommand, left)
            if self.held_open or (self.feeder is not None and self.feeder.is_alive()):
                continue
            try:
                exited(self.proc, 0, posix=self.posix)
            except subprocess.TimeoutExpired:
                continue
            self.held_open = True
            if self.proc.returncode is None:
                _kill_left_behind(self.proc)


_END = object()


class _Stream:
    def __init__(
        self,
        proc: "subprocess.Popen[bytes]",
        stdin: bytes | None,
        subcommand: str,
        *,
        posix: bool,
    ) -> None:
        self.proc = proc
        self.subcommand = subcommand
        self.posix = posix
        self.queue: queue.Queue[object] = queue.Queue(maxsize=_STREAM_HELD)
        self.stopping = threading.Event()
        self.released = threading.Event()
        self.write_error: OSError | None = None
        self.held_open = False
        self.ended = False
        self.feeder: threading.Thread | None = None
        unowned: list[int] = []
        try:
            out = cast(IO[bytes], proc.stdout)
            unowned.append(os.dup(out.fileno()))
            out.close()
            threading.Thread(target=self._read, args=(unowned[0],), daemon=True).start()
            unowned.clear()
            if stdin is not None:
                into = cast(IO[bytes], proc.stdin)
                unowned.append(os.dup(into.fileno()))
                into.close()
                self.feeder = threading.Thread(
                    target=self._feed, args=(unowned[0], stdin), daemon=True
                )
                self.feeder.start()
                unowned.clear()
        except BaseException:
            for fd in unowned:
                os.close(fd)
            try:
                _kill_tree(proc, posix=posix)
            finally:
                self.stopping.set()
                self.released.set()
            raise

    def _put(self, item: object) -> bool:
        while not self.stopping.is_set():
            try:
                self.queue.put(item, timeout=CANCEL_POLL)
            except queue.Full:
                continue
            return True
        return False

    def _read(self, fd: int) -> None:
        closed = False
        try:
            while True:
                chunk = os.read(fd, _CHUNK)
                if not chunk:
                    closed = True
                    self._put(_END)
                    break
                if not self._put(chunk):
                    break
        except OSError as error:
            self._put(error)
        finally:
            if not closed:
                self.released.wait()
            os.close(fd)

    def _feed(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        try:
            while view:
                view = view[os.write(fd, view) :]
        except BrokenPipeError:
            pass
        except OSError as error:
            self.write_error = error
        finally:
            os.close(fd)

    def _next(self, deadline: float, timeout: float, cancel: threading.Event | None) -> object:
        while True:
            if cancel is not None and cancel.is_set():
                raise GitCancelled(self.subcommand)
            left = deadline - time.monotonic()
            if left <= 0:
                raise GitTimeout(self.subcommand, timeout)
            try:
                return self.queue.get(timeout=min(left, CANCEL_POLL))
            except queue.Empty:
                self._kill_what_holds_stdout()

    def _kill_what_holds_stdout(self) -> None:
        if self.held_open or (self.feeder is not None and self.feeder.is_alive()):
            return
        try:
            exited(self.proc, 0, posix=self.posix)
        except subprocess.TimeoutExpired:
            return
        self.held_open = True
        if self.proc.returncode is None:
            _kill_left_behind(self.proc)

    def _exit_step(self, left: float) -> None:
        until = time.monotonic() + left
        exited(self.proc, left, posix=self.posix)
        if self.feeder is not None:
            self.feeder.join(max(0.0, until - time.monotonic()))
            if self.feeder.is_alive():
                raise subprocess.TimeoutExpired(self.subcommand, left)

    def chunks(
        self, deadline: float, timeout: float, cancel: threading.Event | None
    ) -> Iterator[bytes]:
        while True:
            item = self._next(deadline, timeout, cancel)
            if item is _END:
                break
            if isinstance(item, OSError):
                raise item
            yield cast(bytes, item)
        wait(
            self.proc,
            self._exit_step,
            subcommand=self.subcommand,
            timeout=max(0.0, deadline - time.monotonic()),
            cancel=cancel,
            posix=self.posix,
        )
        self.ended = True
        if self.write_error is not None:
            raise self.write_error
        if self.proc.returncode != 0:
            raise GitError(self.subcommand, self.proc.returncode)

    def close(self) -> None:
        self.stopping.set()
        try:
            if not self.ended:
                _kill_tree(self.proc, posix=self.posix)
        finally:
            self.released.set()


@contextmanager
def _private_outputs(*paths: Path) -> Iterator[list[int]]:
    fds: list[int] = []
    try:
        for path in paths:
            fds.append(os.open(path, _NEW_PRIVATE_FILE, 0o600))
    except OSError:
        for fd, path in zip(fds, paths, strict=False):
            os.close(fd)
            path.unlink()
        raise
    try:
        yield fds
    finally:
        for fd in fds:
            os.close(fd)


@contextmanager
def spawned(
    argv: Sequence[str | bytes],
    *,
    cwd: Path,
    env: Mapping[str, str],
    stdin: bool,
    stdout: Path | Discard | int,
    stderr: Path | Discard | int,
    posix: bool,
) -> Iterator[tuple["subprocess.Popen[bytes]", list[int]]]:
    files = [stream for stream in (stdout, stderr) if isinstance(stream, Path)]
    with _private_outputs(*files) as fds:
        made = iter(fds)
        out, err = (
            subprocess.DEVNULL
            if isinstance(stream, Discard)
            else next(made)
            if isinstance(stream, Path)
            else stream
            for stream in (stdout, stderr)
        )
        try:
            proc = subprocess.Popen(  # noqa: S603
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                **_spawn_kwargs(posix=posix),
            )
        except OSError as error:
            if _not_started(error, argv[0], posix=posix):
                raise NotStarted(error.errno, error.strerror, argv[0]) from error
            raise
        with proc:
            job = _held_in_job(proc, posix=posix)
            try:
                yield proc, [fd for fd in (out, err) if fd != subprocess.DEVNULL]
            finally:
                if job is not None:
                    _end_job(proc, job)


def _not_started(error: OSError, program: str | bytes, *, posix: bool) -> bool:
    if posix:
        named: object = error.filename
        return named == program
    return getattr(error, "winerror", None) in _WONT_START


def check_extra_config(
    extra_config: Sequence[tuple[str, str]], *, file_clone: bool = False
) -> None:
    guarded = {key.lower() for key in SAFE_CONFIG_KEYS}
    for key, value in extra_config:
        lowered = key.lower()
        section = lowered.split(".", 1)[0]
        if lowered in guarded:
            raise ValueError(f"{key} is set by the runner and cannot be replaced")
        if section in ("include", "includeif"):
            raise ValueError(f"{key} cannot include another config file")
        if section == "protocol" and not (file_clone and (key, value) == FILE_CLONE):
            raise ValueError(f"{key} cannot change which protocols git may use")
        if section == "gpg":
            raise ValueError(f"{key} cannot change how git checks a signature")
        if lowered == "safe.directory" and (value == "*" or value.endswith("/*")):
            raise ValueError(f"{key} cannot be a wildcard")


def _name(arg: str | bytes) -> str:
    return arg.decode("utf-8", "replace") if isinstance(arg, bytes) else arg


_GIT_FOUND: dict[str, str] = {}
_GIT_FOUND_LOCK = threading.Lock()


def git_on(path_env: str, *, windows: bool = sys.platform == "win32") -> str | None:
    with _GIT_FOUND_LOCK:
        found = _GIT_FOUND.get(path_env)
    if found is not None:
        return found
    name = "git.exe" if windows else "git"
    for entry in path_env.split(os.pathsep):
        folder = Path(entry)
        if not entry or not folder.is_absolute():
            continue
        candidate = folder / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            with _GIT_FOUND_LOCK:
                _GIT_FOUND[path_env] = str(candidate)
            return str(candidate)
    return None


class GitRunner:
    def __init__(self, private_dir: Path) -> None:
        self.private_dir = private_dir
        self.home = private_dir / "home"
        self.tmp = private_dir / "tmp"
        self.hooks = private_dir / "hooks"
        for directory in (private_dir, self.home, self.tmp, self.hooks):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)

    def env(
        self,
        extra: Mapping[str, str] | None = None,
        extra_config: Sequence[tuple[str, str]] = (),
    ) -> dict[str, str]:
        safe = safe_config(str(self.hooks))
        check_extra_config(extra_config)
        pairs = [*safe, *extra_config]
        env = {
            **inherited_env(posix=os.name == "posix"),
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "TMPDIR": str(self.tmp),
            "TMP": str(self.tmp),
            "TEMP": str(self.tmp),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "TZ": "UTC",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_GRAFT_FILE": str(self.private_dir / "no-grafts"),
            **NO_FETCH_ENV,
            "GIT_CONFIG_COUNT": str(len(pairs)),
        }
        for n, (key, value) in enumerate(pairs):
            env[f"GIT_CONFIG_KEY_{n}"] = key
            env[f"GIT_CONFIG_VALUE_{n}"] = value
        for key, value in (extra or {}).items():
            if key not in CALLER_ENV:
                raise ValueError(f"{key} is not a variable a caller may set")
            env[key] = value
        return env

    def _command(
        self,
        args: Sequence[str | bytes],
        extra_env: Mapping[str, str] | None,
        extra_config: Sequence[tuple[str, str]],
    ) -> tuple[list[str | bytes], dict[str, str]]:
        if not args:
            raise ValueError("git needs a subcommand")
        first = _name(args[0])
        if first.startswith("-") and first not in _TOP_LEVEL_OPTIONS:
            raise ValueError("git takes no option before the subcommand here")
        env = self.env(extra_env, extra_config)
        git = git_on(env["PATH"])
        if git is None:
            raise GitUnavailable("git was not found on PATH")
        return [git, *args], env

    def run(
        self,
        args: Sequence[str | bytes],
        *,
        cwd: Path,
        stdin: bytes | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        ok_codes: Collection[int] = (0,),
        extra_env: Mapping[str, str] | None = None,
        extra_config: Sequence[tuple[str, str]] = (),
        cancel: threading.Event | None = None,
        max_stdout: int | None = None,
    ) -> bytes:
        argv, env = self._command(args, extra_env, extra_config)
        posix = os.name == "posix"
        subcommand = _name(args[0])
        with (
            subprocess.Popen(  # noqa: S603
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                **_spawn_kwargs(posix=posix),
            ) as proc,
            _Pipes(proc, stdin, max_stdout, subcommand, posix=posix) as pipes,
        ):
            out = wait(
                proc, pipes.step, subcommand=subcommand, timeout=timeout, cancel=cancel, posix=posix
            )
        if proc.returncode not in ok_codes:
            raise GitError(subcommand, proc.returncode)
        return out

    def capture(
        self,
        args: Sequence[str | bytes],
        *,
        cwd: Path,
        stdout: Path | Discard,
        stderr: Path | Discard,
        timeout: float,
        cancel: threading.Event | None = None,
        extra_env: Mapping[str, str] | None = None,
        extra_config: Sequence[tuple[str, str]] = (),
        path_first: Sequence[Path] = (),
        stdin: bytes | None = None,
    ) -> int:
        argv, env = self._command(args, extra_env, extra_config)
        env["PATH"] = os.pathsep.join([*(str(folder) for folder in path_first), env["PATH"]])
        posix = os.name == "posix"
        subcommand = _name(args[0])
        with (
            spawned(
                argv,
                cwd=cwd,
                env=env,
                stdin=stdin is not None,
                stdout=stdout,
                stderr=stderr,
                posix=posix,
            ) as (proc, _outputs),
            _Pipes(proc, stdin, None, subcommand, posix=posix, read=False) as pipes,
        ):
            wait(
                proc, pipes.step, subcommand=subcommand, timeout=timeout, cancel=cancel, posix=posix
            )
        return proc.returncode

    @contextmanager
    def stream(
        self,
        args: Sequence[str | bytes],
        *,
        cwd: Path,
        timeout: float,
        cancel: threading.Event | None = None,
        stdin: bytes | None = None,
        stderr: Path | Discard = DISCARD,
        extra_env: Mapping[str, str] | None = None,
        extra_config: Sequence[tuple[str, str]] = (),
    ) -> Iterator[Iterator[bytes]]:
        argv, env = self._command(args, extra_env, extra_config)
        posix = os.name == "posix"
        subcommand = _name(args[0])
        deadline = time.monotonic() + timeout
        files = [stderr] if isinstance(stderr, Path) else []
        with (
            _private_outputs(*files) as fds,
            subprocess.Popen(  # noqa: S603
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=fds[0] if fds else subprocess.DEVNULL,
                **_spawn_kwargs(posix=posix),
            ) as proc,
        ):
            pipes = _Stream(proc, stdin, subcommand, posix=posix)
            try:
                yield pipes.chunks(deadline, timeout, cancel)
            finally:
                pipes.close()

    def version(self) -> tuple[int, int, int]:
        text = self.run(["--version"], cwd=self.private_dir).decode("utf-8", "replace")
        match = _VERSION.search(text)
        if match is None:
            raise GitUnavailable("git did not report a version")
        major, minor, patch = match.groups()
        return int(major), int(minor), int(patch or 0)


@contextmanager
def git_runner() -> Iterator[GitRunner]:
    with tempfile.TemporaryDirectory(prefix="gitmortem-git-") as directory:
        yield GitRunner(Path(directory))


def require_git(runner: GitRunner) -> tuple[int, int, int]:
    try:
        found = runner.version()
    except GitError as error:
        raise GitUnavailable(f"git did not run ({error}); install git 2.34 or newer") from None
    shown = ".".join(map(str, found))
    if found < MIN_GIT:
        need = ".".join(map(str, MIN_GIT[:2]))
        raise GitUnavailable(f"git {need} or newer is required (found {shown})")
    try:
        fetches = _fetches_when_told_not_to(runner, found)
    except (GitError, OSError) as error:
        raise GitUnavailable(f"git {shown} could not check itself ({error})") from None
    if fetches:
        raise GitUnavailable(
            f"git {shown} fetches for a repository's own config even when told not to: "
            "install git 2.34 or newer with your system's security updates, "
            "or upstream git 2.39.4, 2.43.4, 2.45.2 or newer"
        )
    return found


_PROBE_CONFIG = """[core]
\trepositoryformatversion = 1
\tbare = true
[extensions]
\tpartialClone = origin
[remote "origin"]
\turl = {source}
\tpromisor = true
\tpartialclonefilter = blob:none
[fetch]
\tbundleURI = {bundle}
[protocol "file"]
\tallow = always
"""
_PROBE_PERSON = {
    "GIT_AUTHOR_NAME": "GitMortem",
    "GIT_AUTHOR_EMAIL": "probe@gitmortem.invalid",
    "GIT_AUTHOR_DATE": "1700000000 +0000",
    "GIT_COMMITTER_NAME": "GitMortem",
    "GIT_COMMITTER_EMAIL": "probe@gitmortem.invalid",
    "GIT_COMMITTER_DATE": "1700000000 +0000",
}
_PROBE_SECONDS = 30.0
_fetch_checked: dict[tuple[tuple[int, int, int], str], bool] = {}
_fetch_lock = threading.Lock()


def _state(folder: Path) -> list[tuple[str, int, bytes]]:
    found = []
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            data = path.read_bytes() if path.name == "config" else b""
            found.append((path.relative_to(folder).as_posix(), path.stat().st_size, data))
    return found


def _fetches_when_told_not_to(runner: GitRunner, version: tuple[int, int, int]) -> bool:
    key = (version, os.environ.get("PATH", ""))
    with _fetch_lock:
        if key in _fetch_checked:
            return _fetch_checked[key]
        with tempfile.TemporaryDirectory(dir=runner.private_dir) as made:
            fetched = _probe_fetch(runner, Path(made))
        _fetch_checked[key] = fetched
        return fetched


def _probe_fetch(runner: GitRunner, top: Path) -> bool:
    source, probe, bundle = top / "source.git", top / "probe.git", top / "source.bundle"

    def git(args: list[str], git_dir: Path | None = None, *, ok: tuple[int, ...] = (0,)) -> bytes:
        env = {} if git_dir is None else {"GIT_DIR": str(git_dir), "GIT_COMMON_DIR": str(git_dir)}
        return runner.run(
            args,
            cwd=runner.private_dir,
            extra_env=env | _PROBE_PERSON,
            ok_codes=ok,
            timeout=_PROBE_SECONDS,
        )

    for folder in (source, probe):
        git(["init", "-q", "--bare", str(folder)])
    commit = git(["commit-tree", "-m", "probe", EMPTY_TREE], source).strip().decode("ascii")
    git(["update-ref", "refs/heads/main", commit], source)
    git(["bundle", "create", str(bundle), "refs/heads/main"], source)
    (probe / "config").write_text(
        _PROBE_CONFIG.format(source=source.as_uri(), bundle=bundle.as_uri()), encoding="utf-8"
    )
    before = _state(probe)
    git(["cat-file", "-e", commit], probe, ok=(0, 1, 128))
    return _state(probe) != before


def shadow_problem(
    runner: GitRunner,
    repo_git_dir: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    cancel: threading.Event | None = None,
) -> ShadowProblem | None:
    files = (
        (repo_git_dir / "commondir", ShadowProblem.LINKED_WORKTREE),
        (repo_git_dir / "objects" / "info" / "alternates", ShadowProblem.OWN_ALTERNATES),
        (repo_git_dir / "objects" / "info" / "http-alternates", ShadowProblem.OWN_HTTP_ALTERNATES),
        (repo_git_dir / "shallow", ShadowProblem.SHALLOW),
    )
    for path, problem in files:
        try:
            os.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            return ShadowProblem.UNREADABLE
        return problem
    worktree_problem = _worktree_problem(repo_git_dir)
    if worktree_problem is not None:
        return worktree_problem
    if any(mark in os.fsencode(repo_git_dir) for mark in (b"\n", b"\r")):
        return ShadowProblem.ODD_PATH
    try:
        linked = _linked_worktrees(repo_git_dir)
    except WorktreesUnreadable:
        return ShadowProblem.UNREADABLE
    for folder in (repo_git_dir, *linked):
        table_problem = _reftable_problem(folder)
        if table_problem is not None:
            return table_problem
        if _config_fetches(runner, folder, repo_git_dir, timeout=timeout, cancel=cancel):
            return ShadowProblem.FETCHES
    found = runner.run(
        ["rev-parse", "--show-object-format"],
        cwd=runner.private_dir,
        extra_env={"GIT_DIR": str(repo_git_dir), "GIT_COMMON_DIR": str(repo_git_dir)},
        timeout=timeout,
        cancel=cancel,
    )
    if found.strip() != b"sha1":
        return ShadowProblem.NOT_SHA1
    return None


_TABLES_MAX = 1 << 20
_CONFIG_MAX = 1 << 20
SHADOW_READ_MAX = 256 << 20
_FETCHING_KEYS = (b"extensions.partialclone", b"fetch.bundleuri")
_FETCHING_REMOTE_KEYS = (b"promisor", b"partialclonefilter")


def _config_fetches(
    runner: GitRunner,
    git_dir: Path,
    common: Path,
    *,
    timeout: float,
    cancel: threading.Event | None,
) -> bool:
    out = runner.run(
        ["config", "--includes", "--null", "--list"],
        cwd=runner.private_dir,
        extra_env={"GIT_DIR": str(git_dir), "GIT_COMMON_DIR": str(common)},
        ok_codes=(0, 1),
        timeout=timeout,
        cancel=cancel,
        max_stdout=_CONFIG_MAX,
    )
    for entry in out.split(b"\0"):
        key = entry.split(b"\n", 1)[0].lower()
        if key in _FETCHING_KEYS or key.startswith(b"hook."):
            return True
        if key.startswith(b"remote.") and key.rsplit(b".", 1)[-1] in _FETCHING_REMOTE_KEYS:
            return True
    return False


def _reftable_problem(folder: Path) -> ShadowProblem | None:
    path = folder / "reftable" / "tables.list"
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        return ShadowProblem.UNREADABLE
    try:
        fd = os.open(path, _READ_COMMONDIR)
    except OSError:
        return ShadowProblem.UNREADABLE
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ShadowProblem.UNREADABLE
        data = os.read(fd, _TABLES_MAX + 1)
    finally:
        os.close(fd)
    if len(data) > _TABLES_MAX:
        return ShadowProblem.UNREADABLE
    for name in data.splitlines():
        if name in (b"", b".", b"..") or any(mark in name for mark in (b"/", b"\\", b"\0")):
            return ShadowProblem.REFS_OUTSIDE
    return None


def _worktree_entries(git_dir: Path) -> list[os.DirEntry[str]]:
    try:
        with os.scandir(git_dir / "worktrees") as listing:
            return sorted(listing, key=lambda entry: entry.name)
    except (FileNotFoundError, NotADirectoryError):
        return []


def _linked_worktrees(git_dir: Path) -> list[Path]:
    found = []
    try:
        for entry in _worktree_entries(git_dir):
            try:
                os.lstat(Path(entry.path) / "HEAD")
            except (FileNotFoundError, NotADirectoryError):
                continue
            found.append(Path(entry.path))
    except OSError as exc:
        raise WorktreesUnreadable(exc.errno, "a worktree of the repository cannot be read") from exc
    return found


def _names_another_git_dir(folder: Path, own: str) -> bool:
    path = folder / "commondir"
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    fd = os.open(path, _READ_COMMONDIR)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("a linked worktree's commondir is not a regular file")
        data = os.read(fd, _COMMONDIR_MAX + 1)
    finally:
        os.close(fd)
    named = data.rstrip(b"\r\n")
    if not named or b"\0" in named or len(data) > _COMMONDIR_MAX:
        return True
    return os.path.realpath(os.path.join(folder, os.fsdecode(named))) != own


def _worktree_problem(repo_git_dir: Path) -> ShadowProblem | None:
    try:
        own = os.path.realpath(repo_git_dir)
        for entry in _worktree_entries(repo_git_dir):
            if entry.is_junction() or not entry.is_dir(follow_symlinks=False):
                return ShadowProblem.UNREADABLE
            if _names_another_git_dir(Path(entry.path), own):
                return ShadowProblem.FOREIGN_COMMONDIR
    except OSError:
        return ShadowProblem.UNREADABLE
    return None


def shadow_git_dir(
    runner: GitRunner,
    repo_git_dir: Path,
    into: Path,
    *,
    also: Sequence[Path] = (),
    timeout: float = DEFAULT_TIMEOUT,
    cancel: threading.Event | None = None,
) -> Path:
    if into.is_dir() and any(into.iterdir()):
        raise ShadowRefused("the shadow's folder is not empty")
    repo_git_dir = repo_git_dir.resolve()
    versions = [path.resolve() for path in also]
    for checked in (repo_git_dir, *versions):
        problem = shadow_problem(runner, checked, timeout=timeout, cancel=cancel)
        if problem is ShadowProblem.UNREADABLE:
            raise WorktreesUnreadable(None, SHADOW_PROBLEMS[problem])
        if problem is not None:
            raise ShadowRefused(SHADOW_PROBLEMS[problem])
    source = {"GIT_DIR": str(repo_git_dir)}
    into.mkdir(parents=True, exist_ok=True)
    into = into.resolve()
    objects = into / "objects"
    (objects / "info").mkdir(parents=True, exist_ok=True)
    (into / "refs").mkdir(exist_ok=True)
    borrowed = (repo_git_dir, *versions)
    (objects / "info" / "alternates").write_bytes(
        b"".join(
            os.fsencode(os.path.relpath(source / "objects", objects)) + b"\n" for source in borrowed
        )
    )

    refs = runner.run(
        ["for-each-ref", "--format=%(objectname) %(refname)"],
        cwd=into,
        extra_env=source,
        timeout=timeout,
        cancel=cancel,
        max_stdout=SHADOW_READ_MAX,
    )
    packed = dict(_ref_line(line) for line in refs.splitlines())
    _write_packed_refs(into, packed)

    symbolic = runner.run(
        ["symbolic-ref", "--quiet", "HEAD"],
        cwd=into,
        extra_env=source,
        ok_codes=(0, 1),
        timeout=timeout,
        cancel=cancel,
    ).strip()
    if symbolic:
        head = b"ref: " + symbolic
    else:
        head = runner.run(
            ["rev-parse", "--verify", "HEAD"],
            cwd=into,
            extra_env=source,
            timeout=timeout,
            cancel=cancel,
        ).strip()
    (into / "HEAD").write_bytes(head + b"\n")
    (into / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
        "\tuseReplaceRefs = false\n\tcommitGraph = false\n\tmultiPackIndex = false\n"
    )

    carried = set(_shadow_tips(runner, into, timeout=timeout, cancel=cancel))
    candidates = list(
        dict.fromkeys(
            tip
            for source in borrowed
            for tip in repo_tips(
                runner, source, timeout=timeout, cancel=cancel, max_stdout=SHADOW_READ_MAX
            )
            if tip not in carried
        )
    )
    missing = _unreached(runner, into, candidates, timeout=timeout, cancel=cancel)
    if missing:
        prefix = _free_ref_folder(packed)
        packed.update((prefix + b"/%d" % n, tip) for n, tip in enumerate(missing))
        _write_packed_refs(into, packed)
    return into


def _ref_line(line: bytes) -> tuple[bytes, bytes]:
    oid, name = line.split(b" ", 1)
    return name, oid


def _write_packed_refs(into: Path, refs: Mapping[bytes, bytes]) -> None:
    lines = b"".join(b"%s %s\n" % (refs[name], name) for name in sorted(refs))
    (into / "packed-refs").write_bytes(b"# pack-refs with: sorted\n" + lines)


def repo_tips(
    runner: GitRunner,
    repo_git_dir: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    deadline: float | None = None,
    cancel: threading.Event | None = None,
    max_stdout: int | None = None,
) -> list[bytes]:
    problem = _worktree_problem(repo_git_dir)
    if problem is ShadowProblem.UNREADABLE:
        raise WorktreesUnreadable(None, "a worktree of the repository cannot be read")
    if problem is not None:
        raise ShadowRefused(SHADOW_PROBLEMS[problem])
    reads: list[tuple[list[str], dict[str, str]]] = [(["--reflog"], {"GIT_DIR": str(repo_git_dir)})]
    reads += [
        ([], {"GIT_DIR": str(folder), "GIT_COMMON_DIR": str(repo_git_dir)})
        for folder in _linked_worktrees(repo_git_dir)
    ]
    tips: dict[bytes, None] = {}
    for more, env in reads:
        each = timeout
        if deadline is not None:
            each = min(timeout, deadline - time.monotonic())
            if each <= 0:
                raise GitTimeout("rev-list", 0)
        out = runner.run(
            ["rev-list", "--all", *more, "--no-walk=unsorted"],
            cwd=runner.private_dir,
            extra_env=env,
            timeout=each,
            cancel=cancel,
            max_stdout=max_stdout,
        )
        tips.update(dict.fromkeys(out.split()))
    return list(tips)


def _shadow_tips(
    runner: GitRunner, shadow: Path, *, timeout: float, cancel: threading.Event | None
) -> list[bytes]:
    out = runner.run(
        ["rev-list", "--all", "--no-walk=unsorted"],
        cwd=runner.private_dir,
        extra_env={"GIT_DIR": str(shadow)},
        timeout=timeout,
        cancel=cancel,
        max_stdout=SHADOW_READ_MAX,
    )
    return out.split()


def _unreached(
    runner: GitRunner,
    shadow: Path,
    candidates: Sequence[bytes],
    *,
    timeout: float,
    cancel: threading.Event | None,
) -> list[bytes]:
    if not candidates:
        return []
    out = runner.run(
        ["rev-list", "--stdin", "--not", "--all"],
        cwd=runner.private_dir,
        stdin=b"".join(tip + b"\n" for tip in candidates),
        extra_env={"GIT_DIR": str(shadow)},
        timeout=timeout,
        cancel=cancel,
        max_stdout=SHADOW_READ_MAX,
    )
    printed = set(out.split())
    return sorted({tip for tip in candidates if tip in printed})


def _free_ref_folder(refs: Collection[bytes]) -> bytes:
    folders = {name[:end] for name in refs for end in _slashes(name)}
    n = 0
    while True:
        prefix = b"refs/gitmortem/tips" if n == 0 else b"refs/gitmortem-%d/tips" % n
        taken = prefix in refs or prefix in folders
        if not taken and not any(prefix[:end] in refs for end in _slashes(prefix)):
            return prefix
        n += 1


def _slashes(name: bytes) -> Iterator[int]:
    return (n for n, byte in enumerate(name) if byte == 0x2F)
