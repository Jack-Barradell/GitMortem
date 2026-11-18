import os
import shutil
import subprocess
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import IO, cast

from gitmortem.gitrun import (
    CANCEL_POLL,
    FILE_CLONE,
    NO_FETCH_ENV,
    Discard,
    check_extra_config,
    exited,
    inherited_env,
    safe_config,
    spawned,
    wait,
)
from gitmortem.scanning.trace import trace_dir

__all__ = [
    "DISK_FLOOR",
    "SpaceWatch",
    "ToolEnv",
    "ToolOutputTooLarge",
    "never_made",
    "run_tool_process",
    "tool_env",
    "watched_space",
]

DISK_FLOOR = 64 << 20
SPACE_POLL = 0.5

type ToolEnv = dict[str, str]


class ToolOutputTooLarge(Exception):
    def __init__(self, tool: str, limit: int) -> None:
        super().__init__(f"{tool} wrote more than {limit} bytes")
        self.tool = tool
        self.limit = limit


class SpaceWatch:
    def __init__(self, folder: Path, floor: int) -> None:
        self.folder = folder
        self.floor = floor
        self.low = False

    def sample(self) -> None:
        try:
            free = shutil.disk_usage(self.folder).free
        except OSError:
            return
        if free < self.floor:
            self.low = True


@contextmanager
def watched_space(folder: Path, floor: int = DISK_FLOOR) -> Iterator[SpaceWatch]:
    watch = SpaceWatch(folder, floor)
    watch.sample()
    stop = threading.Event()

    def loop() -> None:
        while not stop.wait(SPACE_POLL):
            watch.sample()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        yield watch
    finally:
        stop.set()
        thread.join()
        watch.sample()


def never_made(private: Path) -> Path:
    return private.with_name(f"{private.name}.never")


def tool_env(private: Path, *, extra_config: Sequence[tuple[str, str]] = ()) -> ToolEnv:
    check_extra_config(extra_config, file_clone=True)
    never = never_made(private)
    pairs = [*safe_config(str(never / "hooks")), *extra_config]
    env = {
        **inherited_env(posix=os.name == "posix"),
        "HOME": str(private),
        "TMPDIR": str(private),
        "TMP": str(private),
        "TEMP": str(private),
        "LC_ALL": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_GRAFT_FILE": str(never / "no-grafts"),
        **NO_FETCH_ENV,
        "GIT_TRACE2_EVENT": str(trace_dir(private)),
        "GIT_CONFIG_COUNT": str(len(pairs)),
    }
    if FILE_CLONE in extra_config:
        del env["GIT_ALLOW_PROTOCOL"]
    for n, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{n}"] = key
        env[f"GIT_CONFIG_VALUE_{n}"] = value
    return env


def _feed_stdin(proc: "subprocess.Popen[bytes]", data: bytes) -> None:
    pipe = cast(IO[bytes], proc.stdin)
    fd = os.dup(pipe.fileno())
    pipe.close()

    def feed() -> None:
        view = memoryview(data)
        try:
            while view:
                view = view[os.write(fd, view) :]
        except OSError:
            pass
        finally:
            os.close(fd)

    threading.Thread(target=feed, daemon=True).start()


def run_tool_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    stdout: Path | Discard | int,
    stderr: Path | Discard | int,
    timeout: float,
    cancel: threading.Event | None,
    max_output: int | None = None,
    stdin_bytes: bytes | None = None,
) -> int:
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError("a tool runs by the absolute path its detection found")
    name = Path(argv[0]).name
    posix = os.name == "posix"
    with spawned(
        list(argv),
        cwd=cwd,
        env=dict(env),
        stdin=stdin_bytes is not None,
        stdout=stdout,
        stderr=stderr,
        posix=posix,
    ) as (proc, outputs):
        if stdin_bytes is not None:
            _feed_stdin(proc, stdin_bytes)

        def written() -> int:
            return sum(os.fstat(fd).st_size for fd in outputs)

        def step(left: float) -> None:
            if max_output is None:
                exited(proc, left, posix=posix)
                return
            try:
                exited(proc, min(left, CANCEL_POLL), posix=posix)
            except subprocess.TimeoutExpired:
                if written() > max_output:
                    raise ToolOutputTooLarge(name, max_output) from None
                raise

        wait(proc, step, subcommand=name, timeout=timeout, cancel=cancel, posix=posix, command=name)
        if max_output is not None and written() > max_output:
            raise ToolOutputTooLarge(name, max_output)
    return proc.returncode
