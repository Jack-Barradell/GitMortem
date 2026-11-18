import base64
import json
import re
import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from gitmortem.gitread import OBJECT_ID
from gitmortem.gitrun import GitError, GitRunner, _free_ref_folder

__all__ = [
    "CARRIER_PART",
    "Carried",
    "CarrierMap",
    "Census",
    "carrier_findings_place",
    "load_map",
    "plant_carrier",
    "take_census",
]

CARRIER_PART = "carrier"
MESSAGES = "m"
TAGS = "t"
OBJECTS = "o"
NAMES = "n"
KEYS = "k"
MAX_CARRIED_BYTES = 64 << 20
MAX_ENTRIES = 200_000
MAX_REFS = 100_000
MAX_NAMES = 500_000
MAX_SIZES = 100_000
MAX_HELD = 1 << 20
HEAD = 8000
LONG_LINE = 10 << 20
BIG_FILE = 512 << 20
MEBIBYTE = 1 << 20
_LOG_MAX = 256 << 20
_LINK = b"120000"
_NO_OBJECT = b"0" * 40
_PERSON = "GitMortem <carrier@gitmortem.invalid> 1 +0000"
_MESSAGE = b"GitMortem carrier\n"
_LFS = b"version https://git-lfs.github.com/spec/v1"
_LINE_HEAD = 256
_KEY = re.compile(rb"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
_KEY_HELD = 64
_ARCHIVES = (
    (0, b"PK\x03\x04"),
    (0, b"\x1f\x8b"),
    (0, b"!<arch>\n"),
    (0, b"7z\xbc\xaf\x27\x1c"),
    (0, b"\xfd7zXZ\x00"),
    (0, b"BZh"),
    (0, b"\x28\xb5\x2f\xfd"),
    (0, b"Rar!\x1a\x07"),
    (257, b"ustar"),
)
_WIDE_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")


@dataclass
class Census:
    archives: int = 0
    encoded_text: int = 0
    lfs_pointers: int = 0
    binary: int = 0
    long_lines: int = 0
    big_files: int = 0
    merges_with_own_text: int = 0
    type_changes: int = 0
    not_carried: int = 0
    large_sizes: list[int] = field(default_factory=list)

    def over(self, megabytes: int) -> int:
        limit = megabytes * MEBIBYTE
        return sum(1 for size in self.large_sizes if size > limit)


@dataclass(frozen=True)
class Carried:
    commit: str
    path: bytes
    place: str
    line: int


@dataclass(frozen=True)
class CarrierMap:
    commit: str
    names: dict[str, list[tuple[bytes, str]]] = field(default_factory=dict, repr=False)
    keys: dict[str, tuple[str, bytes]] = field(default_factory=dict, repr=False)

    def dumps(self) -> bytes:
        return json.dumps(
            {
                "commit": self.commit,
                "names": {
                    commit: [[base64.b64encode(path).decode(), kind] for path, kind in held]
                    for commit, held in self.names.items()
                },
                "keys": {
                    blob: [commit, base64.b64encode(path).decode()]
                    for blob, (commit, path) in self.keys.items()
                },
            },
            sort_keys=True,
        ).encode()


def load_map(data: bytes) -> CarrierMap | None:
    try:
        held = json.loads(data)
        commit = held["commit"]
        if not isinstance(commit, str) or OBJECT_ID.fullmatch(commit.encode()) is None:
            return None
        names = {
            str(commit_id): [(base64.b64decode(path), str(kind)) for path, kind in entries]
            for commit_id, entries in held["names"].items()
        }
        keys = {
            str(blob): (str(commit_id), base64.b64decode(path))
            for blob, (commit_id, path) in held["keys"].items()
        }
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    return CarrierMap(commit, names, keys)


def carrier_findings_place(held: CarrierMap, path: bytes, line: int) -> Carried | None:
    kind, _, rest = path.partition(b"/")
    target, _, inner = rest.partition(b"/")
    if OBJECT_ID.fullmatch(target) is None:
        return None
    sha = target.decode("ascii")
    if kind == MESSAGES.encode() and not inner:
        return Carried(sha, b"", "message", line)
    if kind == TAGS.encode() and not inner:
        return Carried(sha, b"", "tag", line)
    if kind == OBJECTS.encode():
        return Carried(sha, inner, "object", line)
    if kind == NAMES.encode() and not inner:
        names = held.names.get(sha, [])
        if not 1 <= line <= len(names):
            return None
        return Carried(sha, names[line - 1][0], "name", 0)
    if kind == KEYS.encode() and not inner and sha in held.keys:
        commit, at = held.keys[sha]
        return Carried(commit, at, "line", line)
    return None


@dataclass
class _Plan:
    messages: dict[str, bytes] = field(default_factory=dict, repr=False)
    tags: dict[str, bytes] = field(default_factory=dict, repr=False)
    objects: dict[str, str] = field(default_factory=dict)
    refs: set[str] = field(default_factory=set)
    keys: set[str] = field(default_factory=set)
    links: set[str] = field(default_factory=set)
    heads: dict[str, bytes] = field(default_factory=dict, repr=False)
    size: int = 0


class _Blob:
    def __init__(self, size: int, keep: bool) -> None:
        self.size = size
        self.head = bytearray()
        self.keep = keep
        self.run = 0
        self.longest = 0
        self.tail = b""
        self.key = False

    def feed(self, data: bytes) -> None:
        if len(self.head) < HEAD:
            self.head += data[: HEAD - len(self.head)]
        if self.size > LONG_LINE:
            cut = data.rfind(b"\n")
            if cut == -1:
                self.run += len(data)
            else:
                self.longest = max(self.longest, self.run + data.find(b"\n"))
                self.run = len(data) - cut - 1
            self.longest = max(self.longest, self.run)
        if not self.key:
            window = self.tail + data
            self.key = _KEY.search(window) is not None
            self.tail = window[-_KEY_HELD:]


def _wide(head: bytes) -> bool:
    if head.startswith(_WIDE_BOMS):
        return True
    sample = head[:512]
    if len(sample) < 16:
        return False
    for zeros, text in ((sample[1::2], sample[0::2]), (sample[0::2], sample[1::2])):
        if zeros.count(0) == len(zeros) and all(
            32 <= byte < 127 or byte in b"\t\r\n" for byte in text
        ):
            return True
    return False


def _classify(census: Census, blob: _Blob) -> None:
    head = bytes(blob.head)
    if blob.size > MEBIBYTE and len(census.large_sizes) < MAX_SIZES:
        census.large_sizes.append(blob.size)
    if blob.size > BIG_FILE:
        census.big_files += 1
    if blob.longest > LONG_LINE:
        census.long_lines += 1
    if head.startswith(_LFS):
        census.lfs_pointers += 1
    elif _wide(head):
        census.encoded_text += 1
    elif any(head[at : at + len(magic)] == magic for at, magic in _ARCHIVES):
        census.archives += 1
    elif b"\0" in head:
        census.binary += 1


def _objects(chunks: Iterable[bytes], plan: _Plan, census: Census) -> None:
    stream = iter(chunks)
    held = bytearray()

    def more() -> bool:
        for chunk in stream:
            if chunk:
                held.extend(chunk)
                return True
        return False

    while True:
        newline = held.find(b"\n")
        while newline == -1:
            if not more():
                if held:
                    raise GitError("cat-file", 0, "git cat-file ended inside an object's header")
                return
            newline = held.find(b"\n")
        header = bytes(held[:newline]).split(b" ")
        del held[: newline + 1]
        if len(header) != 3 or OBJECT_ID.fullmatch(header[0]) is None:
            raise GitError("cat-file", 0, "git cat-file printed a header it should not")
        sha, kind, size = header[0].decode("ascii"), header[1], int(header[2])
        blob = _Blob(size, sha in plan.links) if kind == b"blob" else None
        body = bytearray()
        left = size
        while left:
            if not held and not more():
                raise GitError("cat-file", 0, "git cat-file ended inside an object")
            take = bytes(held[: min(left, len(held))])
            del held[: len(take)]
            left -= len(take)
            if blob is not None:
                blob.feed(take)
            elif kind in (b"commit", b"tag") and len(body) < MAX_HELD:
                body += take[: MAX_HELD - len(body)]
        if not held and not more():
            raise GitError("cat-file", 0, "git cat-file ended before an object's newline")
        del held[:1]
        if blob is not None:
            _classify(census, blob)
            if blob.key:
                plan.keys.add(sha)
            if blob.keep:
                plan.heads[sha] = bytes(blob.head)
        elif kind in (b"commit", b"tag"):
            if size > MAX_HELD:
                census.not_carried += 1
            if kind == b"commit":
                _carry(plan, census, plan.messages, sha, _message(bytes(body)))
            else:
                _tag(plan, census, sha, bytes(body))


def _message(body: bytes) -> bytes:
    at = body.find(b"\n\n")
    return b"" if at == -1 else body[at + 2 :]


def _carry(plan: _Plan, census: Census, into: dict[str, bytes], sha: str, text: bytes) -> None:
    if not text.strip():
        return
    if _wide(text):
        census.encoded_text += 1
    text = text.replace(b"\0", b" ")
    if (
        plan.size + len(text) > MAX_CARRIED_BYTES
        or len(plan.messages) + len(plan.tags) >= MAX_ENTRIES
    ):
        census.not_carried += 1
        return
    plan.size += len(text)
    into[sha] = text


def _tag(plan: _Plan, census: Census, sha: str, body: bytes) -> None:
    head = body.split(b"\n\n", 1)[0].split(b"\n")
    target = next((line[7:] for line in head if line.startswith(b"object ")), b"")
    kind = next((line[5:] for line in head if line.startswith(b"type ")), b"")
    if OBJECT_ID.fullmatch(target) is not None:
        if kind == b"commit":
            plan.refs.add(target.decode("ascii"))
        elif kind in (b"blob", b"tree"):
            plan.objects[target.decode("ascii")] = kind.decode("ascii")
    _carry(plan, census, plan.tags, sha, _message(body))


@dataclass
class _Changes:
    names: dict[str, list[tuple[bytes, str]]] = field(default_factory=dict, repr=False)
    first: dict[str, tuple[str, bytes]] = field(default_factory=dict, repr=False)
    links: dict[str, list[tuple[bytes, str]]] = field(default_factory=dict, repr=False)
    count: int = 0


def _changes(chunks: Iterable[bytes], plan: _Plan, census: Census) -> _Changes:
    found = _Changes()
    commit: str | None = None
    header: list[bytes] | None = None
    typed: set[str] = set()
    for token in _tokens(chunks):
        if header is not None:
            _entry(found, plan, census, commit, header, token, typed)
            header = None
        elif token.startswith(b":"):
            header = token[1:].split(b" ")
        elif OBJECT_ID.fullmatch(token) is not None:
            commit = token.decode("ascii")
        else:
            raise GitError("diff-tree", 0, "git diff-tree printed a line it should not")
    census.type_changes = len(typed)
    return found


def _entry(
    found: _Changes,
    plan: _Plan,
    census: Census,
    commit: str | None,
    header: list[bytes],
    path: bytes,
    typed: set[str],
) -> None:
    if commit is None or len(header) != 5:
        raise GitError("diff-tree", 0, "git diff-tree printed a change outside a commit")
    mode, sha, status = header[1], header[3], header[4]
    if status == b"T":
        typed.add(commit)
    if status not in (b"A", b"M", b"T") or sha == _NO_OBJECT:
        return
    blob = sha.decode("ascii")
    found.first.setdefault(blob, (commit, path))
    if status != b"A":
        return
    if b"\n" in path or found.count >= MAX_NAMES:
        census.not_carried += 1
        return
    found.count += 1
    found.names.setdefault(commit, []).append((path, "name"))
    if mode == _LINK:
        plan.links.add(blob)
        found.links.setdefault(blob, []).append((path, commit))


def _line_heads(chunks: Iterable[bytes]) -> Iterator[bytes]:
    head = bytearray()
    for chunk in chunks:
        start = 0
        while (end := chunk.find(b"\n", start)) != -1:
            if len(head) < _LINE_HEAD:
                head += chunk[start : min(end, start + _LINE_HEAD - len(head))]
            yield bytes(head)
            head.clear()
            start = end + 1
        if len(head) < _LINE_HEAD:
            head += chunk[start : start + _LINE_HEAD - len(head)]
    if head:
        yield bytes(head)


def _own_text(chunks: Iterable[bytes]) -> int:
    marked: set[bytes] = set()
    commit: bytes | None = None
    parents = 0
    in_file = False
    for line in _line_heads(chunks):
        if OBJECT_ID.fullmatch(line) is not None:
            commit, parents, in_file = line, 0, False
            continue
        if commit is None:
            raise GitError("diff-tree", 0, "git diff-tree printed a diff outside a merge")
        if commit in marked:
            continue
        if line.startswith((b"diff --cc ", b"diff --combined ")):
            in_file, parents = True, 0
        elif not in_file:
            marked.add(commit)
        elif line.startswith(b"@"):
            ats = len(line) - len(line.lstrip(b"@"))
            if ats < 3 or ats >= _LINE_HEAD:
                marked.add(commit)
            parents = ats - 1
        elif parents == 0:
            if line.startswith(b"Binary files "):
                marked.add(commit)
        elif not line.startswith(b"\\"):
            prefix = line[:parents]
            if len(prefix) == parents and (prefix == b"+" * parents or prefix.strip(b" +-")):
                marked.add(commit)
    return len(marked)


def _tokens(chunks: Iterable[bytes]) -> Iterator[bytes]:
    held = b""
    for chunk in chunks:
        held += chunk
        parts = held.split(b"\0")
        held = parts.pop()
        yield from parts
    if held:
        yield held


def take_census(
    runner: GitRunner,
    shadow: Path,
    *,
    timeout: float,
    cancel: threading.Event | None,
    merges: bool = False,
) -> tuple[Census, "_Plan", "_Changes"]:
    census = Census()
    plan = _Plan()
    env = {"GIT_DIR": str(shadow)}
    commits = runner.run(
        ["rev-list", "--all"],
        cwd=runner.private_dir,
        extra_env=env,
        timeout=timeout,
        cancel=cancel,
        max_stdout=_LOG_MAX,
    )
    with runner.stream(
        [
            "diff-tree",
            "--stdin",
            "-r",
            "-z",
            "--root",
            "--no-renames",
            "--no-textconv",
            "--no-ext-diff",
            "--diff-merges=first-parent",
        ],
        cwd=runner.private_dir,
        stdin=commits,
        extra_env=env,
        timeout=timeout,
        cancel=cancel,
    ) as chunks:
        changes = _changes(chunks, plan, census)
    if merges:
        census.merges_with_own_text = _merges_with_own_text(runner, env, timeout, cancel)
    with runner.stream(
        ["cat-file", "--batch-all-objects", "--batch", "--unordered"],
        cwd=runner.private_dir,
        extra_env=env,
        timeout=timeout,
        cancel=cancel,
    ) as chunks:
        _objects(chunks, plan, census)
    return census, plan, changes


def _merges_with_own_text(
    runner: GitRunner, env: dict[str, str], timeout: float, cancel: threading.Event | None
) -> int:
    merges = runner.run(
        ["rev-list", "--all", "--merges"],
        cwd=runner.private_dir,
        extra_env=env,
        timeout=timeout,
        cancel=cancel,
        max_stdout=_LOG_MAX,
    )
    if not merges.strip():
        return 0
    with runner.stream(
        [
            "diff-tree",
            "--stdin",
            "--cc",
            "-p",
            "--no-color",
            "--no-renames",
            "--no-textconv",
            "--no-ext-diff",
        ],
        cwd=runner.private_dir,
        stdin=merges,
        extra_env=env,
        timeout=timeout,
        cancel=cancel,
    ) as chunks:
        return _own_text(chunks)


def _refs(
    runner: GitRunner, shadow: Path, timeout: float, cancel: threading.Event | None
) -> list[bytes]:
    out = runner.run(
        ["for-each-ref", "--format=%(objectname) %(objecttype) %(refname)"],
        cwd=runner.private_dir,
        extra_env={"GIT_DIR": str(shadow)},
        timeout=timeout,
        cancel=cancel,
        max_stdout=_LOG_MAX,
    )
    return [line for line in out.split(b"\n") if line]


def _fast_import(plan: _Plan, changes: _Changes, keep_names: bool, ref: bytes) -> bytes:
    out = bytearray()
    entries: list[bytes] = []
    marks = 0

    def blob(text: bytes) -> bytes:
        nonlocal marks
        marks += 1
        out.extend(b"blob\nmark :%d\ndata %d\n" % (marks, len(text)))
        out.extend(text)
        out.extend(b"\n")
        return b":%d" % marks

    for sha, text in sorted(plan.messages.items()):
        entries.append(b"M 100644 %s %s/%s\n" % (blob(text), MESSAGES.encode(), sha.encode()))
    for sha, text in sorted(plan.tags.items()):
        entries.append(b"M 100644 %s %s/%s\n" % (blob(text), TAGS.encode(), sha.encode()))
    for sha, kind in sorted(plan.objects.items()):
        mode = b"040000" if kind == "tree" else b"100644"
        entries.append(b"M %s %s %s/%s\n" % (mode, sha.encode(), OBJECTS.encode(), sha.encode()))
    for sha in sorted(plan.keys):
        if sha in changes.first:
            entries.append(b"M 100644 %s %s/%s\n" % (sha.encode(), KEYS.encode(), sha.encode()))
    if keep_names:
        for commit, held in sorted(changes.names.items()):
            text = b"".join(path + b"\n" for path, _ in held)
            entries.append(b"M 100644 %s %s/%s\n" % (blob(text), NAMES.encode(), commit.encode()))
    out.extend(b"commit %s\ncommitter %s\ndata %d\n" % (ref, _PERSON.encode(), len(_MESSAGE)))
    out.extend(_MESSAGE)
    out.extend(b"".join(entries))
    out.extend(b"done\n")
    return bytes(out)


def _with_targets(plan: _Plan, changes: _Changes) -> None:
    for blob, places in changes.links.items():
        target = plan.heads.get(blob)
        if target is None or b"\n" in target:
            continue
        for path, commit in places:
            held = changes.names.get(commit, [])
            at = next((n for n, (name, _) in enumerate(held) if name == path), None)
            if at is not None:
                held.insert(at + 1, (target, "target"))


def plant_carrier(
    runner: GitRunner,
    shadow: Path,
    *,
    dangling: Iterable[tuple[str, str]],
    timeout: float,
    cancel: threading.Event | None,
    merges: bool = False,
) -> tuple[Census, CarrierMap | None]:
    census, plan, changes = take_census(
        runner, shadow, timeout=timeout, cancel=cancel, merges=merges
    )
    _with_targets(plan, changes)
    for sha, kind in dangling:
        if kind == "commit":
            plan.refs.add(sha)
        elif kind in ("blob", "tree"):
            plan.objects[sha] = kind
    refs = _refs(runner, shadow, timeout, cancel)
    for line in refs:
        named, typed, _ = line.split(b" ", 2)
        if typed in (b"blob", b"tree"):
            plan.objects[named.decode("ascii")] = typed.decode("ascii")
    env = {"GIT_DIR": str(shadow)}
    folder = _free_ref_folder([line.split(b" ", 2)[2] for line in refs])
    walked = sorted(plan.refs)
    if len(walked) > MAX_REFS:
        census.not_carried += len(walked) - MAX_REFS
        walked = walked[:MAX_REFS]
    if walked:
        runner.run(
            ["update-ref", "--stdin"],
            cwd=runner.private_dir,
            stdin=b"".join(
                b"create %s/reached/%s %s\n" % (folder, sha.encode(), sha.encode())
                for sha in walked
            ),
            extra_env=env,
            timeout=timeout,
            cancel=cancel,
        )
    if len(plan.objects) > MAX_ENTRIES:
        census.not_carried += len(plan.objects) - MAX_ENTRIES
        plan.objects = dict(sorted(plan.objects.items())[:MAX_ENTRIES])
    names_bytes = sum(len(path) + 1 for held in changes.names.values() for path, _ in held)
    keep_names = names_bytes + plan.size <= MAX_CARRIED_BYTES
    if not keep_names and changes.names:
        census.not_carried += len(changes.names)
    ref = folder + b"/carrier"
    runner.run(
        ["fast-import", "--quiet", "--done", "--date-format=raw"],
        cwd=runner.private_dir,
        stdin=_fast_import(plan, changes, keep_names, ref),
        extra_env=env,
        timeout=timeout,
        cancel=cancel,
    )
    commit = runner.run(
        ["rev-parse", "--verify", "--end-of-options", ref + b"^{commit}"],
        cwd=runner.private_dir,
        extra_env=env,
        timeout=timeout,
        cancel=cancel,
    ).strip()
    if OBJECT_ID.fullmatch(commit) is None:
        raise GitError("rev-parse", 0, "git rev-parse did not name the carrier")
    keys = {sha: changes.first[sha] for sha in plan.keys if sha in changes.first}
    names = changes.names if keep_names else {}
    return census, CarrierMap(commit.decode("ascii"), names, keys)
