import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from gitmortem.corpus.fakes import SecretType, make_secret
from gitmortem.corpus.rng import Rng
from gitmortem.gitread import OBJECT_ID
from gitmortem.gitrun import GitError, GitRunner, _free_ref_folder

__all__ = ["CANARY_FILE", "CANDIDATES", "Canary", "Candidate", "chosen", "plant_canary"]

CANARY_FILE = "gitmortem-canary.txt"
_NAME = "GitMortem"
_EMAIL = "canary@gitmortem.invalid"
_DATE = "@1 +0000"
_MESSAGE = "GitMortem canary"
_NO_OBJECT = "0" * 40
_PLACEHOLDER_WORDS = ("true", "false", "null")
_MAX_DRAWS = 100


@dataclass(frozen=True)
class Candidate:
    kind: SecretType
    gitleaks: str
    trufflehog: str


CANDIDATES: tuple[Candidate, ...] = (
    Candidate(SecretType.GITHUB_PAT, "github-pat", "Github"),
    Candidate(SecretType.SLACK_BOT_TOKEN, "slack-bot-token", "Slack"),
)


@dataclass(frozen=True)
class Canary:
    kind: SecretType
    commit: str
    value: str = field(repr=False)


def chosen(keeps: Callable[[SecretType], bool]) -> Candidate | None:
    return next((candidate for candidate in CANDIDATES if keeps(candidate.kind)), None)


def _draw(kind: SecretType) -> str:
    for _ in range(_MAX_DRAWS):
        value = make_secret(kind, Rng(os.urandom(32))).value
        lowered = value.lower()
        if not any(word in lowered for word in _PLACEHOLDER_WORDS):
            return value
    raise RuntimeError("no canary value cleared the placeholder words")


def _object_id(out: bytes, subcommand: str) -> str:
    found = out.strip()
    if OBJECT_ID.fullmatch(found) is None:
        raise GitError(subcommand, 0, f"git {subcommand} did not print an object id")
    return found.decode("ascii")


def plant_canary(
    runner: GitRunner,
    shadow: Path,
    *,
    keeps: Callable[[SecretType], bool],
    timeout: float,
    cancel: threading.Event | None,
) -> Canary | None:
    candidate = chosen(keeps)
    if candidate is None:
        return None
    value = _draw(candidate.kind)

    def git(args: list[str | bytes], *, stdin: bytes | None = None, **env: str) -> bytes:
        return runner.run(
            args,
            cwd=runner.private_dir,
            stdin=stdin,
            extra_env={"GIT_DIR": str(shadow), **env},
            timeout=timeout,
            cancel=cancel,
        )

    blob = _object_id(
        git(["hash-object", "-w", "--stdin"], stdin=f"token = {value}\n".encode()), "hash-object"
    )
    tree = _object_id(
        git(["mktree"], stdin=f"100644 blob {blob}\t{CANARY_FILE}\n".encode()), "mktree"
    )
    commit = _object_id(
        git(
            ["commit-tree", tree, "-m", _MESSAGE],
            GIT_AUTHOR_NAME=_NAME,
            GIT_AUTHOR_EMAIL=_EMAIL,
            GIT_AUTHOR_DATE=_DATE,
            GIT_COMMITTER_NAME=_NAME,
            GIT_COMMITTER_EMAIL=_EMAIL,
            GIT_COMMITTER_DATE=_DATE,
        ),
        "commit-tree",
    )
    names = [name for name in git(["for-each-ref", "--format=%(refname)"]).split(b"\n") if name]
    git(["update-ref", _free_ref_folder(names) + b"/canary", commit, _NO_OBJECT])
    return Canary(candidate.kind, commit, value)
