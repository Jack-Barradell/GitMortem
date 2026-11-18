import contextlib
import os
import stat
import sys
from pathlib import Path

from gitmortem import __version__
from gitmortem.corpus.errors import CorpusError
from gitmortem.corpus.history import write_repo
from gitmortem.corpus.hostile import plant_hostile
from gitmortem.corpus.manifest import GeneratorInfo, Manifest, Size
from gitmortem.corpus.recipe import plan_corpus, realise, secret_entries
from gitmortem.corpus.rng import Rng
from gitmortem.gitrun import git_runner, require_git

__all__ = [
    "DEFAULT_SEED",
    "CorpusError",
    "Manifest",
    "Size",
    "generate",
    "preflight",
]

DEFAULT_SEED = 2026

_README = """\
GitMortem demo corpus
=====================

Written by the GitMortem {version} corpus generator: seed {seed}, size {size}.

Every secret in these repositories is fake. The values were generated from the seed above and
are shaped so that real secret scanners report them, but none of them is valid anywhere.

  repos/         the scan root: point GitMortem or a scanner here

Never push these repositories anywhere or copy their files into a real project: the values
would trip secret scanners and push protection. Delete the whole directory when you are done.
"""

_HOSTILE_README = """
It also holds hostile repositories for security tests, written because --hostile was given:

  repos/hostile/  repos that run a command when git or a scanner is used on them naively, try to
                  silence each scanner, hide history from git, carry odd file names, or link out
                  of the scan root
  outside/        where those links lead: a file and a repository outside the scan root
  markers/        empty; a file appears here when a hostile repository's command has run

Do not run git, or a scanner with its default settings, inside repos/hostile/ unless that is
what you are testing.
"""


def _require_empty(target: Path) -> None:
    if not target.exists():
        return
    if not target.is_dir():
        raise CorpusError(f"{target} is not a directory; choose an empty or new directory")
    if any(target.iterdir()):
        raise CorpusError(f"{target} is not empty; choose an empty or new directory")


def _posix() -> bool:
    return os.name == "posix"


def _claim(target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileExistsError):
        os.mkdir(target, 0o700)
    held = os.lstat(target)
    if stat.S_ISLNK(held.st_mode) or not stat.S_ISDIR(held.st_mode):
        raise CorpusError(f"{target} is not a directory; choose an empty or new directory")
    if sys.platform != "win32" and _posix():
        if held.st_uid != os.geteuid():
            raise CorpusError(f"{target} belongs to another user; choose your own directory")
        if held.st_mode & 0o022:
            raise CorpusError(f"{target} can be changed by other users; make it 0700 first")
    if os.listdir(target):
        raise CorpusError(f"{target} is not empty; choose an empty or new directory")


def preflight(target: Path, *, hostile: bool = False) -> None:
    if hostile and not _posix():
        raise CorpusError("--hostile needs a POSIX system (macOS or Linux)")
    _require_empty(target)
    with git_runner() as runner:
        require_git(runner)


def generate(
    target: Path, *, seed: int = DEFAULT_SEED, size: Size = Size.SMALL, hostile: bool = False
) -> Manifest:
    target = target.resolve()
    preflight(target, hostile=hostile)
    with git_runner() as runner:
        plan = plan_corpus(seed, size)
        _claim(target)
        marks_dir = runner.private_dir / "marks"
        entries = []
        found = []
        for repo in plan.repos:
            marks = write_repo(
                runner, target / repo.path, repo.history, bare=repo.bare, marks_dir=marks_dir
            )
            entry, occurrences = realise(repo, marks)
            entries.append(entry)
            found += occurrences
        for path, content in plan.loose_files:
            (target / path).parent.mkdir(parents=True, exist_ok=True)
            (target / path).write_bytes(content)
        if hostile:
            rng = Rng.from_seed(seed).derive("corpus hostile")
            more, occurrences = plant_hostile(runner, target, rng, plan.values)
            entries += more
            found += occurrences

    manifest = Manifest(
        format=1,
        generator=GeneratorInfo(version=__version__, seed=seed, size=size, hostile=hostile),
        repos=sorted(entries, key=lambda entry: entry.id),
        secrets=secret_entries(found, plan.values),
        non_repo_paths=list(plan.non_repo_paths),
    )
    readme = _README.format(version=__version__, seed=seed, size=size.value)
    if hostile:
        readme += _HOSTILE_README
    (target / "README.txt").write_bytes(readme.encode())
    return manifest
