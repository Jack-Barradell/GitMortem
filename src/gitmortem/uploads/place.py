import secrets
import threading
from pathlib import Path

from gitmortem.db.models import RepositoryRefusal
from gitmortem.scanning.repos import contained_git_dir

UPLOADS = "uploads"
DISK_RESERVE_BYTES = 1 << 30


def private_folder(folder: Path) -> Path:
    missing: list[Path] = []
    at = folder
    while not at.exists() and at != at.parent:
        missing.append(at)
        at = at.parent
    for each in reversed(missing):
        each.mkdir(mode=0o700, exist_ok=True)
    return folder


def uploads_dir(data_dir: Path) -> Path:
    return data_dir / UPLOADS


def pieces_dir(data_dir: Path) -> Path:
    return uploads_dir(data_dir) / "pieces"


def staging_dir(data_dir: Path) -> Path:
    return uploads_dir(data_dir) / "staging"


def pending_dir(data_dir: Path) -> Path:
    return uploads_dir(data_dir) / "pending"


def repos_dir(data_dir: Path) -> Path:
    return uploads_dir(data_dir) / "repos"


def new_version_dir(data_dir: Path) -> Path:
    return repos_dir(data_dir) / f"{secrets.token_hex(16)}.git"


def new_pending_dir(data_dir: Path) -> Path:
    return pending_dir(data_dir) / f"{secrets.token_hex(16)}.git"


def contained_upload_git_dir(
    git_dir: Path,
    uploads_root: Path,
    *,
    cancel: threading.Event | None = None,
    deadline: float | None = None,
) -> Path | RepositoryRefusal:
    return contained_git_dir(git_dir, uploads_root / "repos", cancel=cancel, deadline=deadline)
