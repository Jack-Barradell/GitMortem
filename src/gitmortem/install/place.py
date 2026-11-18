import os
from pathlib import Path

__all__ = ["replace"]


def replace(new: Path, final: Path) -> None:
    new.chmod(0o755)
    os.replace(new, final)
