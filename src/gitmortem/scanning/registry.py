import os
import shutil
import tempfile
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from gitmortem.config import BUILT_IN_TOOLS, Settings, tool_file_names
from gitmortem.db.models import ToolName
from gitmortem.gitrun import GitRunner, require_git
from gitmortem.scanning import custom_rules, git_secrets, gitleaks, tools_folder, trufflehog
from gitmortem.scanning.jobs import WORK
from gitmortem.scanning.tools import Detection, DetectionStatus, ToolSpec

TOOLS: dict[ToolName, ToolSpec] = {
    ToolName.GIT_SECRETS: git_secrets.GitSecretsSpec(),
    ToolName.GITLEAKS: gitleaks.GitleaksSpec(),
    ToolName.TRUFFLEHOG: trufflehog.TruffleHogSpec(),
    ToolName.CUSTOM_RULES: custom_rules.CustomRulesSpec(),
}
SCANNERS: tuple[ToolName, ...] = (
    ToolName.GIT_SECRETS,
    ToolName.GITLEAKS,
    ToolName.TRUFFLEHOG,
    ToolName.CUSTOM_RULES,
)
TESTED_VERSIONS: dict[ToolName, str] = {
    ToolName.GITLEAKS: ".".join(str(part) for part in gitleaks.TESTED),
    ToolName.TRUFFLEHOG: ".".join(str(part) for part in trufflehog.TESTED),
}
KNOWN_BUILDS: dict[ToolName, Mapping[str, str]] = {ToolName.GIT_SECRETS: git_secrets.KNOWN_BUILDS}
DETECT = "detect"


class DetectionFolderError(OSError):
    pass


_DETECT_DIRS = threading.Lock()


def detect_tools(
    settings: Settings, runner: GitRunner, tools: Mapping[ToolName, ToolSpec] = TOOLS
) -> dict[ToolName, Detection]:
    major, minor, patch = require_git(runner)
    exec_path = Path(
        os.fsdecode(runner.run(["--exec-path"], cwd=runner.private_dir)).rstrip("\r\n")
    )
    tools_bin = (settings.tools_dir or settings.data_dir / "tools") / "bin"
    loose = tools_folder.folder_problem(tools_bin.parent) is not None
    searched = [] if loose else [str(tools_bin)]
    path_env = os.pathsep.join([*searched, os.environ.get("PATH", os.defpath)])
    git_version = f"{major}.{minor}.{patch}"
    found: dict[ToolName, Detection] = {}
    with _detect_dir(settings.data_dir) as work_dir:
        for name, spec in tools.items():
            operator = settings.tool_paths.get(name)
            planted = _planted(name, tools_bin, operator) if loose else None
            if planted is not None:
                found[name] = Detection(
                    DetectionStatus.UNSAFE_FOLDER, path=planted, git_version=git_version
                )
                continue
            found[name] = spec.detect(
                path_env,
                operator,
                known_builds=KNOWN_BUILDS.get(name, {}),
                exec_path=exec_path,
                git_version=git_version,
                work_dir=work_dir,
            )
    return tools_folder.judged(found, tools_bin.parent, by_build=KNOWN_BUILDS)


def _planted(name: ToolName, tools_bin: Path, operator: Path | None) -> Path | None:
    if name in BUILT_IN_TOOLS:
        return None
    if operator is not None:
        return operator if tools_folder.in_bin(operator, tools_bin) else None
    for file_name in tool_file_names(name, windows=os.name == "nt"):
        candidate = tools_bin / file_name
        if os.path.lexists(candidate):
            return candidate
    return None


@contextmanager
def _detect_dir(data_dir: Path) -> Iterator[Path]:
    work = data_dir / WORK
    parent = work / DETECT
    with _DETECT_DIRS:
        try:
            work.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent.mkdir(mode=0o700, exist_ok=True)
            folder = Path(tempfile.mkdtemp(dir=parent))
        except OSError as error:
            raise DetectionFolderError(error.errno, error.strerror, str(parent)) from error
    try:
        yield folder
    finally:
        with _DETECT_DIRS:
            shutil.rmtree(folder)
            if not any(parent.iterdir()):
                parent.rmdir()
