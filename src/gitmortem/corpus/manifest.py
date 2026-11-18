from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, PositiveInt

from gitmortem.corpus.fakes import Role


class Tool(StrEnum):
    GIT_SECRETS = "git-secrets"
    GITLEAKS = "gitleaks"
    TRUFFLEHOG = "trufflehog"


class Size(StrEnum):
    SMALL = "small"
    DEMO = "demo"
    LARGE = "large"


class Placement(StrEnum):
    HEAD = "head"
    HISTORY_ONLY = "history-only"
    SIDE_BRANCH = "side-branch"
    DELETED_FILE = "deleted-file"
    SILENCED = "silenced"
    REFLOG_ONLY = "reflog-only"
    WORKTREE_REF = "worktree-ref"


class RepoKind(StrEnum):
    NORMAL = "normal"
    CLEAN = "clean"
    BARE = "bare"
    NESTED = "nested"
    HOSTILE = "hostile"
    OUTSIDE = "outside"


class Payload(StrEnum):
    FSMONITOR = "fsmonitor"
    TEXTCONV = "textconv"
    HOOK = "hook"
    GIT_SECRETS_PROVIDER = "git-secrets-provider"


class Silencer(StrEnum):
    GITLEAKS_CONFIG = "gitleaks-config"
    GITLEAKSIGNORE = "gitleaksignore"
    GITLEAKS_ALLOW = "gitleaks-allow-comment"
    GIT_SECRETS_ALLOWED = "git-secrets-allowed"
    GITALLOWED = "gitallowed"
    TRUFFLEHOG_IGNORE = "trufflehog-ignore-comment"
    REPLACE_REF = "replace-ref"
    COMMIT_GRAPH = "commit-graph"
    FORGED_INDEX = "forged-index"


HISTORY_SILENCERS = frozenset({Silencer.REPLACE_REF, Silencer.COMMIT_GRAPH, Silencer.FORGED_INDEX})


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Occurrence(_Model):
    repo: str
    path: str
    path_b64: str | None
    line: PositiveInt
    end_line: PositiveInt
    introduced: str
    removed: str | None
    branches: list[str]
    at_head: bool
    placement: Placement
    context: str
    detected_by: list[Tool]
    silenced_by: list[Silencer]


class HostileInfo(_Model):
    payloads: dict[Payload, str]
    silencers: list[Silencer]
    escapes: list[str]
    integrity_fails: bool


class SecretEntry(_Model):
    id: str
    kind: str
    role: Role
    value: str = Field(repr=False)
    parts: dict[str, str] = Field(repr=False)
    pair: str | None
    occurrences: list[Occurrence]


class RepoEntry(_Model):
    id: str
    path: str
    org: str | None
    name: str
    kind: RepoKind
    branches: dict[str, str]
    tags: dict[str, str]
    commit_count: NonNegativeInt
    hostile: HostileInfo | None


class GeneratorInfo(_Model):
    version: str
    seed: int
    size: Size
    hostile: bool


class Manifest(_Model):
    format: Literal[1]
    generator: GeneratorInfo
    repos: list[RepoEntry]
    secrets: list[SecretEntry]
    non_repo_paths: list[str]
