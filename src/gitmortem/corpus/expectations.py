from gitmortem.corpus.contexts import Context
from gitmortem.corpus.fakes import BaitKind, SecretType
from gitmortem.corpus.manifest import Placement, Tool

__all__ = ["PLACEMENT_MISSES", "Tool", "expected_tools"]

_G, _L, _T = Tool.GIT_SECRETS, Tool.GITLEAKS, Tool.TRUFFLEHOG

_BY_KIND: dict[SecretType | BaitKind, frozenset[Tool]] = {
    SecretType.AWS_ACCESS_KEY_ID: frozenset({_G, _L, _T}),
    SecretType.AWS_SECRET_ACCESS_KEY: frozenset({_G, _T}),
    SecretType.GITHUB_PAT: frozenset({_L, _T}),
    SecretType.SLACK_BOT_TOKEN: frozenset({_L, _T}),
    SecretType.SLACK_WEBHOOK_URL: frozenset({_L, _T}),
    SecretType.PRIVATE_KEY_EC: frozenset({_L, _T}),
    SecretType.PRIVATE_KEY_PKCS8: frozenset({_L}),
    SecretType.PRIVATE_KEY_OPENSSH: frozenset({_L, _T}),
    SecretType.POSTGRES_URL: frozenset({_T}),
    SecretType.MYSQL_URL: frozenset(),
    SecretType.MONGODB_URL: frozenset({_T}),
    SecretType.PASSWORD: frozenset(),
    SecretType.GENERIC_API_KEY: frozenset({_L}),
    SecretType.JWT: frozenset({_L}),
    BaitKind.AWS_EXAMPLE: frozenset({_G, _L, _T}),
    BaitKind.AWS_EXAMPLE_SECRET: frozenset({_G, _L, _T}),
    BaitKind.PLACEHOLDER: frozenset(),
    BaitKind.SHA256_HEX: frozenset(),
    BaitKind.UUID: frozenset(),
    BaitKind.LOCKFILE_INTEGRITY: frozenset(),
    BaitKind.BASE64_IMAGE: frozenset(),
    BaitKind.FIXTURE_KEY: frozenset({_L, _T}),
}

_KEY_KINDS = {
    SecretType.PRIVATE_KEY_EC,
    SecretType.PRIVATE_KEY_PKCS8,
    SecretType.PRIVATE_KEY_OPENSSH,
    BaitKind.FIXTURE_KEY,
}
_KEY_CONTEXTS = (Context.PEM, Context.MARKDOWN)
_LINE_CONTEXTS = tuple(c for c in Context if c is not Context.PEM)

_EXPECTED: dict[tuple[SecretType | BaitKind, Context], frozenset[Tool]] = {
    (kind, context): tools
    for kind, tools in _BY_KIND.items()
    for context in (_KEY_CONTEXTS if kind in _KEY_KINDS else _LINE_CONTEXTS)
}


PLACEMENT_MISSES: dict[Placement, frozenset[Tool]] = {}


def expected_tools(
    kind: SecretType | BaitKind, context: Context, placement: Placement | None = None
) -> frozenset[Tool]:
    misses = PLACEMENT_MISSES.get(placement, frozenset()) if placement is not None else frozenset()
    return _EXPECTED[(kind, context)] - misses
