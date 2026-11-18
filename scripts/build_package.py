import argparse
import re
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "gitmortem"
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def migration_members() -> tuple[str, ...]:
    migrations = PACKAGE / "migrations"
    files = [*migrations.glob("*.py"), migrations / "script.py.mako"]
    files += (migrations / "versions").glob("*.py")
    return tuple(sorted(p.relative_to(PACKAGE.parent).as_posix() for p in files))


def data_members() -> tuple[str, ...]:
    files = (PACKAGE / "scanning" / "data").iterdir()
    return tuple(sorted(p.relative_to(PACKAGE.parent).as_posix() for p in files if p.is_file()))


REQUIRED_MEMBERS = (
    "gitmortem/static/index.html",
    "gitmortem/static/theme-boot.js",
    "gitmortem/static/third-party-licenses.txt",
    *migration_members(),
    *data_members(),
    "gitmortem/install/known_good.json",
    "gitmortem/install/templates/gitmortem.service",
    "gitmortem/install/templates/caddy.service",
    "gitmortem/install/templates/Caddyfile",
    f"gitmortem-{VERSION}.dist-info/licenses/LICENSE",
)

FRONTEND_STEPS = (
    ["npm", "--prefix", "frontend", "ci"],
    ["npm", "--prefix", "frontend", "run", "build"],
)


def missing_members(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    return [member for member in REQUIRED_MEMBERS if member not in names]


_OWN = re.compile(r"(gitmortem|gitmortem-[^/]+\.dist-info)/")
_UNWANTED = re.compile(r"(.*\.key|.*\.sqlite3.*|\.env.*|.*\.map)")


def unwanted_members(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    return [
        name
        for name in names
        if not _OWN.match(name)
        or "tests" in name.split("/")
        or _UNWANTED.fullmatch(name.rsplit("/", 1)[-1])
    ]


def build_commands(out_dir: Path, constraints: Path) -> list[list[str]]:
    return [
        [
            "uv",
            "export",
            "-q",
            "--frozen",
            "--only-group",
            "build",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            str(constraints),
        ],
        [
            "uv",
            "build",
            "--wheel",
            "--build-constraints",
            str(constraints),
            "--require-hashes",
            "--out-dir",
            str(out_dir),
        ],
    ]


def build_wheel(out_dir: Path) -> Path:
    for old in out_dir.glob("gitmortem-*.whl"):
        old.unlink()
    with tempfile.TemporaryDirectory() as work:
        for command in build_commands(out_dir, Path(work) / "build-constraints.txt"):
            subprocess.run(command, check=True, cwd=ROOT)  # noqa: S603
    built = set(out_dir.glob("gitmortem-*.whl"))
    if len(built) != 1:
        msg = f"expected one wheel in {out_dir}, found {len(built)}"
        raise RuntimeError(msg)
    return built.pop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the wheel with the frontend inside.")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "dist", help="where the wheel goes")
    parser.add_argument(
        "--check", type=Path, metavar="WHEEL", help="only check this wheel; build nothing"
    )
    args = parser.parse_args(argv)
    if args.check is not None:
        return report(args.check)
    try:
        for step in FRONTEND_STEPS:
            print(f"[*] {' '.join(step)}", flush=True)
            subprocess.run(step, check=True, cwd=ROOT)  # noqa: S603
        print("[*] uv build --wheel", flush=True)
        wheel = build_wheel(args.out_dir)
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"[!] build failed: {exc}", flush=True)
        return 1
    return report(wheel)


def report(wheel: Path) -> int:
    try:
        missing = missing_members(wheel)
    except (OSError, zipfile.BadZipFile):
        print(f"[!] {wheel.name} cannot be read as a wheel", flush=True)
        return 1
    if missing:
        print(f"[!] {wheel.name} is missing: {', '.join(missing)}", flush=True)
        return 1
    unwanted = unwanted_members(wheel)
    if unwanted:
        print(f"[!] {wheel.name} holds what no wheel may: {', '.join(unwanted)}", flush=True)
        return 1
    print(f"[+] {wheel.name} holds the frontend, the migrations and the scanners' data", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
