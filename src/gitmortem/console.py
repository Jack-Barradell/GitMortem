import sys


def info(msg: str) -> None:
    print(f"[*] {msg}")


def ok(msg: str) -> None:
    print(f"[+] {msg}")


def fail(msg: str) -> None:
    print(f"[-] {msg}")


def error(msg: str) -> None:
    if sys.stdout is not None:
        sys.stdout.flush()
    print(f"[!] {msg}", file=sys.stderr)
