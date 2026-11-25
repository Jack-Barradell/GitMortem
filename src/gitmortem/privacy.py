import ctypes
import ctypes.util
import os
import re
import sys
from pathlib import Path

ACL_TYPE_EXTENDED = 0x100
_FIRST_ENTRY = 0
_NEXT_ENTRY = -1
_ALLOW = 1
_TRUSTED_ALIASES = frozenset({"SY", "BA", "OW", "CO"})
_READ_RIGHTS = frozenset({"GR", "GX", "FR", "FX", "RC"})
_READ_MASK = 0x001200A9 | 0x80000000 | 0x20000000
_ACE = re.compile(r"\(([^;()]*);([^;()]*);([^;()]*);[^;()]*;[^;()]*;([^;()]*)\)")


class NotPrivate(Exception):
    pass


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.acl_get_link_np.restype = ctypes.c_void_p
    libc.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_init.restype = ctypes.c_void_p
    libc.acl_init.argtypes = [ctypes.c_int]
    libc.acl_set_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    return libc


def acl_grants(path: Path) -> bool:
    if sys.platform != "darwin":
        return False
    libc = _libc()
    acl = libc.acl_get_link_np(os.fsencode(path), ACL_TYPE_EXTENDED)
    if not acl:
        return False
    try:
        entry = ctypes.c_void_p()
        tag = ctypes.c_int()
        which = _FIRST_ENTRY
        while libc.acl_get_entry(acl, which, ctypes.byref(entry)) == 0:
            which = _NEXT_ENTRY
            if libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0 or tag.value != _ALLOW:
                continue
            return True
        return False
    finally:
        libc.acl_free(acl)


def strip_extended_acl(path: Path) -> None:
    if sys.platform != "darwin":
        return
    libc = _libc()
    empty = libc.acl_init(0)
    if not empty:
        raise OSError(ctypes.get_errno(), "cannot make an empty ACL")
    try:
        if libc.acl_set_link_np(os.fsencode(path), ACL_TYPE_EXTENDED, empty) != 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number), str(path))
    finally:
        libc.acl_free(empty)


def _writes(rights: str) -> bool:
    if rights.lower().startswith("0x"):
        return bool(int(rights, 16) & ~_READ_MASK)
    return any(rights[i : i + 2] not in _READ_RIGHTS for i in range(0, len(rights), 2))


def others_in(sddl: str, user_sid: str, *, reading: bool) -> list[str]:
    owner = re.match(r"O:([^:]+?)(?=[GDS]:|$)", sddl)
    found: list[str] = []
    if owner is not None and owner.group(1) not in {user_sid, "BA", "SY"}:
        found.append(f"owner {owner.group(1)}")
    dacl = sddl.split("D:", 1)[1] if "D:" in sddl else ""
    dacl = dacl.split("S:", 1)[0]
    for kind, flags, rights, who in _ACE.findall(dacl):
        if kind != "A" or "IO" in flags or who in _TRUSTED_ALIASES or who == user_sid:
            continue
        if reading or _writes(rights):
            found.append(who)
    return found


if sys.platform == "win32":
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.GetCurrentProcess.argtypes = ()
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG),
    )
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    )
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    _advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    _advapi32.SetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    _advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    _SE_FILE_OBJECT = 1
    _OWNER = 0x1
    _DACL = 0x4
    _PROTECTED_DACL = 0x80000000
    _TOKEN_QUERY = 0x8
    _TOKEN_USER = 1

    def _win_error() -> OSError:
        return ctypes.WinError(ctypes.get_last_error())

    def _user_sid() -> str:
        token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            raise _win_error()
        try:
            needed = wintypes.DWORD()
            _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
            buffer = ctypes.create_string_buffer(needed.value)
            if not _advapi32.GetTokenInformation(
                token, _TOKEN_USER, buffer, needed, ctypes.byref(needed)
            ):
                raise _win_error()
            sid = ctypes.c_void_p.from_buffer(buffer).value
            text = wintypes.LPWSTR()
            if not _advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid), ctypes.byref(text)):
                raise _win_error()
            try:
                return str(text.value)
            finally:
                _kernel32.LocalFree(text)
        finally:
            _kernel32.CloseHandle(token)

    def _sddl_of(path: Path) -> str:
        descriptor = ctypes.c_void_p()
        failed = _advapi32.GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _OWNER | _DACL,
            None,
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if failed:
            raise ctypes.WinError(failed)
        try:
            text = wintypes.LPWSTR()
            if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, _OWNER | _DACL, ctypes.byref(text), None
            ):
                raise _win_error()
            try:
                return str(text.value)
            finally:
                _kernel32.LocalFree(text)
        finally:
            _kernel32.LocalFree(descriptor)

    def _set_owner_only(path: Path) -> None:
        inherit = "OICI" if path.is_dir() else ""
        sddl = f"D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;{_user_sid()})"
        descriptor = ctypes.c_void_p()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise _win_error()
        try:
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if not _advapi32.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
            ):
                raise _win_error()
            failed = _advapi32.SetNamedSecurityInfoW(
                str(path), _SE_FILE_OBJECT, _DACL | _PROTECTED_DACL, None, None, dacl, None
            )
            if failed:
                raise ctypes.WinError(failed)
        finally:
            _kernel32.LocalFree(descriptor)


def make_owner_only(path: Path) -> None:
    if sys.platform == "win32":
        _set_owner_only(path)
    elif sys.platform == "darwin":
        strip_extended_acl(path)


def require_private(path: Path, what: str, *, reading: bool, hint: str) -> None:
    if sys.platform == "win32":
        others = others_in(_sddl_of(path), _user_sid(), reading=reading)
        if others:
            raise NotPrivate(f"{what} {path} grants access to {', '.join(others)}; {hint}")
        return
    held = path.lstat()
    if held.st_uid not in {os.geteuid(), 0}:
        raise NotPrivate(f"{what} {path} is owned by another user; {hint}")
    if acl_grants(path):
        raise NotPrivate(
            f"{what} {path} has an access control list that grants access: remove it with"
            f" chmod -N {path}; {hint}"
        )
