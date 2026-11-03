"""Best-effort Windows install-directory and process-principal probes.

SOCA runs unelevated and executes files (``checkstat.py``, ``netapi.py``,
dashboard assets) from its install directory. If that directory grants write
access to broad principals such as ``Authenticated Users`` or ``Everyone``,
another local user can replace those files and get code execution in the
dashboard's context.

The checks here are **operational hardening, not a security boundary**:

- They warn; they do not change ACLs (that needs the owner or an administrator).
- A same-user process can still reproduce the agent command line and creation
  time. Restricting the install ACL and running unelevated are the real
  mitigations, and remain documented residual risk.
- Every probe fails closed: ``None`` means "could not establish", and callers
  must treat that as a rejection for adoption decisions.

All functions are no-ops or return ``None``/``False`` off Windows.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

ON_WINDOWS = os.name == "nt"

# Access masks and constants used by the ACL/token probes.
_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_ACCESS_ALLOWED_ACE_TYPE = 0x0
_ACL_SIZE_INFORMATION_CLASS = 2
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_ELEVATION = 20
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Do not use FILE_GENERIC_WRITE here: it includes SYNCHRONIZE and
# READ_CONTROL, so a read-only ACE would look writable. Test the write bits
# themselves, plus the generic and directory-delete rights.
_GENERIC_WRITE = 0x40000000
_GENERIC_ALL = 0x10000000
_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_FILE_WRITE_EA = 0x00000010
_FILE_DELETE_CHILD = 0x00000040
_FILE_WRITE_ATTRIBUTES = 0x00000100
_DELETE = 0x00010000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_WRITE_MASK = (
    _GENERIC_WRITE
    | _GENERIC_ALL
    | _FILE_WRITE_DATA
    | _FILE_APPEND_DATA
    | _FILE_WRITE_EA
    | _FILE_DELETE_CHILD
    | _FILE_WRITE_ATTRIBUTES
    | _DELETE
    | _WRITE_DAC
    | _WRITE_OWNER
)

# Broad local principals. A write ACE for any of these means another local
# user (or any authenticated process) can replace the agent's files.
_BROAD_WRITE_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
}


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", ctypes.c_uint32),
        ("AclBytesInUse", ctypes.c_uint32),
        ("AclBytesFree", ctypes.c_uint32),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", ctypes.c_ushort),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [
        ("Header", _AceHeader),
        ("Mask", ctypes.c_uint32),
        ("SidStart", ctypes.c_uint32),
    ]


if ON_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    _kernel32.GetCurrentProcessId.restype = ctypes.c_uint32
    _kernel32.OpenProcess.argtypes = [
        ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32
    ]
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = ctypes.c_int
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    _kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    _kernel32.ProcessIdToSessionId.argtypes = [
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)
    ]
    _kernel32.ProcessIdToSessionId.restype = ctypes.c_int
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    _advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.OpenProcessToken.restype = ctypes.c_int
    _advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    _advapi32.GetTokenInformation.restype = ctypes.c_int
    _advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    _advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    _advapi32.GetAclInformation.restype = ctypes.c_int
    _advapi32.GetAce.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)
    ]
    _advapi32.GetAce.restype = ctypes.c_int
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
    ]
    _advapi32.ConvertSidToStringSidW.restype = ctypes.c_int


def _sid_to_string(sid_ptr: int | ctypes.c_void_p) -> str | None:
    if not ON_WINDOWS:
        return None
    if isinstance(sid_ptr, int):
        sid_ptr = ctypes.c_void_p(sid_ptr)
    text = ctypes.c_void_p()
    if not _advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(text)):
        return None
    try:
        if not text.value:
            return None
        return ctypes.wstring_at(text.value)
    finally:
        _kernel32.LocalFree(text)


def _token_user_sid(token: int | ctypes.c_void_p) -> str | None:
    size = ctypes.c_uint32(0)
    _advapi32.GetTokenInformation(
        token, _TOKEN_USER, None, 0, ctypes.byref(size)
    )
    if size.value == 0:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if not _advapi32.GetTokenInformation(
        token, _TOKEN_USER, buffer, size, ctypes.byref(size)
    ):
        return None
    # TOKEN_USER starts with SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; }.
    sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
    return _sid_to_string(sid)


def current_user_sid() -> str | None:
    """SID of the user running this process, or None if unavailable."""
    if not ON_WINDOWS:
        return None
    token = ctypes.c_void_p()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        return None
    try:
        return _token_user_sid(token)
    finally:
        _kernel32.CloseHandle(token)


def process_owner_sid(pid: int) -> str | None:
    """Owner SID of another process, or None if it cannot be queried."""
    if not ON_WINDOWS or not isinstance(pid, int) or pid <= 0:
        return None
    handle = _kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        return None
    try:
        token = ctypes.c_void_p()
        if not _advapi32.OpenProcessToken(
            handle, _TOKEN_QUERY, ctypes.byref(token)
        ):
            return None
        try:
            return _token_user_sid(token)
        finally:
            _kernel32.CloseHandle(token)
    finally:
        _kernel32.CloseHandle(handle)


def process_image_path(pid: int) -> str | None:
    """Full executable path of another process, or None."""
    if not ON_WINDOWS or not isinstance(pid, int) or pid <= 0:
        return None
    handle = _kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        return None
    try:
        size = ctypes.c_uint32(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not _kernel32.QueryFullProcessImageNameW(
            handle, 0, buffer, ctypes.byref(size)
        ):
            return None
        return buffer.value
    finally:
        _kernel32.CloseHandle(handle)


def _session_id(pid: int) -> int | None:
    if not ON_WINDOWS or not isinstance(pid, int) or pid <= 0:
        return None
    session = ctypes.c_uint32(0)
    if not _kernel32.ProcessIdToSessionId(pid, ctypes.byref(session)):
        return None
    return int(session.value)


def current_session_id() -> int | None:
    return _session_id(_kernel32.GetCurrentProcessId()) if ON_WINDOWS else None


def process_session_id(pid: int) -> int | None:
    return _session_id(pid)


def is_elevated() -> bool:
    """True when the current token is elevated (UAC/admin)."""
    if not ON_WINDOWS:
        return False
    token = ctypes.c_void_p()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        return False
    try:
        elevation = ctypes.c_uint32(0)
        size = ctypes.c_uint32(0)
        if not _advapi32.GetTokenInformation(
            token,
            _TOKEN_ELEVATION,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(size),
        ):
            return False
        return bool(elevation.value)
    finally:
        _kernel32.CloseHandle(token)


def _mask_grants_write(mask: int) -> bool:
    return bool(int(mask) & _WRITE_MASK)


def broad_write_sids(path: str | os.PathLike[str]) -> list[str] | None:
    """Names of broad principals granted write access on ``path``.

    Returns an empty list when only the owner/administrators can write,
    ``None`` when the DACL cannot be read (fail closed for callers that treat
    unknown as a warning), and a list of SID names when a broad allow ACE
    grants write, delete, or ACL-write access.
    """
    if not ON_WINDOWS:
        return None
    security_descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    status = _advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if status != 0:
        return None
    try:
        if not dacl.value:
            # A NULL DACL grants full access to everyone.
            return ["Everyone (unrestricted DACL)"]
        size_info = _AclSizeInformation()
        if not _advapi32.GetAclInformation(
            dacl,
            ctypes.byref(size_info),
            ctypes.sizeof(size_info),
            _ACL_SIZE_INFORMATION_CLASS,
        ):
            return None
        found: set[str] = set()
        for index in range(int(size_info.AceCount)):
            ace_ptr = ctypes.c_void_p()
            if not _advapi32.GetAce(
                dacl, index, ctypes.byref(ace_ptr)
            ):
                continue
            header = ctypes.cast(
                ace_ptr, ctypes.POINTER(_AceHeader)
            ).contents
            if header.AceType != _ACCESS_ALLOWED_ACE_TYPE:
                continue
            ace = ctypes.cast(
                ace_ptr, ctypes.POINTER(_AccessAllowedAce)
            ).contents
            if not _mask_grants_write(ace.Mask):
                continue
            sid_address = (
                ctypes.addressof(ace) + _AccessAllowedAce.SidStart.offset
            )
            sid = _sid_to_string(sid_address)
            if sid in _BROAD_WRITE_SIDS:
                found.add(_BROAD_WRITE_SIDS[sid])
        return sorted(found)
    finally:
        if security_descriptor.value:
            _kernel32.LocalFree(security_descriptor)


def install_warnings(script_dir: str | os.PathLike[str]) -> list[str]:
    """Human-readable warnings for an unsafe install directory/elevation."""
    if not ON_WINDOWS:
        return []
    warnings: list[str] = []
    try:
        elevated = is_elevated()
        sids = broad_write_sids(script_dir)
    except Exception:
        # A warning probe must never prevent the agent from starting.
        return []
    if elevated:
        warnings.append(
            "running with an elevated token; SOCA is designed to run "
            "unelevated. Stop and relaunch without 'Run as administrator'."
        )
    if sids:
        warnings.append(
            f"install directory {Path(script_dir)} grants write access to "
            f"{', '.join(sids)}. The dashboard executes files from this "
            "directory, so another local user could replace them. Install "
            "under %LOCALAPPDATA% or %PROGRAMFILES%, restrict the ACL to "
            "your account, and never run elevated. See README 'Security "
            "posture and hardening'."
        )
    return warnings


def image_matches_current_interpreter(path: str | os.PathLike[str] | None) -> bool:
    """True when ``path`` is this interpreter (or its venv base runtime).

    A Windows venv ``python.exe`` is a launcher: the PID returned by Popen may
    be the launcher itself or the base interpreter it starts. Accept both
    ``sys.executable`` and ``sys._base_executable`` so adoption still works
    across that boundary, while rejecting any other image.
    """
    if not path:
        return False
    expected = {os.path.normcase(os.path.realpath(sys.executable))}
    base = getattr(sys, "_base_executable", None)
    if base:
        expected.add(os.path.normcase(os.path.realpath(base)))
    actual = os.path.normcase(os.path.realpath(str(path)))
    return actual in expected
