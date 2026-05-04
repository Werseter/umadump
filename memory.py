#!/usr/bin/env python3
"""
Unified memory reader infrastructure.

Contains:
  - Target process / module constants
  - MemoryReader Protocol
  - ProcessMemory — live process reader via Win32/ntdll
  - MinidumpMemory — offline reader backed by a full-memory minidump
"""
from __future__ import annotations

import re
import struct
from bisect import bisect_right
from contextlib import contextmanager
from ctypes import (Array, POINTER as _POINTER, WINFUNCTYPE, WinDLL, byref as _byref, c_char, c_long, c_size_t,
                    c_void_p, create_string_buffer, create_unicode_buffer, get_last_error, sizeof)
from ctypes.wintypes import BOOL, DWORD, HANDLE, HMODULE, INT, LPWSTR, WCHAR
from dataclasses import dataclass
from typing import (Any, Callable, Iterable, Iterator, Literal as L, Optional, Protocol, Self, TYPE_CHECKING, TypeAlias,
                    TypeVar, cast as type_cast)

from ctypes_utils import CStructureDataclass, C_VoidPtr, StrArrayType, set_pointer_reader

if TYPE_CHECKING:
    from minidump.common_structs import MinidumpMemorySegment
    from minidump.minidumpfile import MinidumpFile

TARGET_PROCESS = "UmamusumePrettyDerby.exe"
TARGET_MODULE = "GameAssembly.dll"
POINTER_SIZE = 8  # x64 only


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

class MemoryReader(Protocol):
    """Protocol for process memory access (live or offline)."""

    def __enter__(self) -> Self: ...

    def __exit__(self, *_: Any) -> None: ...

    def close(self) -> None: ...

    def exe_path(self) -> str: ...

    def module_info(self, module_name: str) -> tuple[int, int]: ...

    def scan(self, base: int, size: int, pattern_re: re.Pattern[bytes], overlap: int = 0) -> Iterable[int]: ...

    def read(self, address: int, size: int) -> bytes: ...

    def read_pointer(self, address: int) -> int: ...

    def read_u32(self, address: int) -> int: ...

    def read_i32(self, address: int) -> int: ...

    def read_cstring(self, address: int, max_len: int = 256) -> str: ...


# ---------------------------------------------------------------------------
# Shared reader helpers (mixin)
# ---------------------------------------------------------------------------

class _ReaderMixin:
    """Implements scalar-read helpers in terms of self.read()."""

    def read(self, address: int, size: int) -> bytes:
        raise NotImplementedError  # must be implemented by concrete subclass

    def read_pointer(self, address: int) -> int:
        return int.from_bytes(self.read(address, POINTER_SIZE), "little")

    def read_u32(self, address: int) -> int:
        return int(struct.unpack("<I", self.read(address, 4))[0])

    def read_i32(self, address: int) -> int:
        return int(struct.unpack("<i", self.read(address, 4))[0])

    def read_cstring(self, address: int, max_len: int = 256) -> str:
        raw = self.read(address, max_len)
        end = raw.find(b"\0")
        return raw[:end if end >= 0 else len(raw)].decode("utf-8", errors="replace")


class _ReadCache:
    """Bisect-backed in-memory byte cache shared by both memory backends.

    Stores complete region/span contents keyed by start VA.  ``lookup`` finds
    the entry containing *address* in O(log n); ``insert`` maintains sorted
    order.  Both backends populate entries lazily on first access.
    """

    __slots__ = ("_starts", "_entries")

    def __init__(self) -> None:
        self._starts: list[int] = []
        # start -> (exclusive_end, data)
        self._entries: dict[int, tuple[int, bytes]] = {}

    def lookup(self, address: int) -> Optional[tuple[int, int, bytes]]:
        """Return ``(start, end, data)`` for the cached block containing *address*, or ``None``."""
        idx = bisect_right(self._starts, address) - 1
        if idx < 0:
            return None
        start = self._starts[idx]
        end, data = self._entries[start]
        return (start, end, data) if address < end else None

    def insert(self, start: int, end: int, data: bytes) -> None:
        """Insert a new block; *start* must not already be present."""
        idx = bisect_right(self._starts, start)
        self._starts.insert(idx, start)
        self._entries[start] = (end, data)

    def read(self, address: int, size: int) -> Optional[bytes]:
        """Serve *size* bytes from *address* if fully covered by one cached block."""
        block = self.lookup(address)
        if block is None:
            return None
        start, end, data = block
        if address + size > end:
            return None  # request spans beyond this block
        off = address - start
        return data[off: off + size]


@dataclass(frozen=True, slots=True)
class ScanRegion:
    """A normalized scannable region with backend-supplied read implementation."""

    start: int
    end: int
    read: Callable[[int, int], bytes]


class _RegionChunkScanMixin(_ReaderMixin):
    """Shared scan pipeline over backend-provided regions and chunk reads."""

    _SCAN_CHUNK_SIZE = 16 * 1024 * 1024

    def scan(self, base: int, size: int, pattern_re: re.Pattern[bytes], overlap: int = 0) -> Iterator[int]:
        start, end = self._normalized_scan_bounds(base, size)
        if end <= start:
            return
        yield from self._iter_scan_matches(self._iter_region_chunks(start, end, overlap), pattern_re, overlap)

    @staticmethod
    def _normalized_scan_bounds(base: int, size: int) -> tuple[int, int]:
        start = max(0, int(base))
        end = start + max(0, int(size))
        return start, end

    def _iter_matches(self, blob: bytes, pat: re.Pattern[bytes]) -> Iterator[int]:
        """Yield all (possibly overlapping) start offsets of pat in blob."""
        pos = 0
        while (m := pat.search(blob, pos)) is not None:
            yield m.start()
            pos = m.start() + 1

    def _iter_scan_matches(self, region_chunks: Iterable[tuple[int, bytes, int]],
                           pattern_re: re.Pattern[bytes], overlap: int) -> Iterator[int]:
        """Yield virtual addresses of regex matches from pre-windowed scan chunks."""
        if not pattern_re.pattern:
            return

        overlap = max(0, overlap)
        for window_base, window, chunk_va in region_chunks:
            min_emit_va = chunk_va - overlap
            for off in self._iter_matches(window, pattern_re):
                match_va = window_base + off
                if match_va >= min_emit_va:
                    yield match_va

    def _iter_region_chunks(self, start: int, end: int, overlap: int) -> Iterator[tuple[int, bytes, int]]:
        """Yield (window_base, window, chunk_va) across scan regions with overlap carry."""
        overlap = max(0, overlap)
        carry = b""
        prev_end: Optional[int] = None

        for region in self._iter_scan_regions(start, end):
            if region.start >= region.end:
                continue
            if prev_end is not None and region.start != prev_end:
                carry = b""
            prev_end = region.end

            cursor = region.start
            while cursor < region.end:
                take = min(region.end - cursor, self._SCAN_CHUNK_SIZE)
                try:
                    chunk = region.read(cursor, take)
                except RuntimeError:
                    break
                if not chunk:
                    break
                window = carry + chunk
                yield cursor - len(carry), window, cursor
                carry = window[-overlap:] if overlap else b""
                cursor += len(chunk)

    def _iter_scan_regions(self, start: int, end: int) -> Iterable[ScanRegion]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# MinidumpMemory
# ---------------------------------------------------------------------------

class MinidumpMemory(_RegionChunkScanMixin):
    """Offline process memory via python-minidump.

    Span data is loaded into ``_ReadCache`` on first access so subsequent reads
    to the same span are served entirely from memory without further file I/O.
    """

    def __init__(self, dump_path: str) -> None:
        # Make dependency required only if MinidumpMemory is actually used
        from minidump.common_structs import MinidumpMemorySegment
        from minidump.minidumpfile import MinidumpFile

        self._dump = MinidumpFile.parse(dump_path)
        self._reader = self._dump.get_reader()
        self._fh = self._dump.file_handle

        _sorted = sorted(self._reader.memory_segments, key=lambda s: int(s.start_virtual_address))
        self._span_starts: tuple[int, ...] = tuple(int(s.start_virtual_address) for s in _sorted)
        self._spans: tuple[MinidumpMemorySegment, ...] = tuple(_sorted)
        self._cache = _ReadCache()
        self._register()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _register(self) -> None:
        set_pointer_reader(self.read)

    def _deregister(self) -> None:
        set_pointer_reader(None)

    def close(self) -> None:
        self._deregister()
        self._fh.close()

    def exe_path(self) -> str:
        raise NotImplementedError("MinidumpMemory does not expose the original exe path")

    def module_info(self, module_name: str) -> tuple[int, int]:
        m = self._reader.get_module_by_name(module_name)
        if m is None:
            raise RuntimeError(f"Module not found in dump: {module_name}")
        return int(m.baseaddress), int(m.size)

    def read(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError(f"size must be non-negative, got {size}")
        if size == 0:
            return b""

        # Fast path — fully served from cache.
        cached = self._cache.read(address, size)
        if cached is not None:
            return cached

        # Multi-region stitching with lazy span population.
        out = bytearray()
        cursor, end = address, address + size
        while cursor < end:
            # Ensure the span containing cursor is cached.
            if self._cache.lookup(cursor) is None:
                span = self._span_at(cursor)
                if span is None:
                    raise RuntimeError(f"0x{cursor:X} not in dump")
                span_start = int(span.start_virtual_address)
                span_end = int(span.end_virtual_address)
                span_size = span_end - span_start
                try:
                    data = span.read(span_start, span_size, self._fh)
                except Exception:
                    raise
                self._cache.insert(span_start, span_start + len(data), data)

            block = self._cache.lookup(cursor)
            if block is None:
                raise RuntimeError(f"0x{cursor:X} not in dump after cache population")
            block_start, block_end, block_data = block
            take = min(end - cursor, block_end - cursor)
            off = cursor - block_start
            out.extend(block_data[off: off + take])
            cursor += take

        return bytes(out)

    def _iter_scan_regions(self, start: int, end: int) -> Iterable[ScanRegion]:
        for seg_start, seg_end, _span in self._relevant_spans(start, end - start):
            yield ScanRegion(start=seg_start, end=seg_end, read=self.read)

    def _relevant_spans(self, base: int, size: int) -> Iterator[tuple[int, int, MinidumpMemorySegment]]:
        """Yield (seg_start, seg_end, span) for each span overlapping [base, base+size)."""
        scan_end = base + size
        start_idx = max(0, bisect_right(self._span_starts, base) - 1)
        for span_start, span in zip(self._span_starts[start_idx:], self._spans[start_idx:]):
            if span_start >= scan_end:
                break
            seg_start = max(base, span_start)
            seg_end = min(scan_end, int(span.end_virtual_address))
            if seg_start < seg_end:
                yield seg_start, seg_end, span

    def _span_at(self, va: int) -> Optional[MinidumpMemorySegment]:
        idx = bisect_right(self._span_starts, va) - 1
        if idx < 0:
            return None
        span = self._spans[idx]
        return span if va < int(span.end_virtual_address) else None


# ---------------------------------------------------------------------------
# ProcessMemory (Windows / ntdll)
# ---------------------------------------------------------------------------
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = c_void_p(-1).value

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

MEMORY_BASIC_INFORMATION_CLASS = 0


class _PROCESSENTRY32W(CStructureDataclass):
    dwSize: DWORD
    cntUsage: DWORD
    th32ProcessID: DWORD
    th32DefaultHeapID: C_VoidPtr
    th32ModuleID: DWORD
    cntThreads: DWORD
    th32ParentProcessID: DWORD
    pcPriClassBase: c_long
    dwFlags: DWORD
    szExeFile: StrArrayType[WCHAR, L[260]]


class _MEMORY_BASIC_INFORMATION(CStructureDataclass):
    BaseAddress: C_VoidPtr
    AllocationBase: C_VoidPtr
    AllocationProtect: DWORD
    RegionSize: c_size_t
    State: DWORD
    Protect: DWORD
    Type: DWORD


class _MODULEENTRY32W(CStructureDataclass):
    dwSize: DWORD
    th32ModuleID: DWORD
    th32ProcessID: DWORD
    GlblcntUsage: DWORD
    ProccntUsage: DWORD
    modBaseAddr: C_VoidPtr
    modBaseSize: DWORD
    hModule: HMODULE
    szModule: StrArrayType[WCHAR, L[256]]
    szExePath: StrArrayType[WCHAR, L[260]]


if TYPE_CHECKING:
    from _ctypes import _CData, _Pointer

    CDT = TypeVar("CDT", bound=_CData)

    POINTER: TypeAlias = _Pointer[CDT]


    def byref(obj: CDT) -> POINTER[CDT]:
        ...
else:
    class POINTER:
        @classmethod
        def __class_getitem__(cls, item):
            # Not actually deprecated
            # PyCharm bug treats _Pointer[str] deprecation as if all _Pointer[T] are deprecated
            # noinspection PyDeprecation
            return _POINTER(item)


    byref = _byref


# noinspection PyPep8Naming
class _Kernel32Api:
    """Typed kernel32 wrapper with named forwarding stubs."""

    def __init__(self) -> None:
        dll = WinDLL("kernel32", use_last_error=True)
        self._open_process = WINFUNCTYPE(HANDLE, DWORD, BOOL, DWORD, use_last_error=True)(("OpenProcess", dll))
        self._create_toolhelp32_snapshot = WINFUNCTYPE(
                HANDLE, DWORD, DWORD, use_last_error=True
        )(("CreateToolhelp32Snapshot", dll))
        self._process32_first_w = WINFUNCTYPE(
                BOOL, HANDLE, POINTER[_PROCESSENTRY32W], use_last_error=True
        )(("Process32FirstW", dll))
        self._process32_next_w = WINFUNCTYPE(
                BOOL, HANDLE, POINTER[_PROCESSENTRY32W], use_last_error=True
        )(("Process32NextW", dll))
        self._module32_first_w = WINFUNCTYPE(
                BOOL, HANDLE, POINTER[_MODULEENTRY32W], use_last_error=True
        )(("Module32FirstW", dll))
        self._module32_next_w = WINFUNCTYPE(
                BOOL, HANDLE, POINTER[_MODULEENTRY32W], use_last_error=True
        )(("Module32NextW", dll))
        self._query_full_process_image_name_w = WINFUNCTYPE(
                BOOL, HANDLE, DWORD, LPWSTR, POINTER[DWORD], use_last_error=True
        )(("QueryFullProcessImageNameW", dll))
        self._close_handle = WINFUNCTYPE(BOOL, HANDLE, use_last_error=True)(("CloseHandle", dll))

    def OpenProcess(self, dwDesiredAccess: int, bInheritHandle: bool, dwProcessId: int) -> HANDLE:
        return type_cast(
                HANDLE,
                self._open_process(DWORD(dwDesiredAccess), BOOL(bool(bInheritHandle)), DWORD(dwProcessId)))

    def CreateToolhelp32Snapshot(self, dwFlags: int, th32ProcessID: int) -> HANDLE:
        return type_cast(
                HANDLE,
                self._create_toolhelp32_snapshot(DWORD(dwFlags), DWORD(th32ProcessID)))

    def Process32FirstW(self, hSnapshot: HANDLE, lppe: _PROCESSENTRY32W) -> BOOL:
        return type_cast(
                BOOL,
                self._process32_first_w(hSnapshot, byref(lppe)))

    def Process32NextW(self, hSnapshot: HANDLE, lppe: _PROCESSENTRY32W) -> BOOL:
        return type_cast(
                BOOL,
                self._process32_next_w(hSnapshot, byref(lppe)))

    def Module32FirstW(self, hSnapshot: HANDLE, lpme: _MODULEENTRY32W) -> BOOL:
        return type_cast(
                BOOL,
                self._module32_first_w(hSnapshot, byref(lpme)))

    def Module32NextW(self, hSnapshot: HANDLE, lpme: _MODULEENTRY32W) -> BOOL:
        return type_cast(
                BOOL,
                self._module32_next_w(hSnapshot, byref(lpme)))

    def QueryFullProcessImageNameW(self, hProcess: HANDLE, dwFlags: int, lpExeName: Any, lpdwSize: Any) -> BOOL:
        return type_cast(
                BOOL,
                self._query_full_process_image_name_w(hProcess, DWORD(dwFlags), lpExeName, lpdwSize))

    def CloseHandle(self, hObject: HANDLE) -> BOOL:
        return type_cast(
                BOOL,
                self._close_handle(hObject))


# noinspection PyPep8Naming
class _NtdllApi:
    """Typed ntdll wrapper with named forwarding stubs."""

    def __init__(self) -> None:
        dll = WinDLL("ntdll", use_last_error=True)
        self._nt_read_virtual_memory = WINFUNCTYPE(
                c_long, HANDLE, c_void_p, c_void_p, c_size_t, POINTER[c_size_t], use_last_error=True
        )(("NtReadVirtualMemory", dll))
        self._nt_query_virtual_memory = WINFUNCTYPE(
                c_long, HANDLE, c_void_p, INT, c_void_p, c_size_t, POINTER[c_size_t], use_last_error=True
        )(("NtQueryVirtualMemory", dll))
        self._nt_close = WINFUNCTYPE(c_long, HANDLE, use_last_error=True)(("NtClose", dll))

    def NtReadVirtualMemory(self, ProcessHandle: HANDLE, BaseAddress: c_void_p, Buffer: Array[c_char],
                            NumberOfBytesToRead: int, NumberOfBytesRead: POINTER[c_size_t]) -> int:
        return int(self._nt_read_virtual_memory(
                ProcessHandle,
                BaseAddress,
                Buffer,
                c_size_t(NumberOfBytesToRead),
                NumberOfBytesRead
        ))

    def NtQueryVirtualMemory(self, ProcessHandle: HANDLE, BaseAddress: c_void_p, MemoryInformationClass: int,
                             MemoryInformation: POINTER[_MEMORY_BASIC_INFORMATION], MemoryInformationLength: int,
                             ReturnLength: POINTER[c_size_t]) -> int:
        return int(self._nt_query_virtual_memory(
                ProcessHandle,
                BaseAddress,
                INT(MemoryInformationClass),
                MemoryInformation,
                c_size_t(MemoryInformationLength),
                ReturnLength
        ))

    def NtClose(self, Handle: HANDLE) -> int:
        return int(self._nt_close(Handle))


_kernel32 = _Kernel32Api()
_ntdll = _NtdllApi()


# ---------------------------------------------------------------------------
# Toolhelp snapshot helpers
# ---------------------------------------------------------------------------

@contextmanager
def _toolhelp_snapshot(flags: int, pid: int = 0) -> Iterator[HANDLE]:
    """Context manager that opens and closes a Toolhelp32 snapshot handle."""
    snap = _kernel32.CreateToolhelp32Snapshot(flags, pid)
    if snap == INVALID_HANDLE_VALUE:
        raise RuntimeError(
                f"CreateToolhelp32Snapshot(flags=0x{flags:X}, pid={pid}) failed "
                f"(winerror={get_last_error()})"
        )
    try:
        yield snap
    finally:
        _kernel32.CloseHandle(snap)


def _iter_snapshot[_SnapshotEntryT: CStructureDataclass](
        snap: HANDLE, entry_type: type[_SnapshotEntryT], first_fn: Callable[[HANDLE, _SnapshotEntryT], BOOL],
        next_fn: Callable[[HANDLE, _SnapshotEntryT], BOOL]) -> Iterator[_SnapshotEntryT]:
    """Yield successive entries from an open Toolhelp32 snapshot."""
    entry = entry_type()
    # Toolhelp32 entry structs require dwSize to be initialized before first call.
    entry.dwSize = sizeof(entry_type)  # type: ignore[attr-defined]
    ok = first_fn(snap, entry)
    while ok:
        yield entry
        ok = next_fn(snap, entry)


class ProcessMemory(_RegionChunkScanMixin):
    """Live process memory backend using Windows ntdll APIs through ctypes.

    Each readable VM region is fetched in full via a single ``NtReadVirtualMemory``
    call on first access, then cached in ``_ReadCache``.  Subsequent reads to the
    same region are served from the in-memory cache with bisect lookup — the same
    pattern used by ``MinidumpMemory`` for dump spans.
    """

    _READABLE_PROTECTIONS = {
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }

    def __init__(self, process_name: str = TARGET_PROCESS) -> None:
        self._process_name = process_name
        self._pid = self._find_pid_by_name(process_name)
        self._process = self._open_process(self._pid)
        self._cache = _ReadCache()
        self._register()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _register(self) -> None:
        set_pointer_reader(self.read)

    def _deregister(self) -> None:
        set_pointer_reader(None)

    def close(self) -> None:
        self._deregister()
        process = self._process
        if process:
            _ntdll.NtClose(process)
            self._process = HANDLE()

    def exe_path(self) -> str:
        cap = DWORD(32768)
        buf = create_unicode_buffer(cap.value)
        ok = _kernel32.QueryFullProcessImageNameW(self._process, 0, buf, byref(cap))
        if not ok:
            raise RuntimeError(f"QueryFullProcessImageNameW failed (winerror={get_last_error()})")
        return buf.value

    def module_info(self, module_name: str) -> tuple[int, int]:
        return self._find_module_by_name(self._pid, module_name)

    def _iter_scan_regions(self, start: int, end: int) -> Iterable[ScanRegion]:
        for seg_start, seg_end, _ in self._iter_readable_regions(start, end - start):
            yield ScanRegion(start=seg_start, end=seg_end, read=self.read)

    def read(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError(f"size must be non-negative, got {size}")
        if size == 0:
            return b""

        # Fast path — fully served from cache.
        cached = self._cache.read(address, size)
        if cached is not None:
            return cached

        # Multi-region stitching with lazy region population.
        out = bytearray()
        cursor, end_addr = address, address + size
        while cursor < end_addr:
            # Populate the cache for the region containing cursor if not yet present.
            if self._cache.lookup(cursor) is None:
                self._fetch_region_into_cache(cursor)

            block = self._cache.lookup(cursor)
            if block is None:
                raise RuntimeError(
                        f"Failed to read 0x{cursor:X}: region not readable or not committed")
            block_start, block_end, block_data = block
            take = min(end_addr - cursor, block_end - cursor)
            off = cursor - block_start
            out.extend(block_data[off: off + take])
            cursor += take

        return bytes(out)

    def _fetch_region_into_cache(self, address: int) -> None:
        """Query and read the full committed readable region containing *address* into cache."""
        mbi = _MEMORY_BASIC_INFORMATION()
        ret_len = c_size_t(0)
        status = _ntdll.NtQueryVirtualMemory(
                self._process,
                c_void_p(address),
                MEMORY_BASIC_INFORMATION_CLASS,
                byref(mbi),
                sizeof(mbi),
                byref(ret_len),
        )
        if status < 0:
            raise RuntimeError(
                    f"NtQueryVirtualMemory(0x{address:X}) failed (status=0x{status & 0xFFFFFFFF:08X})")

        if not self._is_region_readable(mbi):
            raise RuntimeError(f"0x{address:X} is in a non-readable region")

        region_base = int(mbi.BaseAddress or 0)
        region_size = int(mbi.RegionSize)
        if region_size <= 0:
            raise RuntimeError(f"0x{address:X}: region size is zero")

        buf = create_string_buffer(region_size)
        read_len = c_size_t(0)
        status = _ntdll.NtReadVirtualMemory(
                self._process,
                c_void_p(region_base),
                buf,
                region_size,
                byref(read_len),
        )
        actual = int(read_len.value)
        read_ok = status >= 0 and actual > 0
        if not read_ok:
            raise RuntimeError(
                    f"NtReadVirtualMemory(0x{region_base:X}, size={region_size}) failed "
                    f"(status=0x{status & 0xFFFFFFFF:08X}, read={actual})")

        self._cache.insert(region_base, region_base + actual, bytes(buf.raw[:actual]))

    @staticmethod
    def _find_pid_by_name(process_name: str) -> int:
        with _toolhelp_snapshot(TH32CS_SNAPPROCESS) as snap:
            for entry in _iter_snapshot(snap, _PROCESSENTRY32W,
                                        _kernel32.Process32FirstW, _kernel32.Process32NextW):
                if entry.szExeFile.lower() == process_name.lower():
                    return int(entry.th32ProcessID)
        raise RuntimeError(f"Target process not found: {process_name}")

    @staticmethod
    def _open_process(pid: int) -> HANDLE:
        access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
        handle = _kernel32.OpenProcess(access, False, pid)
        if not handle:
            raise RuntimeError(f"OpenProcess failed for pid {pid} (winerror={get_last_error()})")
        return handle

    @staticmethod
    def _find_module_by_name(pid: int, module_name: str) -> tuple[int, int]:
        target = module_name.lower()
        with _toolhelp_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) as snap:
            for entry in _iter_snapshot(snap, _MODULEENTRY32W,
                                        _kernel32.Module32FirstW, _kernel32.Module32NextW):
                if entry.szModule.lower() == target:
                    return int(entry.modBaseAddr), int(entry.modBaseSize)
        raise RuntimeError(f"Module not found: {module_name}")

    def _iter_regions(self, base: int, size: int) -> Iterator[tuple[int, int, _MEMORY_BASIC_INFORMATION]]:
        cursor = max(0, int(base))
        end = cursor + max(0, int(size))
        while cursor < end:
            mbi = _MEMORY_BASIC_INFORMATION()
            ret_len = c_size_t(0)
            status = _ntdll.NtQueryVirtualMemory(
                    self._process,
                    c_void_p(cursor),
                    MEMORY_BASIC_INFORMATION_CLASS,
                    byref(mbi),
                    sizeof(mbi),
                    byref(ret_len),
            )
            if status < 0:
                break

            region_base = int(mbi.BaseAddress or 0)
            region_size = int(mbi.RegionSize)
            if region_size <= 0:
                break
            region_end = region_base + region_size
            if region_end <= cursor:
                break

            yield max(cursor, region_base), min(end, region_end), mbi
            cursor = region_end

    @classmethod
    def _is_region_readable(cls, mbi: _MEMORY_BASIC_INFORMATION) -> bool:
        if mbi.State != MEM_COMMIT:
            return False
        protect = int(mbi.Protect)
        if protect == 0:
            return False
        if protect & PAGE_GUARD or protect & PAGE_NOACCESS:
            return False
        return (protect & 0xFF) in cls._READABLE_PROTECTIONS

    def _iter_readable_regions(self, base: int, size: int) -> Iterator[tuple[int, int, _MEMORY_BASIC_INFORMATION]]:
        for seg_start, seg_end, mbi in self._iter_regions(base, size):
            if seg_start < seg_end and self._is_region_readable(mbi):
                yield seg_start, seg_end, mbi
