"""Read seekable Zstd minidumps using a bounded frame cache.

Files must use the standard seekable format without optional entry checksums;
Zstd frame checksums are verified on access. Limits reject oversized indexes/frames
before allocation.
"""
from __future__ import annotations

from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Buffer
from compression.zstd import DecompressionParameter, ZstdDecompressor, get_frame_info
from contextlib import ExitStack
from io import BufferedIOBase, Reader, SEEK_CUR, SEEK_END, SEEK_SET
from itertools import accumulate
from operator import index
from struct import Struct
from typing import BinaryIO, NamedTuple, SupportsIndex

_MIB = 1024 * 1024
DEFAULT_FRAME_CACHE_BYTES = 256 * _MIB
_MAX_FRAMES = 65536
_MAX_FRAME_BYTES = 64 * _MIB
_MAX_COMPRESSED_FRAME_BYTES = _MAX_FRAME_BYTES + _MIB
_SEEK_TABLE_MAGIC = 0x184D2A5E
_SEEK_FOOTER_MAGIC = 0x8F92EAB1
_TABLE_HEADER = Struct("<II")
_TABLE_FOOTER = Struct("<IBI")
_TABLE_ENTRY = Struct("<II")


class _Frame(NamedTuple):
    compressed_offset: int
    compressed_size: int
    decoded_size: int


def _read_exact(source: Reader[bytes], size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise EOFError("Truncated seekable Zstd dump")
    return data


def _read_seek_footer(source: BinaryIO) -> tuple[int, int]:
    """Read file size and frame count, rejecting unsupported index formats."""
    file_size = source.seek(0, SEEK_END)
    if file_size < _TABLE_FOOTER.size:
        raise ValueError("Compressed dump has no Zstd seek table; repack with compress_minidump.py")
    source.seek(-_TABLE_FOOTER.size, SEEK_END)
    footer_data: tuple[int, int, int] = _TABLE_FOOTER.unpack(_read_exact(source, _TABLE_FOOTER.size))
    frame_count, descriptor, magic = footer_data
    if magic != _SEEK_FOOTER_MAGIC:
        raise ValueError("Compressed dump has no Zstd seek table; repack with compress_minidump.py")
    if descriptor & 0x7C:
        raise ValueError("Unsupported reserved bits in Zstd seek-table descriptor")
    if descriptor & 0x80:
        raise ValueError("Zstd seek tables with optional entry checksums are not supported")
    if frame_count > _MAX_FRAMES:
        raise ValueError(f"Zstd seek table exceeds {_MAX_FRAMES} frames")
    return file_size, frame_count


def _read_seek_entries(source: BinaryIO, file_size: int, frame_count: int) -> tuple[bytes, int]:
    """Locate and validate the table header before reading its bounded entries."""
    table_size = frame_count * _TABLE_ENTRY.size + _TABLE_FOOTER.size
    table_offset = file_size - _TABLE_HEADER.size - table_size
    if table_offset < 0:
        raise ValueError("Zstd seek table extends before the file")
    source.seek(table_offset)
    table_magic, declared_size = _TABLE_HEADER.unpack(_read_exact(source, _TABLE_HEADER.size))
    if table_magic != _SEEK_TABLE_MAGIC or declared_size != table_size:
        raise ValueError("Invalid Zstd seek-table header")
    entries = _read_exact(source, frame_count * _TABLE_ENTRY.size)
    return entries, table_offset


def _decode_seek_frames(entries: bytes, table_offset: int) -> tuple[_Frame, ...]:
    """Validate frame sizes and require exact coverage of the compressed data."""
    frames: list[_Frame] = []
    offset = 0
    for compressed_size, decoded_size in _TABLE_ENTRY.iter_unpack(entries):
        if not 0 < compressed_size <= _MAX_COMPRESSED_FRAME_BYTES or decoded_size > _MAX_FRAME_BYTES:
            raise ValueError("Zstd seek-table frame exceeds supported size limits")
        frames.append(_Frame(offset, compressed_size, decoded_size))
        offset += compressed_size
    if offset != table_offset:
        raise ValueError("Zstd seek table does not cover the data frames exactly")
    return tuple(frames)


def _read_seek_table(source: BinaryIO) -> tuple[_Frame, ...]:
    """Require a valid seek table before allocating any decoded frames."""
    file_size, frame_count = _read_seek_footer(source)
    entries, table_offset = _read_seek_entries(source, file_size, frame_count)
    return _decode_seek_frames(entries, table_offset)


class SeekableZstdReader(BufferedIOBase):
    """Own a compressed file; logical seeks never decode, reads verify whole frames.

    The cache bounds retained frame bytes, not caller-requested output buffers.
    This immutable-file reader, like the minidump reader, is not thread-safe.
    """

    def __init__(self, source: BinaryIO, *, cache_bytes: int = DEFAULT_FRAME_CACHE_BYTES) -> None:
        super().__init__()
        self._source = source
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._cache_bytes = 0
        with ExitStack() as cleanup:
            cleanup.callback(self.close)
            frames = _read_seek_table(source)
            self._cache_limit = index(cache_bytes)
            if self._cache_limit <= 0 or any(frame.decoded_size > self._cache_limit for frame in frames):
                raise ValueError("Zstd frame cache must be positive and fit each decoded frame")
            self._frames = frames
            self._ends = tuple(accumulate(frame.decoded_size for frame in frames))
            self._size = self._ends[-1] if self._ends else 0
            self._position = 0
            for frame in frames:
                if frame.decoded_size == 0:
                    self._decode_frame(frame)
            cleanup.pop_all()

    def _require_open(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed Zstd dump")

    def _decode_frame(self, frame: _Frame) -> bytes:
        self._source.seek(frame.compressed_offset)
        encoded = _read_exact(self._source, frame.compressed_size)
        info = get_frame_info(encoded)
        if info.decompressed_size is not None and info.decompressed_size != frame.decoded_size:
            raise ValueError("Zstd frame size differs from its seek-table entry")
        if info.dictionary_id:
            raise ValueError("Dictionary-compressed Zstd dump frames are not supported")
        decoder = ZstdDecompressor(options={DecompressionParameter.window_log_max: 26})
        decoded = decoder.decompress(encoded, max_length=frame.decoded_size + 1)
        if len(decoded) != frame.decoded_size or not decoder.eof or decoder.unused_data:
            raise ValueError("Zstd frame payload differs from its seek-table entry")
        return decoded

    def _frame_data(self, frame_index: int) -> bytes:
        if frame_index in self._cache:
            self._cache.move_to_end(frame_index)
            return self._cache[frame_index]
        frame = self._frames[frame_index]
        while self._cache_bytes + frame.decoded_size > self._cache_limit:
            _, evicted = self._cache.popitem(last=False)
            self._cache_bytes -= len(evicted)
        decoded = self._decode_frame(frame)
        self._cache[frame_index] = decoded
        self._cache_bytes += len(decoded)
        return decoded

    def read(self, size: SupportsIndex | None = -1) -> bytes:
        self._require_open()
        available = max(0, self._size - self._position)
        requested = -1 if size is None else index(size)
        count = available if requested < 0 else min(available, requested)
        if not count:
            return b""
        frame_index = bisect_right(self._ends, self._position)
        if self._position + count <= self._ends[frame_index]:
            start = self._ends[frame_index] - self._frames[frame_index].decoded_size
            local = self._position - start
            result = self._frame_data(frame_index)[local:local + count]
            self._position += count
            return result
        result_buffer = bytearray(count)
        self.readinto(result_buffer)
        return bytes(result_buffer)

    def readinto(self, buffer: Buffer) -> int:
        self._require_open()
        with memoryview(buffer).cast("B") as view:
            if view.readonly:
                raise TypeError("readinto requires a writable buffer")
            count = min(len(view), max(0, self._size - self._position))
            written = 0
            while written < count:
                frame_index = bisect_right(self._ends, self._position)
                start = self._ends[frame_index] - self._frames[frame_index].decoded_size
                take = min(count - written, self._ends[frame_index] - self._position)
                local = self._position - start
                decoded = self._frame_data(frame_index)
                view[written:written + take] = memoryview(decoded)[local:local + take]
                self._position += take
                written += take
            return written

    def seek(self, offset: SupportsIndex, whence: int = SEEK_SET) -> int:
        self._require_open()
        offset_value = index(offset)
        whence = index(whence)
        if whence == SEEK_SET:
            position = offset_value
        elif whence == SEEK_CUR:
            position = self._position + offset_value
        elif whence == SEEK_END:
            position = self._size + offset_value
        else:
            raise ValueError("Invalid seek mode")
        if position < 0:
            raise ValueError("Negative seek position")
        self._position = position
        return position

    def tell(self) -> int:
        self._require_open()
        return self._position

    def readable(self) -> bool:
        self._require_open()
        return True

    def seekable(self) -> bool:
        self._require_open()
        return True

    def writable(self) -> bool:
        self._require_open()
        return False

    def close(self) -> None:
        if not self.closed:
            try:
                self._cache.clear()
                self._cache_bytes = 0
                self._source.close()
            finally:
                super().close()


def open_compressed_dump(path: str, *, cache_bytes: int = DEFAULT_FRAME_CACHE_BYTES) -> SeekableZstdReader:
    """The reader owns the opened file, including cleanup if initialization fails."""
    return SeekableZstdReader(open(path, "rb"), cache_bytes=cache_bytes)
