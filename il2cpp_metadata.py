"""Static IL2CPP metadata parsing and integral default-value decoding."""
from __future__ import annotations

from ctypes import c_int16, c_int32, c_int64, c_int8, c_uint16, c_uint32, c_uint64, c_uint8, sizeof
from dataclasses import dataclass
from pathlib import Path
from struct import unpack_from

from ctypes_utils import EnumStorageType
from il2cpp_structs import (Il2CppFieldDefaultValue, Il2CppFieldDefinition, Il2CppGlobalMetadataHeader,
                            Il2CppImageDefinition, Il2CppMetadataRange, Il2CppMethodDefinition, Il2CppTypeDefinition)
from logger import logger


@dataclass(frozen=True)
class MinimalMetadata:
    """Subset of metadata needed by the dumper and schema validator."""

    strings: dict[int, str]
    type_defs: tuple[Il2CppTypeDefinition, ...]
    image_defs: tuple[Il2CppImageDefinition, ...]
    method_defs: tuple[Il2CppMethodDefinition, ...]
    field_defs: tuple[Il2CppFieldDefinition, ...]
    field_default_data_by_field_index: dict[int, bytes]
    unresolved_indirect_call_param_ranges_count: int
    type_def_names: tuple[str, ...]
    type_def_namespaces: tuple[str, ...]
    field_def_names: tuple[str, ...]


def _parse_cstrings(data: bytes, offset: int, size: int) -> dict[int, str]:
    """Parse a null-terminated string blob into ``relative_offset -> str``."""

    blob = data[offset:offset + size]
    strings: dict[int, str] = {}
    i = 0
    while i < len(blob):
        end = blob.find(b"\0", i)
        if end < 0:
            end = len(blob)
        strings[i] = blob[i:end].decode("utf-8", errors="replace")
        i = end + 1
    return strings


def _parse_type_defs(data: bytes, offset: int, size: int) -> tuple[Il2CppTypeDefinition, ...]:
    """Parse ``Il2CppTypeDefinition`` entries from the metadata binary section."""

    type_size = sizeof(Il2CppTypeDefinition)
    count = size // type_size
    return tuple(Il2CppTypeDefinition.from_buffer_copy(data, offset + i * type_size) for i in range(count))


def _parse_image_defs(data: bytes, offset: int, size: int) -> tuple[Il2CppImageDefinition, ...]:
    """Parse ``Il2CppImageDefinition`` entries from the metadata binary section."""

    type_size = sizeof(Il2CppImageDefinition)
    count = size // type_size
    return tuple(Il2CppImageDefinition.from_buffer_copy(data, offset + i * type_size) for i in range(count))


def _parse_method_defs(data: bytes, offset: int, size: int) -> tuple[Il2CppMethodDefinition, ...]:
    """Parse ``Il2CppMethodDefinition`` entries from the metadata binary section."""

    type_size = sizeof(Il2CppMethodDefinition)
    count = size // type_size
    return tuple(Il2CppMethodDefinition.from_buffer_copy(data, offset + i * type_size) for i in range(count))


def _parse_field_defs(data: bytes, offset: int, size: int) -> tuple[Il2CppFieldDefinition, ...]:
    """Parse ``Il2CppFieldDefinition`` entries from the metadata binary section."""

    type_size = sizeof(Il2CppFieldDefinition)
    count = size // type_size
    return tuple(Il2CppFieldDefinition.from_buffer_copy(data, offset + i * type_size) for i in range(count))


def _parse_field_default_values(data: bytes, offset: int, size: int) -> tuple[Il2CppFieldDefaultValue, ...]:
    """Parse ``Il2CppFieldDefaultValue`` entries from the metadata binary section."""

    type_size = sizeof(Il2CppFieldDefaultValue)
    count = size // type_size
    return tuple(Il2CppFieldDefaultValue.from_buffer_copy(data, offset + i * type_size) for i in range(count))


def _read_compressed_uint32(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if (first & 0x80) == 0:
        return first, offset + 1
    if (first & 0xC0) == 0x80:
        return unpack_from(">H", data, offset)[0] & 0x3FFF, offset + 2
    if (first & 0xE0) == 0xC0:
        return unpack_from(">I", data, offset)[0] & 0x1FFFFFFF, offset + 4
    if first == 0xF0:
        return unpack_from("<I", data, offset + 1)[0], offset + 5
    if first == 0xFE:
        return 0xFFFFFFFE, offset + 1
    if first == 0xFF:
        return 0xFFFFFFFF, offset + 1
    raise ValueError(f"Invalid compressed uint32 marker: 0x{first:02X}")


def _read_compressed_int32(data: bytes, offset: int) -> tuple[int, int]:
    encoded, offset = _read_compressed_uint32(data, offset)
    if encoded == 0xFFFFFFFF:
        return -0x80000000, offset
    value = encoded >> 1
    if encoded & 1:
        return -(value + 1), offset
    return value, offset


def _parse_field_default_data(data: bytes, header: Il2CppGlobalMetadataHeader) -> dict[int, bytes]:
    """Preserve raw default-value data until its exact IL2CPP storage is known."""
    field_defaults = _parse_field_default_values(data, header.fieldDefaultValuesOffset, header.fieldDefaultValuesSize)
    values: dict[int, bytes] = {}
    data_offset = int(header.fieldAndParameterDefaultValueDataOffset)
    data_size = int(header.fieldAndParameterDefaultValueDataSize)
    for default in field_defaults:
        local_offset = int(default.dataIndex)
        if local_offset < 0 or local_offset >= data_size:
            continue
        value_offset = data_offset + local_offset
        # Eight bytes cover all supported enum bases and the compressed I4/U4
        # representation.  Decoding happens after ``value__`` is resolved.
        values[int(default.fieldIndex)] = data[value_offset:min(value_offset + 8, data_offset + data_size)]
    return values


def decode_integer_field_default(raw_data: bytes, storage_type: EnumStorageType) -> int:
    """Decode an IL2CPP integral literal using its resolved fixed-width storage."""

    def _fixed_width(width: int, *, signed: bool) -> int:
        if len(raw_data) < width:
            raise ValueError(f"truncated {width}-byte field default")
        return int.from_bytes(raw_data[:width], byteorder="little", signed=signed)

    if storage_type is c_int8:
        return _fixed_width(1, signed=True)
    if storage_type is c_uint8:
        return _fixed_width(1, signed=False)
    if storage_type is c_int16:
        return _fixed_width(2, signed=True)
    if storage_type is c_uint16:
        return _fixed_width(2, signed=False)
    if storage_type is c_int32:
        return _read_compressed_int32(raw_data, 0)[0]
    if storage_type is c_uint32:
        return _read_compressed_uint32(raw_data, 0)[0]
    if storage_type is c_int64:
        return _fixed_width(8, signed=True)
    if storage_type is c_uint64:
        return _fixed_width(8, signed=False)
    raise TypeError(f"unsupported integer default storage: {storage_type!r}")


def parse_minimal_metadata(metadata_path: Path) -> MinimalMetadata:
    """Load and parse the minimal set of sections required by this project."""

    data = metadata_path.read_bytes()
    header = Il2CppGlobalMetadataHeader.from_buffer_copy(data)

    if header.sanity != 0xFAB11BAF:
        raise ValueError("Invalid metadata header sanity value (expected 0xFAB11BAF)")
    if header.version != 31:
        logger.warning("Unexpected metadata version %d (expected 31)", header.version)

    strings = _parse_cstrings(data, header.stringOffset, header.stringSize)
    type_defs = _parse_type_defs(data, header.typeDefinitionsOffset, header.typeDefinitionsSize)
    image_defs = _parse_image_defs(data, header.imagesOffset, header.imagesSize)
    method_defs = _parse_method_defs(data, header.methodsOffset, header.methodsSize)
    field_defs = _parse_field_defs(data, header.fieldsOffset, header.fieldsSize)
    field_default_data_by_field_index = _parse_field_default_data(data, header)
    unresolved_count = header.unresolvedIndirectCallParameterRangesSize // sizeof(Il2CppMetadataRange)
    type_def_names = tuple(strings.get(type_def.nameIndex, "") for type_def in type_defs)
    type_def_namespaces = tuple(strings.get(type_def.namespaceIndex, "") for type_def in type_defs)
    field_def_names = tuple(strings.get(field_def.nameIndex, "") for field_def in field_defs)

    return MinimalMetadata(
            strings=strings, type_defs=type_defs, image_defs=image_defs, method_defs=method_defs, field_defs=field_defs,
            field_default_data_by_field_index=field_default_data_by_field_index,
            unresolved_indirect_call_param_ranges_count=unresolved_count,
            type_def_names=type_def_names,
            type_def_namespaces=type_def_namespaces,
            field_def_names=field_def_names,
    )


def default_metadata_path_from_exe(exe_path: str) -> Path:
    """Derive ``global-metadata.dat`` path from a Unity executable path."""

    exe = Path(exe_path)
    return exe.parent / f"{exe.stem}_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
