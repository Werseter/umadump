#!/usr/bin/env python3
"""IL2CPP metadata parsing and runtime type-resolution helpers.

This module bridges static ``global-metadata.dat`` type information with live
``Il2CppMetadataRegistration`` pointers from process memory.
"""
from __future__ import annotations

from ctypes import sizeof
from dataclasses import dataclass
from pathlib import Path
from struct import iter_unpack
from typing import Optional, TypeAlias

from il2cpp_structs import (Il2CppFieldDefinition, Il2CppGlobalMetadataHeader, Il2CppMetadataRange,
                            Il2CppTypeDefinition, RuntimeIl2CppMetadataRegistration)
from logger import logger
from memory import MemoryReader, POINTER_SIZE

TypeLookupKey: TypeAlias = tuple[str, tuple[str, ...]]


@dataclass(frozen=True)
class RuntimeTypeResolveContext:
    """Precomputed lookup tables used by ``Il2CppResolutionManager``."""

    type_def_index_by_full_name: dict[TypeLookupKey, int]
    runtime_type_ptr_by_typedef: tuple[int, ...]


class Il2CppResolutionManager:
    """
    Manages resolution of runtime type pointers to metadata indices using global-metadata.dat
    and metadata registration info
    """

    def __init__(self, mem: MemoryReader, metadata: MinimalMetadata,
                 meta_reg: RuntimeIl2CppMetadataRegistration) -> None:
        self.mem = mem
        self.metadata = metadata
        self.meta_reg = meta_reg
        self._runtime_type_ptr_addresses = self._build_runtime_type_ptr_addresses()
        self._context = self._build_resolve_context(self._runtime_type_ptr_addresses)

    def _build_runtime_type_ptr_addresses(self) -> tuple[int, ...]:
        count = int(self.meta_reg.typesCount)
        if count <= 0:
            raise RuntimeError(f"MetadataRegistration.typesCount is invalid: {count}")
        if not self.meta_reg.types:
            raise RuntimeError("MetadataRegistration.types pointer is null")
        blob = self.mem.read(self.meta_reg.types.address, count * POINTER_SIZE)
        return tuple(ptr for (ptr,) in iter_unpack("<Q", blob))

    def _build_resolve_context(self, type_ptrs: tuple[int, ...]) -> RuntimeTypeResolveContext:
        logger.debug("Building runtime type resolution context from metadata registration info...")
        type_index_to_typedef: list[int] = [-1] * len(type_ptrs)
        runtime_type_ptr_by_typedef: list[int] = [0] * len(self.metadata.type_defs)
        for typedef_idx, type_def in enumerate(self.metadata.type_defs):
            byval_type_index = int(type_def.byvalTypeIndex)
            if 0 <= byval_type_index < len(type_index_to_typedef):
                type_index_to_typedef[byval_type_index] = typedef_idx
                runtime_type_ptr_by_typedef[typedef_idx] = type_ptrs[byval_type_index]

        type_defs = self.metadata.type_defs
        type_def_names = self.metadata.type_def_names
        type_def_namespaces = self.metadata.type_def_namespaces
        type_def_index_by_full_name: dict[TypeLookupKey, int] = {}
        for leaf_idx, _type_def in enumerate(type_defs):
            class_chain = [type_def_names[leaf_idx]]
            current_idx: int = leaf_idx
            while True:
                declaring_type_index = int(type_defs[current_idx].declaringTypeIndex)
                if declaring_type_index < 0:
                    type_def_index_by_full_name.setdefault(
                            (type_def_namespaces[current_idx], tuple(reversed(class_chain))),
                            leaf_idx,
                    )
                    break
                if declaring_type_index >= len(type_index_to_typedef):
                    break

                parent_idx = type_index_to_typedef[declaring_type_index]
                if parent_idx < 0:
                    break

                class_chain.append(type_def_names[parent_idx])
                current_idx = parent_idx

        ctx = RuntimeTypeResolveContext(
                type_def_index_by_full_name=type_def_index_by_full_name,
                runtime_type_ptr_by_typedef=tuple(runtime_type_ptr_by_typedef),
        )
        resolved_ptrs = sum(1 for ptr in ctx.runtime_type_ptr_by_typedef if ptr)
        logger.debug("Built runtime type resolution context with %d typedef runtime type pointers", resolved_ptrs)
        return ctx

    def find_type_def_index(self, class_chain: list[str], namespace: str) -> Optional[int]:
        """Return leaf TypeDefinitionIndex for namespace::class_chain, validating nesting via meta_reg.types."""
        if not class_chain:
            return None
        return self._context.type_def_index_by_full_name.get((namespace, tuple(class_chain)))

    def require_type_def_index(self, class_chain: list[str], namespace: str) -> int:
        typedef_index = self.find_type_def_index(class_chain, namespace)
        if typedef_index is None:
            joined = ".".join(class_chain) if class_chain else "<empty>"
            raise RuntimeError(f"Type definition not found: {namespace}::{joined}")
        return typedef_index

    def runtime_type_ptr_for_typedef(self, typedef_index: int) -> int:
        if typedef_index < 0 or typedef_index >= len(self._context.runtime_type_ptr_by_typedef):
            return 0
        return self._context.runtime_type_ptr_by_typedef[typedef_index]

    def runtime_type_ptr_for_type_index(self, type_index: int) -> int:
        if type_index < 0 or type_index >= len(self._runtime_type_ptr_addresses):
            return 0
        return self._runtime_type_ptr_addresses[type_index]

    def require_runtime_type_ptr_for_typedef(self, typedef_index: int) -> int:
        runtime_type_ptr = self.runtime_type_ptr_for_typedef(typedef_index)
        if not runtime_type_ptr:
            type_name = "<unknown>"
            if 0 <= typedef_index < len(self.metadata.type_def_names):
                type_name = self.metadata.type_def_names[typedef_index]
            raise RuntimeError(f"Runtime type pointer not found for typedef {typedef_index} ({type_name})")
        return runtime_type_ptr

    def find_static_field_local_index(self, owner_typedef: int, field_name: str) -> Optional[int]:
        owner = self.metadata.type_defs[owner_typedef]
        start = owner.fieldStart
        end = start + owner.field_count
        for global_idx in range(start, end):
            if self.metadata.field_def_names[global_idx] == field_name:
                return global_idx - start
        return None

    def require_static_field_local_index(self, owner_typedef: int, field_name: str) -> int:
        field_local_index = self.find_static_field_local_index(owner_typedef, field_name)
        if field_local_index is None:
            owner_name = "<unknown>"
            if 0 <= owner_typedef < len(self.metadata.type_def_names):
                owner_name = self.metadata.type_def_names[owner_typedef]
            raise RuntimeError(f"Static field not found: {owner_name}.{field_name}")
        return field_local_index


# ---------------------------------------------------------------------------
# MinimalMetadata and global-metadata.dat parser
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MinimalMetadata:
    """Subset of metadata needed by the dumper and schema validator."""

    strings: dict[int, str]
    type_defs: tuple[Il2CppTypeDefinition, ...]
    field_defs: tuple[Il2CppFieldDefinition, ...]
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


def _parse_field_defs(data: bytes, offset: int, size: int) -> tuple[Il2CppFieldDefinition, ...]:
    """Parse ``Il2CppFieldDefinition`` entries from the metadata binary section."""

    type_size = sizeof(Il2CppFieldDefinition)
    count = size // type_size
    return tuple(Il2CppFieldDefinition.from_buffer_copy(data, offset + i * type_size) for i in range(count))


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
    field_defs = _parse_field_defs(data, header.fieldsOffset, header.fieldsSize)
    unresolved_count = header.unresolvedIndirectCallParameterRangesSize // sizeof(Il2CppMetadataRange)
    type_def_names = tuple(strings.get(type_def.nameIndex, "") for type_def in type_defs)
    type_def_namespaces = tuple(strings.get(type_def.namespaceIndex, "") for type_def in type_defs)
    field_def_names = tuple(strings.get(field_def.nameIndex, "") for field_def in field_defs)

    return MinimalMetadata(
            strings=strings, type_defs=type_defs, field_defs=field_defs,
            unresolved_indirect_call_param_ranges_count=unresolved_count,
            type_def_names=type_def_names,
            type_def_namespaces=type_def_namespaces,
            field_def_names=field_def_names,
    )


def default_metadata_path_from_exe(exe_path: str) -> Path:
    """Derive ``global-metadata.dat`` path from a Unity executable path."""

    exe = Path(exe_path)
    return exe.parent / f"{exe.stem}_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
