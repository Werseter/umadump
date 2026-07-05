#!/usr/bin/env python3
"""IL2CPP metadata parsing and runtime type-resolution helpers.

This module bridges static ``global-metadata.dat`` type information with live
``Il2CppMetadataRegistration`` pointers from process memory.
"""
from __future__ import annotations

from ctypes import sizeof
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from struct import error as StructError, iter_unpack, unpack_from
from typing import Any, Optional, TypeAlias

from ctypes_utils import C_Ptr, StructOrSimple
from il2cpp_structs import (Il2CppFieldDefaultValue, Il2CppFieldDefinition, Il2CppGlobalMetadataHeader,
                            Il2CppImageDefinition, Il2CppMetadataRange, Il2CppMethodDefinition, Il2CppTypeDefinition,
                            RuntimeIl2CppClass, RuntimeIl2CppCodeGenModule, RuntimeIl2CppCodeRegistration,
                            RuntimeIl2CppGenericClass, RuntimeIl2CppMetadataRegistration, RuntimeIl2CppObject,
                            RuntimeIl2CppType)
from logger import logger
from memory import MemoryReader, POINTER_SIZE

TypeLookupKey: TypeAlias = tuple[str, tuple[str, ...]]


@dataclass(frozen=True)
class RuntimeTypeResolveContext:
    """Precomputed lookup tables used by ``Il2CppResolutionManager``."""

    type_def_index_by_full_name: dict[TypeLookupKey, int]
    type_index_to_typedef: tuple[int, ...]
    runtime_type_ptr_by_typedef: tuple[int, ...]
    typedef_by_type_metadata_handle: dict[int, int]


class Il2CppTypeEnum(IntEnum):
    VALUETYPE = 0x11
    CLASS = 0x12
    GENERICINST = 0x15


class Il2CppResolutionManager:
    """
    Manages resolution of runtime type pointers to metadata indices using global-metadata.dat
    and metadata registration info
    """

    def __init__(self, mem: MemoryReader, metadata: MinimalMetadata,
                 code_reg: RuntimeIl2CppCodeRegistration,
                 meta_reg: RuntimeIl2CppMetadataRegistration) -> None:
        self.mem = mem
        self.metadata = metadata
        self.code_reg = code_reg
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
        typedef_by_type_metadata_handle: dict[int, int] = {}
        for leaf_idx, _type_def in enumerate(type_defs):
            runtime_type_ptr = runtime_type_ptr_by_typedef[leaf_idx]
            if runtime_type_ptr:
                runtime_type = C_Ptr[RuntimeIl2CppType](runtime_type_ptr).contents
                type_metadata_handle = int(runtime_type.data)
                if type_metadata_handle:
                    typedef_by_type_metadata_handle.setdefault(type_metadata_handle, leaf_idx)

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
                type_index_to_typedef=tuple(type_index_to_typedef),
                runtime_type_ptr_by_typedef=tuple(runtime_type_ptr_by_typedef),
                typedef_by_type_metadata_handle=typedef_by_type_metadata_handle,
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

    def typedef_index_for_type_index(self, type_index: int) -> Optional[int]:
        if type_index < 0 or type_index >= len(self._context.type_index_to_typedef):
            return None
        typedef_index = self._context.type_index_to_typedef[type_index]
        return typedef_index if typedef_index >= 0 else None

    def typedef_index_for_type_metadata_handle(self, type_metadata_handle: int) -> Optional[int]:
        return self._context.typedef_by_type_metadata_handle.get(int(type_metadata_handle))

    def typedef_index_for_runtime_type(self, runtime_type: RuntimeIl2CppType) -> Optional[int]:
        try:
            type_bits = Il2CppTypeEnum(runtime_type.get_type_bits())
        except ValueError:
            return None
        if type_bits in (Il2CppTypeEnum.CLASS, Il2CppTypeEnum.VALUETYPE):
            return self.typedef_index_for_type_metadata_handle(int(runtime_type.data))
        if type_bits == Il2CppTypeEnum.GENERICINST and runtime_type.data:
            generic_class = C_Ptr[RuntimeIl2CppGenericClass](int(runtime_type.data)).contents
            if generic_class.type:
                return self.typedef_index_for_runtime_type(generic_class.type.contents)
        return None

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

    def _image_for_typedef(self, typedef_index: int) -> Optional[Il2CppImageDefinition]:
        for image_def in self.metadata.image_defs:
            start = int(image_def.typeStart)
            end = start + int(image_def.typeCount)
            if start <= typedef_index < end:
                return image_def
        return None

    def _find_codegen_module(self, module_name: str) -> Optional[RuntimeIl2CppCodeGenModule]:
        if not self.code_reg.codeGenModules:
            return None

        for module_ptr in self.code_reg.codeGenModules.as_span(self.code_reg.codeGenModulesCount):
            if not module_ptr:
                continue
            module = module_ptr.contents
            if module.moduleName.as_string == module_name:
                return module
        return None

    def _find_method_definition(self, typedef_index: int, method_name: str) \
            -> Optional[tuple[int, Il2CppMethodDefinition]]:
        type_def = self.metadata.type_defs[typedef_index]
        start = int(type_def.methodStart)
        end = start + int(type_def.method_count)
        for method_index in range(start, end):
            method_def = self.metadata.method_defs[method_index]
            if self.metadata.strings.get(int(method_def.nameIndex), "") == method_name:
                return method_index, method_def
        return None

    def _native_method_pointer(self, namespace: str, class_chain: list[str], method_name: str) -> Optional[int]:
        typedef_index = self.require_type_def_index(class_chain, namespace)
        image_def = self._image_for_typedef(typedef_index)
        if image_def is None:
            logger.warning("No metadata image found for %s::%s", namespace, ".".join(class_chain))
            return None

        method_match = self._find_method_definition(typedef_index, method_name)
        if method_match is None:
            logger.warning("Method not found in metadata: %s::%s.%s", namespace, ".".join(class_chain), method_name)
            return None
        method_index, method_def = method_match

        module_name = self.metadata.strings.get(int(image_def.nameIndex), "")
        module = self._find_codegen_module(module_name)
        if module is None:
            logger.warning("No CodeGenModule found for metadata image %s", module_name)
            return None

        if not module.methodPointers:
            logger.warning(
                    "CodeGenModule methodPointers is null for %s while resolving %s::%s.%s",
                    module_name, namespace, ".".join(class_chain), method_name,
            )
            return None

        candidate_indices = [method_index]
        row_index = method_def.get_token_row_id() - 1
        if row_index not in candidate_indices:
            candidate_indices.append(row_index)

        for candidate_index in candidate_indices:
            if 0 <= candidate_index < int(module.methodPointerCount):
                method_pointer = int(module.methodPointers[candidate_index])
                if method_pointer:
                    return method_pointer

        logger.warning(
                "No usable method pointer for %s::%s.%s in CodeGenModule %s",
                namespace, ".".join(class_chain), method_name, module_name,
        )
        return None

    TYPEINFO_ACCESSOR_SCAN_BYTES = 256

    def _rip_relative_targets(
            self,
            function_va: int,
            max_bytes: int = TYPEINFO_ACCESSOR_SCAN_BYTES,
            opcodes: Optional[set[int]] = None) -> list[int]:
        """Return memory targets referenced by simple x64 ``[rip + disp32]`` operands.

        IL2CPP-generated accessors for static properties usually touch a small
        global slot that stores the owning ``Il2CppClass*``. On x64 those globals
        are typically addressed relative to the current instruction pointer,
        not through absolute addresses. The effective address is:

            instruction_address + instruction_size + signed_disp32

        This is intentionally not a general disassembler. It only recognizes the
        compact instruction forms observed in generated IL2CPP accessor code and
        returns every matching memory target. Callers must treat the results as
        candidates and validate the pointed-to object before using it. ``opcodes``
        may be supplied by callers that only care about load/address forms; this
        keeps metadata-init flags and nearby comparisons out of typeinfo probing.
        """

        REX_PREFIXES = (0x48, 0x4C)
        MIN_INSTRUCTION_SIZE = 7
        DISPLACEMENT_OFFSET = 3
        DISPLACEMENT_SIZE = 4
        RIP_RELATIVE_MODRM_MASK = 0xC7
        RIP_RELATIVE_MODRM_VALUE = 0x05
        INSTRUCTION_SIZE_BY_OPCODE = {
            0x8B: 7,  # mov r32, [rip+disp32]
            0x8D: 7,  # lea r64, [rip+disp32]
            0x89: 7,  # mov [rip+disp32], r32
            0x39: 7,  # cmp [rip+disp32], r32
            0x83: 8,  # cmp/add/etc. [rip+disp32], imm8
        }

        code = self.mem.read(function_va, max_bytes)
        targets: list[int] = []
        offset = 0

        while offset + MIN_INSTRUCTION_SIZE <= len(code):
            if code[offset] not in REX_PREFIXES:
                offset += 1
                continue

            opcode = code[offset + 1]
            if opcodes is not None and opcode not in opcodes:
                offset += 1
                continue

            instruction_size = INSTRUCTION_SIZE_BY_OPCODE.get(opcode)
            if instruction_size is None:
                offset += 1
                continue

            if offset + instruction_size > len(code):
                break

            modrm = code[offset + 2]
            if (modrm & RIP_RELATIVE_MODRM_MASK) != RIP_RELATIVE_MODRM_VALUE:
                offset += 1
                continue

            displacement_start = offset + DISPLACEMENT_OFFSET
            displacement_end = displacement_start + DISPLACEMENT_SIZE
            displacement = int.from_bytes(code[displacement_start:displacement_end], "little", signed=True)
            targets.append(function_va + offset + instruction_size + displacement)
            offset += instruction_size

        return targets

    def static_fields_from_instance[TStaticFields: StructOrSimple](
            self,
            instance: Optional[C_Ptr[Any]],
            namespace: str,
            class_name: str,
            static_fields_type: type[TStaticFields]) -> Optional[C_Ptr[TStaticFields]]:
        """Resolve class static fields through an existing managed object instance.

        Every managed IL2CPP object begins with ``RuntimeIl2CppObject``, whose
        first field is the object's ``Il2CppClass*``. If a singleton ``_instance``
        is non-null, this is the simplest and most direct way to get the class
        static storage:

            instance -> instance._il2cpp_obj.klass -> klass.static_fields

        This does not require native-code scanning. It is only insufficient when
        the singleton instance has not been assigned yet, even though the class
        static fields are already initialized and live.
        """

        if not instance:
            return None

        try:
            object_header = C_Ptr[RuntimeIl2CppObject](int(instance)).contents
            klass = object_header.klass.contents
            if klass.namespaze.as_string != namespace or klass.name.as_string != class_name:
                return None
            if not klass.static_fields:
                return None
            logger.info("Resolved %s::%s Il2CppClass through instance", namespace, class_name)
            return klass.static_fields_as(static_fields_type)
        except Exception:
            return None

    def static_fields_from_typeinfo_method[TStaticFields: StructOrSimple](
            self, namespace: str, class_name: str, static_fields_type: type[TStaticFields],
            method_name: str) -> Optional[C_Ptr[TStaticFields]]:
        """Resolve class static fields through a native accessor's typeinfo reference.

        This path is used for classes where the static data may be live even
        though the singleton ``_instance`` field is still null.

        1. Resolve a known managed method to its native function pointer through
           ``CodeRegistration.methodPointers``.
        2. Read only the first small window of that function's machine code.
        3. Collect RIP-relative memory references that may be IL2CPP typeinfo
           globals.
        4. Dereference each candidate and keep only the one that validates as the
           requested ``RuntimeIl2CppClass`` by namespace and class name.
        5. Return that class's ``static_fields`` block cast to the requested
           ctypes layout.
        """

        method_va = self._native_method_pointer(namespace, [class_name], method_name)
        if not method_va:
            return None

        for global_va in self._rip_relative_targets(method_va, opcodes={0x8B, 0x8D}):
            candidate_class_vas = [global_va]
            try:
                class_va = self.mem.read_pointer(global_va)
            except Exception:
                pass
            else:
                if class_va:
                    candidate_class_vas.insert(0, class_va)

            seen: set[int] = set()
            for class_va in candidate_class_vas:
                if not class_va or class_va in seen:
                    continue
                seen.add(class_va)
                try:
                    klass = C_Ptr[RuntimeIl2CppClass](class_va).contents
                    candidate_namespace = klass.namespaze.as_string
                    candidate_name = klass.name.as_string
                    if candidate_namespace != namespace or candidate_name != class_name:
                        continue
                    logger.info(
                            "Resolved %s::%s Il2CppClass through %s at 0x%X",
                            namespace, class_name, method_name, class_va,
                    )
                    if not klass.static_fields:
                        return None
                    return klass.static_fields_as(static_fields_type)
                except Exception:
                    continue
        return None

    def static_fields_from_instance_or_typeinfo_method[TStaticFields: StructOrSimple](
            self,
            instance: Optional[C_Ptr[Any]],
            namespace: str,
            class_name: str,
            static_fields_type: type[TStaticFields],
            method_name: str) -> Optional[C_Ptr[TStaticFields]]:
        """Resolve static fields through ``_instance`` first, then the accessor fallback.

        Prefer this for singleton-backed classes such as ``MonoSingleton<T>``
        where ``_instance`` is usually available. The fallback keeps extraction
        working in the observed startup/transition cases where ``_instance`` is
        still null but class statics have already been initialized and are being
        read by game code.
        """

        static_fields = self.static_fields_from_instance(instance, namespace, class_name, static_fields_type)
        if static_fields:
            return static_fields
        return self.static_fields_from_typeinfo_method(namespace, class_name, static_fields_type, method_name)


# ---------------------------------------------------------------------------
# MinimalMetadata and global-metadata.dat parser
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MinimalMetadata:
    """Subset of metadata needed by the dumper and schema validator."""

    strings: dict[int, str]
    type_defs: tuple[Il2CppTypeDefinition, ...]
    image_defs: tuple[Il2CppImageDefinition, ...]
    method_defs: tuple[Il2CppMethodDefinition, ...]
    field_defs: tuple[Il2CppFieldDefinition, ...]
    int32_field_defaults_by_field_index: dict[int, int]
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


def _parse_int32_field_defaults(data: bytes, header: Il2CppGlobalMetadataHeader) -> dict[int, int]:
    """Return int32 field defaults keyed by metadata field index.

    Il2Cpp enum literals observed here are int32-backed and stored as compressed
    signed integers in fieldAndParameterDefaultValueData.
    """

    field_defaults = _parse_field_default_values(data, header.fieldDefaultValuesOffset, header.fieldDefaultValuesSize)
    values: dict[int, int] = {}
    data_offset = int(header.fieldAndParameterDefaultValueDataOffset)
    data_size = int(header.fieldAndParameterDefaultValueDataSize)
    for default in field_defaults:
        local_offset = int(default.dataIndex)
        if local_offset < 0 or local_offset >= data_size:
            continue
        value_offset = data_offset + local_offset
        try:
            values[int(default.fieldIndex)], _ = _read_compressed_int32(data, value_offset)
        except (StructError, ValueError):
            continue
    return values


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
    int32_field_defaults_by_field_index = _parse_int32_field_defaults(data, header)
    unresolved_count = header.unresolvedIndirectCallParameterRangesSize // sizeof(Il2CppMetadataRange)
    type_def_names = tuple(strings.get(type_def.nameIndex, "") for type_def in type_defs)
    type_def_namespaces = tuple(strings.get(type_def.namespaceIndex, "") for type_def in type_defs)
    field_def_names = tuple(strings.get(field_def.nameIndex, "") for field_def in field_defs)

    return MinimalMetadata(
            strings=strings, type_defs=type_defs, image_defs=image_defs, method_defs=method_defs, field_defs=field_defs,
            int32_field_defaults_by_field_index=int32_field_defaults_by_field_index,
            unresolved_indirect_call_param_ranges_count=unresolved_count,
            type_def_names=type_def_names,
            type_def_namespaces=type_def_namespaces,
            field_def_names=field_def_names,
    )


def default_metadata_path_from_exe(exe_path: str) -> Path:
    """Derive ``global-metadata.dat`` path from a Unity executable path."""

    exe = Path(exe_path)
    return exe.parent / f"{exe.stem}_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
