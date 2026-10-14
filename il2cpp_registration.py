#!/usr/bin/env python3
"""Assembly-based metadata discovery and metadata-guided registration scans."""
from __future__ import annotations

import re
import struct
from typing import Optional

from logger import logger
from memory import MemoryReader, POINTER_SIZE

# GlobalMetadata::GetTypeDefinitionForIndex reads header.typeDefinitionsOffset
# (v31: 0xA0) and adds the metadata base. Only RIP displacements vary:
#   48 8B 05 <header disp32>     mov    rax, [rip + header_global]
#   48 63 90 A0 00 00 00         movsxd rdx, dword ptr [rax + 0xA0]
#   48 03 15 <data disp32>       add    rdx, [rip + metadata_global]
_TYPE_DEFINITION_METADATA = re.compile(
        rb"\x48\x8b\x05(?P<header>.{4})"
        rb"\x48\x63\x90\xa0\x00\x00\x00"
        rb"\x48\x03\x15(?P<data>.{4})", re.DOTALL)
_METADATA_ACCESSOR_BYTES = 21


class Il2CppMetadataResolver:
    """Find loaded metadata using a module-bounded v31 accessor scan."""

    def __init__(self, mem: MemoryReader, module_base: int, module_size: int) -> None:
        self.mem = mem
        self.module_base = module_base
        self.module_size = module_size

    @staticmethod
    def _global_slot(address: int, match: re.Match[bytes], name: str) -> int:
        return address + match.end(name) + int.from_bytes(match[name], "little", signed=True)

    def find_global_metadata(self) -> tuple[int, int]:
        """Return initialized data/header pointers; the metadata parser validates their layout."""
        module_end = self.module_base + self.module_size
        try:
            for address in self.mem.scan(self.module_base, self.module_size, _TYPE_DEFINITION_METADATA,
                                         _METADATA_ACCESSOR_BYTES - 1):
                match = _TYPE_DEFINITION_METADATA.match(self.mem.read(address, _METADATA_ACCESSOR_BYTES))
                if match is None:
                    raise ValueError("IL2CPP metadata accessor changed during discovery")
                slots = tuple(self._global_slot(address, match, name) for name in ("data", "header"))
                if not all(self.module_base <= slot <= module_end - POINTER_SIZE for slot in slots):
                    continue
                data, header = (self.mem.read_pointer(slot) for slot in slots)
                if not data or not header:
                    raise ValueError("IL2CPP metadata is not initialized")
                logger.info("Resolved in-memory IL2CPP metadata at 0x%X", data)
                return data, header
            raise ValueError("IL2CPP metadata accessor was not found in the module")
        except ValueError as error:
            raise ValueError(f"{error}; supply --metadata-path") from error


class Il2CppRegistrationResolver:
    """Scans a process module for IL2CPP runtime registration structs."""

    def __init__(self, mem: MemoryReader, module_base: int, module_size: int) -> None:
        self.mem = mem
        self.module_base = module_base
        self.module_size = module_size

    def _in_module(self, va: int) -> bool:
        return self.module_base <= va < self.module_base + self.module_size

    def _value_bytes(self, value: int) -> bytes:
        return value.to_bytes(POINTER_SIZE, "little", signed=False)

    def _read_ptr_table(self, ptr: int, count: int) -> list[int]:
        if not ptr or count == 0:
            return []
        return list(struct.unpack(f"<{count}Q", self.mem.read(ptr, count * POINTER_SIZE)))

    def _find_registration(self, pattern_re: re.Pattern[bytes], overlap: int,
                           array_ptr_offset: int, array_count: int,
                           name: str, offset_adjustment: int) -> Optional[int]:
        logger.info("Scanning for %s", name)
        for match_va in self.mem.scan(self.module_base, self.module_size, pattern_re, overlap):
            array_ptr_va = self.mem.read_pointer(match_va + array_ptr_offset)
            if not self._in_module(array_ptr_va):
                continue

            pointers = self._read_ptr_table(array_ptr_va, array_count)
            if not all(self._in_module(x) for x in pointers):
                continue

            result = match_va + offset_adjustment
            logger.info("Found %s", name)
            return result

        logger.warning("%s was not found in the module scan range", name)
        return None

    def find_code_registration(self, unresolved_indirect_call_count: int, image_count: int) -> Optional[int]:
        """
        Locate Il2CppCodeRegistration by scanning for unresolvedIndirectCallCount
        followed by codeGenModulesCount/codeGenModules.
        """
        CODE_REG_SLOTS_BEFORE_ANCHOR = 7
        CODE_REG_CODEGEN_MODULES_PTR_SLOT = 9

        unresolved_anchor = re.escape(self._value_bytes(unresolved_indirect_call_count))
        image_anchor = re.escape(self._value_bytes(image_count))
        pattern_re = re.compile(unresolved_anchor + (b"." * POINTER_SIZE * 7) + image_anchor, re.DOTALL)
        pattern_width = POINTER_SIZE * 9
        return self._find_registration(
                pattern_re=pattern_re,
                overlap=pattern_width - 1,
                array_ptr_offset=POINTER_SIZE * CODE_REG_CODEGEN_MODULES_PTR_SLOT,
                array_count=image_count,
                name="CodeRegistration",
                offset_adjustment=-(POINTER_SIZE * CODE_REG_SLOTS_BEFORE_ANCHOR),
        )

    def find_metadata_registration(self, type_def_count: int) -> Optional[int]:
        """
        Locate Il2CppMetadataRegistration by scanning for the
        (fieldOffsetsCount, …, typeDefinitionsSizesCount) pair.
        """
        META_REG_SLOTS_BEFORE_ANCHOR = 10  # slots 0-9 precede fieldOffsetsCount
        META_REG_ARRAY_PTR_SLOT = 3  # typeDefinitionsSizes relative to anchor

        anchor = re.escape(self._value_bytes(type_def_count))
        pattern_re = re.compile(anchor + (b"." * POINTER_SIZE) + anchor, re.DOTALL)
        pattern_width = POINTER_SIZE * 3
        return self._find_registration(
                pattern_re=pattern_re,
                overlap=pattern_width - 1,
                array_ptr_offset=POINTER_SIZE * META_REG_ARRAY_PTR_SLOT,
                array_count=type_def_count,
                name="MetadataRegistration",
                offset_adjustment=-(POINTER_SIZE * META_REG_SLOTS_BEFORE_ANCHOR),
        )
