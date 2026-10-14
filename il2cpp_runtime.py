#!/usr/bin/env python3
"""Shared IL2CPP runtime bootstrap for schema and raw dump tools."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ctypes_utils import C_Ptr
from il2cpp_metadata import (default_metadata_path_from_exe, parse_minimal_metadata_from_file,
                             parse_minimal_metadata_from_memory)
from il2cpp_registration import Il2CppMetadataResolver, Il2CppRegistrationResolver
from il2cpp_structs import RuntimeIl2CppCodeRegistration, RuntimeIl2CppMetadataRegistration
from il2cpp_utils import Il2CppResolutionManager
from logger import logger
from memory import MemoryReader, MinidumpMemory, ProcessMemory, TARGET_MODULE
from schema_validation import validate_registered_schema


@dataclass(frozen=True)
class RuntimeSetup:
    mem: MemoryReader
    metadata_path: Optional[Path]


def setup_memory(minidump: Optional[str], metadata_path: Optional[str]) -> RuntimeSetup:
    """Select the memory backend and optional explicit metadata-file override."""
    mem: MemoryReader
    if minidump:
        logger.info("Offline mode from minidump: %s", minidump)
        mem = MinidumpMemory(minidump)
    else:
        logger.info("Live mode from process memory")
        mem = ProcessMemory()

    resolved_metadata_path = Path(metadata_path) if metadata_path else None
    return RuntimeSetup(mem=mem, metadata_path=resolved_metadata_path)


def build_resolver(mem: MemoryReader, metadata_path: Optional[Path] = None) -> Il2CppResolutionManager:
    """Discover the metadata or use an explicit file, falling back to the default location if available."""

    base, size = mem.module_info(TARGET_MODULE)
    if metadata_path is not None:
        metadata = parse_minimal_metadata_from_file(metadata_path)
        logger.info("Metadata source: explicit file override (%s)", metadata_path)
    else:
        try:
            metadata_resolver = Il2CppMetadataResolver(mem, base, size)
            data_address, header_address = metadata_resolver.find_global_metadata()
            metadata = parse_minimal_metadata_from_memory(mem, data_address, header_address)
        except (ValueError, RuntimeError) as error:
            if not isinstance(mem, ProcessMemory):
                raise
            fallback_path = default_metadata_path_from_exe(mem.exe_path())
            logger.warning("In-memory metadata discovery failed (%s); trying installed metadata file %s",
                           error, fallback_path)
            metadata = parse_minimal_metadata_from_file(fallback_path)
            logger.info("Metadata source: installed file fallback (%s)", fallback_path)
        else:
            logger.info("Metadata source: in-memory discovery")
    logger.info("Parsed metadata: type_defs=%d", len(metadata.type_defs))

    registration_resolver = Il2CppRegistrationResolver(mem, base, size)
    param_ranges_count = metadata.unresolved_indirect_call_param_ranges_count
    code_reg_va = registration_resolver.find_code_registration(param_ranges_count, len(metadata.image_defs))
    if code_reg_va is None:
        raise RuntimeError("Could not locate Il2CppCodeRegistration")
    code_reg = C_Ptr[RuntimeIl2CppCodeRegistration](code_reg_va).contents

    reg_va = registration_resolver.find_metadata_registration(len(metadata.type_defs))
    if reg_va is None:
        raise RuntimeError("Could not locate Il2CppMetadataRegistration")
    meta_reg = C_Ptr[RuntimeIl2CppMetadataRegistration](reg_va).contents

    resolver = Il2CppResolutionManager(mem, metadata, code_reg, meta_reg)
    validate_registered_schema(resolver)
    return resolver
