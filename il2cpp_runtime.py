#!/usr/bin/env python3
"""Shared IL2CPP runtime bootstrap for schema and raw dump tools."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ctypes_utils import C_Ptr
from il2cpp_registration import Il2CppRegistrationResolver
from il2cpp_structs import RuntimeIl2CppMetadataRegistration
from il2cpp_utils import Il2CppResolutionManager, default_metadata_path_from_exe, parse_minimal_metadata
from logger import logger
from memory import MemoryReader, MinidumpMemory, ProcessMemory, TARGET_MODULE
from schema_validation import validate_registered_schema


@dataclass(frozen=True)
class RuntimeSetup:
    mem: MemoryReader
    metadata_path: Path


def setup_memory(minidump: Optional[str], metadata_path: Optional[str]) -> RuntimeSetup:
    """Build memory interface and metadata path from CLI-style inputs."""
    mem: MemoryReader
    if minidump:
        logger.info("Offline mode from minidump: %s", minidump)
        mem = MinidumpMemory(minidump)
        if not metadata_path:
            raise ValueError("metadata_path is required when using a minidump")
        resolved_metadata_path = Path(metadata_path)
    else:
        logger.info("Live mode from process memory")
        mem = ProcessMemory()
        if metadata_path:
            resolved_metadata_path = Path(metadata_path)
        else:
            resolved_metadata_path = default_metadata_path_from_exe(mem.exe_path())

    return RuntimeSetup(mem=mem, metadata_path=resolved_metadata_path)


def build_resolver(mem: MemoryReader, metadata_path: Path) -> Il2CppResolutionManager:
    """Create ``Il2CppResolutionManager`` and run schema validation for registered wrappers."""

    metadata = parse_minimal_metadata(metadata_path)
    logger.info("Parsed metadata: type_defs=%d", len(metadata.type_defs))

    base, size = mem.module_info(TARGET_MODULE)
    registration_resolver = Il2CppRegistrationResolver(mem, base, size)

    reg_va = registration_resolver.find_metadata_registration(len(metadata.type_defs))
    if reg_va is None:
        raise RuntimeError("Could not locate Il2CppMetadataRegistration")
    meta_reg = C_Ptr[RuntimeIl2CppMetadataRegistration](reg_va).contents

    resolver = Il2CppResolutionManager(mem, metadata, meta_reg)
    validate_registered_schema(resolver)
    return resolver
