#!/usr/bin/env python3
"""
WorkDataManager singleton resolver.

Supports live mode (process memory reads) and offline mode (full-memory minidump).
Walks Il2CppMetadataRegistration to locate Gallop.Singleton<WorkDataManager>._instance.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, cast as type_cast

from ctypes_utils import C_Ptr, StructOrSimple
from game_structs import (TempDataObject, TempDataSingletonStaticFields, WorkDataManagerObject,
                          WorkDataManagerSingletonStaticFields)
from il2cpp_structs import (RuntimeIl2CppClass, RuntimeIl2CppGenericClass, RuntimeIl2CppGenericInst,
                            RuntimeIl2CppMetadataRegistration, RuntimeIl2CppType)
from il2cpp_utils import Il2CppResolutionManager, default_metadata_path_from_exe, parse_minimal_metadata
from json_encoders import (RaceReplayOutput, decode_card_data_dictionary, decode_champions_meeting_race,
                           decode_friend_data, decode_race_replays, decode_support_card_dictionary,
                           decode_trained_chara_dictionary, decode_trophy_data)
from logger import configure_logging, logger
from memory import MemoryReader, MinidumpMemory, POINTER_SIZE, TARGET_MODULE
from schema_validation import validate_registered_classes
from update_check import CURRENT_VERSION, notify_if_update_available

ProcessMemory: type[MemoryReader]
if os.name == "nt":
    # noinspection PyTypeChecker
    from memory import WindowsProcessMemory as ProcessMemory
else:
    # noinspection PyTypeChecker
    from memory import LinuxProcessMemory as ProcessMemory


# ---------------------------------------------------------------------------
# Registration scanner
# ---------------------------------------------------------------------------

class Il2CppRegistrationResolver:
    """Scans a process module for Il2CppMetadataRegistration."""

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

    def find_metadata_registration(self, type_def_count: int) -> Optional[int]:
        """
        Locate Il2CppMetadataRegistration by scanning for the
        (fieldOffsetsCount, …, typeDefinitionsSizesCount) pair.
        """
        # ---------------------------------------------------------------------------
        # Il2CppMetadataRegistration scan constants (x64).
        #
        # The struct alternates (int32_count, ptr) pairs.  On x64 each int32
        # is followed by 4 bytes of alignment padding, so every "slot"
        # occupies exactly POINTER_SIZE (8) bytes.  The slot numbering
        # below therefore counts 8-byte slots, not C fields:
        #
        #   [0] genericClassesCount      [1] genericClasses
        #   [2] genericInstsCount        [3] genericInsts
        #   [4] genericMethodTableCount  [5] genericMethodTable
        #   [6] typesCount               [7] types
        #   [8] methodSpecsCount         [9] methodSpecs
        #  [10] fieldOffsetsCount ← pattern anchor (= type_def_count)
        #  [11] fieldOffsets      ← wildcard
        #  [12] typeDefinitionsSizesCount ← second anchor (= type_def_count)
        #  [13] typeDefinitionsSizes ← validated pointer array
        #
        # _value_pattern() emits 8-byte patterns (value + zero padding)
        # which match the (int32 + pad) layout.
        # ---------------------------------------------------------------------------
        META_REG_SLOTS_BEFORE_ANCHOR = 10  # slots 0-9 precede fieldOffsetsCount
        META_REG_ARRAY_PTR_SLOT = 3  # typeDefinitionsSizes relative to anchor

        anchor = re.escape(self._value_bytes(type_def_count))
        pattern_re = re.compile(anchor + (b"." * POINTER_SIZE) + anchor, re.DOTALL)
        pattern_width = (POINTER_SIZE * 3)
        return self._find_registration(
                pattern_re=pattern_re,
                overlap=pattern_width - 1,
                array_ptr_offset=POINTER_SIZE * META_REG_ARRAY_PTR_SLOT,
                array_count=type_def_count,
                name="MetadataRegistration",
                offset_adjustment=-(POINTER_SIZE * META_REG_SLOTS_BEFORE_ANCHOR),
        )


# ---------------------------------------------------------------------------
# Misc Utils
# ---------------------------------------------------------------------------
def _write_json_file(name: str, output_path: Path, payload: Any) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pretty_json = json.dumps(payload, indent=2, ensure_ascii=False)
    output_path.write_text(pretty_json, encoding="utf-8")
    logger.info("%s: wrote JSON to %s", name, output_path)


def _write_multi_output_json(output_folder: Path, key: str, payload: Any) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, payload)


# ---------------------------------------------------------------------------
# Singleton resolution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GenericClassCollection:
    """Collected RuntimeIl2CppGenericClass pointers plus dereferenced cache by address."""

    ptrs: list[C_Ptr[RuntimeIl2CppGenericClass]]
    by_addr: dict[int, RuntimeIl2CppGenericClass]


def _collect_generic_classes(meta_reg: RuntimeIl2CppMetadataRegistration) -> GenericClassCollection:
    """Read and dereference ``MetadataRegistration.genericClasses`` into fast lookup form."""

    gc_ptrs = list(meta_reg.genericClasses.as_span(meta_reg.genericClassesCount))
    gc_addrs = [ptr.address for ptr in gc_ptrs if ptr]
    gc_values = C_Ptr[RuntimeIl2CppGenericClass].deref_many_at(gc_addrs)
    gc_by_addr: dict[int, RuntimeIl2CppGenericClass] = {addr: gc for addr, gc in zip(gc_addrs, gc_values)}
    return GenericClassCollection(ptrs=gc_ptrs, by_addr=gc_by_addr)


@dataclass(frozen=True)
class SingletonGenericClassMatch:
    seq: int
    class_ptr: C_Ptr[RuntimeIl2CppClass]


@dataclass(frozen=True)
class SingletonSpec[TSingletonObject: StructOrSimple]:
    name: str
    target_type: str
    static_fields_type: type[Any]
    output_type: type[TSingletonObject]
    namespace: str = "Gallop"
    singleton_class: str = "Singleton`1"
    singleton_namespace: str = "Gallop"


WORKDATAMANAGER_SINGLETON_SPEC = SingletonSpec(
        name="workdatamanager",
        target_type="WorkDataManager",
        static_fields_type=WorkDataManagerSingletonStaticFields,
        output_type=WorkDataManagerObject,
)

TEMPDATA_SINGLETON_SPEC = SingletonSpec(
        name="tempdata",
        target_type="TempData",
        static_fields_type=TempDataSingletonStaticFields,
        output_type=TempDataObject,
)

SINGLETON_SPEC_REGISTRY: dict[str, SingletonSpec[Any]] = {
    spec.name: spec for spec in (
        WORKDATAMANAGER_SINGLETON_SPEC,
        TEMPDATA_SINGLETON_SPEC,
    )
}


def _build_singleton_generic_index(meta_reg: RuntimeIl2CppMetadataRegistration) \
        -> dict[tuple[int, int], SingletonGenericClassMatch]:
    """Build ``(generic-definition-type-ptr, arg0-type-ptr) -> matched class`` index."""
    generic_classes = _collect_generic_classes(meta_reg)

    gc_by_seq: dict[int, RuntimeIl2CppGenericClass] = {}
    inst_addrs: list[int] = []
    for seq, gc_ptr in enumerate(generic_classes.ptrs):
        if not gc_ptr:
            continue
        gc = generic_classes.by_addr[gc_ptr.address]
        if not gc.context.class_inst:
            continue
        gc_by_seq[seq] = gc
        inst_addrs.append(gc.context.class_inst.address)

    inst_values = C_Ptr[RuntimeIl2CppGenericInst].deref_many_at(inst_addrs)
    inst_by_addr = {addr: inst for addr, inst in zip(inst_addrs, inst_values)}

    argv0_ptr_addrs: list[int] = []
    argv0_index_by_inst_addr: dict[int, int] = {}
    for inst_addr, inst in inst_by_addr.items():
        if inst.type_argc < 1 or not inst.type_argv:
            continue
        argv0_index_by_inst_addr[inst_addr] = len(argv0_ptr_addrs)
        argv0_ptr_addrs.append(inst.type_argv.address)

    argv0_ptrs = C_Ptr[C_Ptr[RuntimeIl2CppType]].deref_many_at(argv0_ptr_addrs)
    argv0_type_ptr_by_inst_addr = {
        inst_addr: argv0_ptrs[idx].address
        for inst_addr, idx in argv0_index_by_inst_addr.items()
    }

    by_key: dict[tuple[int, int], SingletonGenericClassMatch] = {}
    for seq, gc in gc_by_seq.items():
        arg0_type_ptr = argv0_type_ptr_by_inst_addr.get(gc.context.class_inst.address)
        if arg0_type_ptr is None or not gc.cached_class or not gc.type:
            continue
        generic_type_addr = gc.type.address
        if generic_type_addr is None:
            continue
        if not isinstance(generic_type_addr, int) or not isinstance(arg0_type_ptr, int):
            continue
        key = (generic_type_addr, arg0_type_ptr)
        by_key.setdefault(key, SingletonGenericClassMatch(seq=seq, class_ptr=gc.cached_class))
    return by_key


def resolve_singleton[TSingletonObject: StructOrSimple](
        resolver: Il2CppResolutionManager,
        spec: SingletonSpec[TSingletonObject],
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch]) -> Optional[C_Ptr[TSingletonObject]]:
    meta_reg = resolver.meta_reg
    if not meta_reg.genericClasses:
        logger.warning("MetadataRegistration genericClasses pointer is missing")
        return None

    singleton_typedef = resolver.require_type_def_index([spec.singleton_class], spec.singleton_namespace)
    target_typedef = resolver.require_type_def_index([spec.target_type], spec.namespace)
    singleton_type_ptr = resolver.require_runtime_type_ptr_for_typedef(singleton_typedef)
    target_type_ptr = resolver.require_runtime_type_ptr_for_typedef(target_typedef)
    resolver.require_static_field_local_index(singleton_typedef, "_instance")

    matched = singleton_index.get((singleton_type_ptr, target_type_ptr))
    if matched is None:
        type_string = f"{spec.singleton_namespace}::{spec.singleton_class}[{spec.namespace}{spec.target_type}]"
        logger.warning("No %s instantiation found", type_string)
        return None

    logger.debug("Matched singleton generic instantiation at index %d", matched.seq)
    static_fields_type = spec.static_fields_type
    # noinspection PyTypeHints
    static_fields_ptr_type = C_Ptr[static_fields_type]  # type: ignore[valid-type]
    static_fields_ptr = static_fields_ptr_type(int(matched.class_ptr.contents.static_fields))
    # noinspection PyTypeChecker
    return type_cast(C_Ptr[TSingletonObject], static_fields_ptr.contents._instance)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Extractor definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Extractor[TExtractorInput, TMultiOutputPayload]:
    """
    Unified extractor definition.

    Single-file mode:  set ``output_path``; the extracted payload is serialised directly.
    Multi-file mode:   set ``output_folder``, ``key_fn`` (and optionally ``writer``);
                       the payload is written to ``output_folder/<key>.json``.
    """
    name: str
    extract: Callable[[TExtractorInput], Any]
    output_path: Optional[Path] = None
    output_folder: Optional[Path] = None
    key_fn: Optional[Callable[[TMultiOutputPayload], str]] = None
    writer: Optional[Callable[[Path, str, TMultiOutputPayload], None]] = None


def _run_extractors(extractors: tuple[Extractor[Any, Any], ...], data: Any) -> None:
    """Run a sequence of extractors against *data*, writing output as configured."""
    for extractor in extractors:
        logger.info("Running extractor: %s", extractor.name)
        try:
            payload = extractor.extract(data)
            if extractor.output_path is not None:
                _write_json_file(extractor.name, extractor.output_path, payload)
            elif extractor.output_folder is not None and extractor.key_fn is not None:
                extractor.output_folder.mkdir(parents=True, exist_ok=True)
                writer = extractor.writer or _write_multi_output_json
                payloads = payload if isinstance(payload, list) else [payload]
                for item in payloads:
                    key = extractor.key_fn(item)
                    if not key:
                        continue
                    writer(extractor.output_folder, key, item)
        except Exception:
            logger.exception("Error in extractor %s", extractor.name)


def _extract_support_cards(wdm: WorkDataManagerObject) -> Any:
    support_cards = decode_support_card_dictionary(wdm)
    logger.info("Decoded %d support cards", len(support_cards))
    return support_cards


def _extract_trained_chara_data(wdm: WorkDataManagerObject) -> Any:
    trained_charas = decode_trained_chara_dictionary(wdm)
    logger.info("Decoded %d trained chara entries", len(trained_charas))
    return trained_charas


def _extract_card_data(wdm: WorkDataManagerObject) -> Any:
    cards = decode_card_data_dictionary(wdm)
    # game calls the owned character data "card" data, making a distinction between alternate costume variants this way
    logger.info("Decoded %d owned character entries", len(cards))
    return cards


def _extract_friend_data(wdm: WorkDataManagerObject) -> dict[str, Any]:
    friends = decode_friend_data(wdm)
    logger.info("Decoded friend data with %d friend entries", len(friends.get('friend_list', [])))
    return friends


def _extract_trophy_data(wdm: WorkDataManagerObject) -> list[dict[str, Any]]:
    trophies = decode_trophy_data(wdm)
    logger.info("Decoded trophy data with %d trophy entries", len(trophies))
    return trophies


def _extract_race_replays(wdm: WorkDataManagerObject) -> list[RaceReplayOutput]:
    replays = decode_race_replays(wdm)
    logger.info("Decoded %d race replay payloads", len(replays))
    return replays


def _race_replay_key(replay: RaceReplayOutput) -> str:
    return replay.key


def _write_race_replay_json(output_folder: Path, key: str, replay: RaceReplayOutput) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, replay.payload)


WORKDATA_EXTRACTORS: tuple[Extractor[Any, Any], ...] = (
    Extractor(
            name="support_cards",
            output_path=Path("support_card_data.json"),
            extract=_extract_support_cards,
    ),
    Extractor(
            name="trained_chara_data",
            output_path=Path("trained_chara_data.json"),
            extract=_extract_trained_chara_data,
    ),
    Extractor(
            name="card_data",
            output_path=Path("card_data.json"),
            extract=_extract_card_data,
    ),
    Extractor(
            name="friend_data",
            output_path=Path("friend_data.json"),
            extract=_extract_friend_data
    ),
    Extractor(
            name="trophy_data",
            output_path=Path("trophy_data.json"),
            extract=_extract_trophy_data,
    ),
    Extractor(
            name="race_replays",
            output_folder=Path("race_replays"),
            extract=_extract_race_replays,
            key_fn=_race_replay_key,
            writer=_write_race_replay_json,
    ),
)


def _champions_meeting_race_room_id(payload: dict[str, Any]) -> str:
    room_id = payload.get("data", {}).get("room_info", {}).get("room_id", 0)
    if not room_id:
        logger.debug("Champions meeting race has no room_id, skipping folder extraction")
        return ""
    return str(room_id)


TEMPDATA_EXTRACTORS: tuple[Extractor[Any, Any], ...] = (
    Extractor(
            name="champions_meeting_race_folder",
            output_folder=Path("champions_meeting_race"),
            extract=decode_champions_meeting_race,
            key_fn=_champions_meeting_race_room_id,
            writer=_write_multi_output_json,
    ),
)


@dataclass(frozen=True)
class SingletonExtractorSet:
    """A singleton root plus the extractors that consume it."""

    spec: SingletonSpec[Any]
    extractors: tuple[Extractor[Any, Any], ...]


SINGLETON_EXTRACTOR_SETS: tuple[SingletonExtractorSet, ...] = (
    SingletonExtractorSet(WORKDATAMANAGER_SINGLETON_SPEC, WORKDATA_EXTRACTORS),
    SingletonExtractorSet(TEMPDATA_SINGLETON_SPEC, TEMPDATA_EXTRACTORS),
)

ResolvedSingletonRoots = dict[str, Optional[C_Ptr[Any]]]


def _resolve_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch]) -> ResolvedSingletonRoots:
    """Resolve singleton roots once so reload passes can skip the metadata/generic scan."""
    roots: ResolvedSingletonRoots = {}
    for extractor_set in SINGLETON_EXTRACTOR_SETS:
        spec = extractor_set.spec
        roots[spec.name] = resolve_singleton(resolver, spec, singleton_index)
    return roots


def _dump_singleton_root(extractor_set: SingletonExtractorSet, instance: Optional[C_Ptr[Any]]) -> None:
    """Run configured extractors from an already-resolved singleton root."""
    spec = extractor_set.spec
    if not instance:
        logger.warning("%s not resolved", spec.target_type)
        return

    _run_extractors(extractor_set.extractors, instance.contents)


def _dump_from_singleton_roots(roots: ResolvedSingletonRoots) -> float:
    """Run all extractors from already-resolved singleton roots and return elapsed seconds."""
    t_start = time.perf_counter()
    for extractor_set in SINGLETON_EXTRACTOR_SETS:
        _dump_singleton_root(extractor_set, roots.get(extractor_set.spec.name))
    return time.perf_counter() - t_start


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parse CLI flags for live/minidump mode and optional validation-only run."""

    parser = argparse.ArgumentParser(
            description="Resolve Gallop.WorkDataManager from a live process or an offline minidump")
    parser.add_argument("--version", action="version", version=f"%(prog)s {CURRENT_VERSION}")
    parser.add_argument("--minidump", help="Path to full-memory minidump (offline mode)")
    parser.add_argument("--metadata-path", help="global-metadata.dat path; required with --minidump")
    parser.add_argument("--no-update-check", action="store_true",
                        help="Skip the startup GitHub release check")
    parser.add_argument("--validate-only", action="store_true",
                        help="Only validate registered classes and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()
    if args.minidump and not args.metadata_path:
        parser.error("--metadata-path is required when using --minidump")
    return args


@dataclass(frozen=True)
class SetupContext:
    mem: MemoryReader
    metadata_path: Path


def _setup(args: argparse.Namespace) -> SetupContext:
    """Build memory interface and metadata path from CLI args."""
    mem: MemoryReader
    if args.minidump:
        logger.info("Offline mode from minidump: %s", args.minidump)
        mem = MinidumpMemory(args.minidump)
        metadata_path = Path(args.metadata_path)
    else:
        logger.info("Live mode from process memory")
        mem = ProcessMemory()
        metadata_path = Path(args.metadata_path) if args.metadata_path else default_metadata_path_from_exe(
                mem.exe_path())

    return SetupContext(mem=mem, metadata_path=metadata_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _build_resolver(mem: MemoryReader, metadata_path: Path) -> Il2CppResolutionManager:
    """Create ``Il2CppResolutionManager`` and run schema validation for registered wrappers."""

    metadata = parse_minimal_metadata(metadata_path)
    logger.info("Parsed metadata: type_defs=%d", len(metadata.type_defs))

    base, size = mem.module_info(TARGET_MODULE)

    reg_va = Il2CppRegistrationResolver(mem, base, size).find_metadata_registration(len(metadata.type_defs))
    if reg_va is None:
        raise RuntimeError("Could not locate Il2CppMetadataRegistration")
    meta_reg = C_Ptr[RuntimeIl2CppMetadataRegistration](reg_va).contents

    resolver = Il2CppResolutionManager(mem, metadata, meta_reg)
    validate_registered_classes(resolver)
    return resolver


def _run_live_reload_loop(mem: MemoryReader, roots: ResolvedSingletonRoots) -> None:
    """Repeatedly rerun extractors using fixed singleton roots and fresh memory reads."""
    pass_num = 1
    while True:
        if not mem.is_alive():
            logger.info("Target process has exited; stopping live reload")
            return

        if pass_num > 1:
            logger.info("Clearing memory cache before reload pass %d", pass_num)
            mem.clear_cache()

        logger.info("Reload extractor pass %d", pass_num)
        elapsed = _dump_from_singleton_roots(roots)
        logger.info("Reload extractor pass %d completed in %.2fs", pass_num, elapsed)

        try:
            response = input("Press Enter to rescan, or type q then Enter to exit...")
        except EOFError:
            return

        if response.strip().lower() in {"q", "quit", "exit"}:
            return

        pass_num += 1


def main() -> None:
    args = _parse_args()
    configure_logging(args.verbose)
    t_start = time.perf_counter()

    logger.info("umadump %s", CURRENT_VERSION)
    if not args.no_update_check:
        notify_if_update_available(CURRENT_VERSION)

    setup = _setup(args)
    logger.info("Metadata path: %s", setup.metadata_path)

    with setup.mem:
        try:
            resolver = _build_resolver(setup.mem, setup.metadata_path)

            if args.validate_only:
                return

            logger.info("Scanning %d generic class instantiations...", resolver.meta_reg.genericClassesCount)
            singleton_index = _build_singleton_generic_index(resolver.meta_reg)
            roots = _resolve_singleton_roots(resolver, singleton_index)
            if not args.minidump:
                _run_live_reload_loop(setup.mem, roots)
            else:
                elapsed = _dump_from_singleton_roots(roots)
                logger.info("Extractor pass completed in %.2fs", elapsed)
        finally:
            logger.info("Total time: %.2fs", time.perf_counter() - t_start)
    if args.minidump and sys.stdin.isatty():
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
