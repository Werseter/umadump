#!/usr/bin/env python3
"""
WorkDataManager singleton resolver plus RaceManager static-field resolver.

Supports live mode (process memory reads) and offline mode (full-memory minidump).
Walks Il2CppMetadataRegistration for generic singletons and CodeRegistration for
RaceManager static fields.
"""
from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, cast as type_cast

from ctypes_utils import C_Ptr, StructOrSimple
from game_structs import (RaceManagerObject, RaceManagerSingletonStaticFields, RaceManagerStaticFields,
                          WorkDataManagerObject, WorkDataManagerSingletonStaticFields)
from il2cpp_runtime import build_resolver, setup_memory
from il2cpp_structs import (RuntimeIl2CppClass, RuntimeIl2CppGenericClass, RuntimeIl2CppGenericInst,
                            RuntimeIl2CppMetadataRegistration, RuntimeIl2CppType)
from il2cpp_utils import Il2CppResolutionManager
from json_encoders import (CardDataExtractionData, ExtractorFingerprint, FingerprintableExtractionData,
                           FriendDataExtractionData, IdleSingleModeExtractionData, IdleSingleModeOutput,
                           RaceInfoReplayExtractionData, RaceReplayOutput, SupportCardExtractionData,
                           TeamStadiumReplayExtractionData, TrainedCharaExtractionData, TrophyDataExtractionData,
                           decode_card_data_dictionary, decode_friend_data, decode_idle_single_mode,
                           decode_race_info_replay, decode_support_card_dictionary, decode_team_stadium_replay,
                           decode_trained_chara_dictionary, decode_trophy_data, resolve_card_data_extraction_data,
                           resolve_friend_data_extraction_data, resolve_idle_single_mode,
                           resolve_race_info_replay_extraction_data, resolve_support_card_extraction_data,
                           resolve_team_stadium_replay_extraction_data, resolve_trained_chara_extraction_data,
                           resolve_trophy_data_extraction_data)
from logger import configure_logging, logger
from memory import MemoryReader, TransientMemoryReadError
from schema_validation import RuntimeValidatableIl2CppClassManager, TransientRuntimeValidationError
from update_check import CURRENT_VERSION, notify_if_update_available


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

RACEMANAGER_SINGLETON_SPEC = SingletonSpec(
        name="racemanager",
        target_type="RaceManager",
        static_fields_type=RaceManagerSingletonStaticFields,
        output_type=RaceManagerObject,
        singleton_class="MonoSingleton`1",
)

SINGLETON_SPEC_REGISTRY: dict[str, SingletonSpec[Any]] = {
    spec.name: spec for spec in (
        WORKDATAMANAGER_SINGLETON_SPEC,
        RACEMANAGER_SINGLETON_SPEC,
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
    if not static_fields_ptr:
        logger.debug("%s singleton static fields are null", spec.name)
        return None
    # noinspection PyTypeChecker
    return type_cast(C_Ptr[TSingletonObject], static_fields_ptr.contents._instance)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Extractor definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Extractor[TExtractorInput, TExtractionData: FingerprintableExtractionData, TMultiOutputPayload]:
    """
    Unified extractor definition.

    Single-file mode:  set ``output_path``; the extracted payload is serialised directly.
    Multi-file mode:   set ``output_folder``, ``key_fn`` (and optionally ``writer``);
                       the payload is written to ``output_folder/<key>.json``.
    """
    name: str
    resolve: Callable[[TExtractorInput], Optional[TExtractionData]]
    extract: Callable[[TExtractionData], Any]
    output_path: Optional[Path] = None
    output_folder: Optional[Path] = None
    key_fn: Optional[Callable[[TMultiOutputPayload], str]] = None
    writer: Optional[Callable[[Path, str, TMultiOutputPayload], None]] = None


@dataclass
class ExtractionRunState:
    fingerprints: dict[str, ExtractorFingerprint] = field(default_factory=dict)

    def should_run(self, name: str, fingerprint: ExtractorFingerprint) -> bool:
        return self.fingerprints.get(name) != fingerprint

    def record(self, name: str, fingerprint: ExtractorFingerprint) -> None:
        self.fingerprints[name] = fingerprint


ResolvedSingletonRoots = dict[str, Optional[C_Ptr[Any]]]


@dataclass(frozen=True)
class ExtractionContext:
    roots: ResolvedSingletonRoots

    def singleton[TSingletonObject: StructOrSimple](self, spec: SingletonSpec[TSingletonObject]) \
            -> Optional[C_Ptr[TSingletonObject]]:
        # noinspection PyTypeChecker
        return type_cast(Optional[C_Ptr[TSingletonObject]], self.roots.get(spec.name))

    def require_singleton[TSingletonObject: StructOrSimple](self, spec: SingletonSpec[TSingletonObject]) \
            -> TSingletonObject:
        instance = self.singleton(spec)
        if not instance:
            raise RuntimeError(f"{spec.target_type} not resolved")
        return instance.contents


def _run_extractors(
        extractors: tuple[Extractor[Any, Any, Any], ...],
        data: Any,
        state: Optional[ExtractionRunState] = None) -> None:
    """Run a sequence of extractors against *data*, writing output as configured."""
    for extractor in extractors:
        _run_extractor(extractor, data, state)


def _run_extractor[TExtractionData: FingerprintableExtractionData](
        extractor: Extractor[Any, TExtractionData, Any],
        data: Any,
        state: Optional[ExtractionRunState]) -> None:
    try:
        extraction_data = extractor.resolve(data)
        if extraction_data is None:
            logger.debug("%s: extraction data unavailable; skipping write", extractor.name)
            return

        fingerprint = extraction_data.fingerprint()
        if _skip_unchanged_extractor(extractor.name, fingerprint, state):
            return

        logger.info("Running extractor: %s", extractor.name)
        payload = extractor.extract(extraction_data)
        if state is not None:
            state.record(extractor.name, fingerprint)
        _write_extractor_payload(extractor, payload)
    except (TransientMemoryReadError, TransientRuntimeValidationError) as exc:
        logger.warning("%s: transient memory state; extraction skipped: %s", extractor.name, exc)
    except Exception:
        logger.exception("Error in extractor %s", extractor.name)


def _skip_unchanged_extractor(
        name: str,
        fingerprint: ExtractorFingerprint,
        state: Optional[ExtractionRunState]) -> bool:
    if state is None or state.should_run(name, fingerprint):
        return False
    logger.debug("%s: extraction data unchanged; skipping extractor", name)
    return True


def _write_extractor_payload(extractor: Extractor[Any, Any, Any], payload: Any) -> None:
    if _is_empty_payload(payload):
        logger.debug("%s: empty payload; skipping write", extractor.name)
        return
    if extractor.output_path is not None:
        _write_json_file(extractor.name, extractor.output_path, payload)
    elif extractor.output_folder is not None and extractor.key_fn is not None:
        _write_multi_output_payloads(extractor, payload)


def _write_multi_output_payloads(extractor: Extractor[Any, Any, Any], payload: Any) -> None:
    if extractor.output_folder is None or extractor.key_fn is None:
        return
    extractor.output_folder.mkdir(parents=True, exist_ok=True)
    writer = extractor.writer or _write_multi_output_json
    payloads = payload if isinstance(payload, list) else [payload]
    for item in payloads:
        if _is_empty_payload(item):
            logger.debug("%s: empty multi-output item; skipping write", extractor.name)
            continue
        key = extractor.key_fn(item)
        if key:
            writer(extractor.output_folder, key, item)


def _is_empty_payload(payload: Any) -> bool:
    def _is_container(value: Any) -> bool:
        return isinstance(value, (dict, list, tuple, set))

    if payload is None:
        return True
    if _is_container(payload) and not payload:
        return True
    if isinstance(payload, dict):
        container_values = [value for value in payload.values() if _is_container(value)]
        if container_values and all(not value for value in container_values):
            return True
    return False


def _resolve_support_cards(ctx: ExtractionContext) -> Optional[SupportCardExtractionData]:
    wdm = ctx.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)
    return resolve_support_card_extraction_data(wdm)


def _extract_support_cards(data: SupportCardExtractionData) -> list[dict[str, Any]]:
    support_cards = decode_support_card_dictionary(data)
    logger.info("Decoded %d support cards", len(support_cards))
    return support_cards


def _resolve_trained_chara_data(ctx: ExtractionContext) -> Optional[TrainedCharaExtractionData]:
    wdm = ctx.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)
    return resolve_trained_chara_extraction_data(wdm)


def _extract_trained_chara_data(data: TrainedCharaExtractionData) -> list[dict[str, Any]]:
    trained_charas = decode_trained_chara_dictionary(data)
    logger.info("Decoded %d trained chara entries", len(trained_charas))
    return trained_charas


def _resolve_card_data(ctx: ExtractionContext) -> Optional[CardDataExtractionData]:
    wdm = ctx.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)
    return resolve_card_data_extraction_data(wdm)


def _extract_card_data(data: CardDataExtractionData) -> list[dict[str, Any]]:
    cards = decode_card_data_dictionary(data)
    # game calls the owned character data "card" data, making a distinction between alternate costume variants this way
    logger.info("Decoded %d owned character entries", len(cards))
    return cards


def _resolve_friend_data(ctx: ExtractionContext) -> Optional[FriendDataExtractionData]:
    wdm = ctx.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)
    return resolve_friend_data_extraction_data(wdm)


def _extract_friend_data(data: FriendDataExtractionData) -> dict[str, Any]:
    friends = decode_friend_data(data)
    logger.info("Decoded friend data with %d friend entries", len(friends.get('friend_list', [])))
    return friends


def _resolve_trophy_data(ctx: ExtractionContext) -> Optional[TrophyDataExtractionData]:
    wdm = ctx.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)
    return resolve_trophy_data_extraction_data(wdm)


def _extract_trophy_data(data: TrophyDataExtractionData) -> list[dict[str, Any]]:
    trophies = decode_trophy_data(data)
    logger.info("Decoded trophy data with %d trophy entries", len(trophies))
    return trophies


def _resolve_team_stadium_replay(ctx: ExtractionContext) -> Optional[TeamStadiumReplayExtractionData]:
    wdm = ctx.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)
    return resolve_team_stadium_replay_extraction_data(wdm)


def _extract_team_stadium_replay(data: TeamStadiumReplayExtractionData) -> Optional[RaceReplayOutput]:
    replay = decode_team_stadium_replay(data)
    logger.info("Decoded %d Team Stadium replay payloads", 1 if replay else 0)
    return replay


def _replay_output_key(replay: RaceReplayOutput) -> str:
    return replay.key


def _write_race_replay_json(output_folder: Path, key: str, replay: RaceReplayOutput) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, replay.payload)


def _resolve_race_info_replay(ctx: ExtractionContext) -> Optional[RaceInfoReplayExtractionData]:
    race_manager_static = ctx.roots.get("racemanager_static")
    if not race_manager_static:
        return None
    return resolve_race_info_replay_extraction_data(race_manager_static.contents)


def _extract_race_info_replay(data: RaceInfoReplayExtractionData) -> RaceReplayOutput:
    return decode_race_info_replay(data)


def _resolve_idle_single_mode(ctx: ExtractionContext) -> Optional[IdleSingleModeExtractionData]:
    wdm = ctx.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)
    return resolve_idle_single_mode(wdm)


def _extract_idle_single_mode(data: IdleSingleModeExtractionData) -> IdleSingleModeOutput:
    return decode_idle_single_mode(data)


def _idle_single_mode_key(ism: IdleSingleModeOutput) -> str:
    return ism.key


def _write_idle_single_mode_json(output_folder: Path, key: str, ism: IdleSingleModeOutput) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, ism.payload)


EXTRACTORS: tuple[Extractor[Any, Any, Any], ...] = (
    Extractor(
            name="support_cards",
            output_path=Path("support_card_data.json"),
            resolve=_resolve_support_cards,
            extract=_extract_support_cards,
    ),
    Extractor(
            name="trained_chara_data",
            output_path=Path("trained_chara_data.json"),
            resolve=_resolve_trained_chara_data,
            extract=_extract_trained_chara_data,
    ),
    Extractor(
            name="card_data",
            output_path=Path("card_data.json"),
            resolve=_resolve_card_data,
            extract=_extract_card_data,
    ),
    Extractor(
            name="friend_data",
            output_path=Path("friend_data.json"),
            resolve=_resolve_friend_data,
            extract=_extract_friend_data,
    ),
    Extractor(
            name="trophy_data",
            output_path=Path("trophy_data.json"),
            resolve=_resolve_trophy_data,
            extract=_extract_trophy_data,
    ),
    Extractor(
            name="team_stadium_replay",
            output_folder=Path("race_replays"),
            resolve=_resolve_team_stadium_replay,
            extract=_extract_team_stadium_replay,
            key_fn=_replay_output_key,
            writer=_write_race_replay_json,
    ),
    Extractor(
            name="race_info_replay",
            output_folder=Path("race_replays"),
            resolve=_resolve_race_info_replay,
            extract=_extract_race_info_replay,
            key_fn=_replay_output_key,
            writer=_write_race_replay_json,
    ),
    Extractor(
            name="idle_single_mode",
            output_folder=Path("idle_single_mode"),
            resolve=_resolve_idle_single_mode,
            extract=_extract_idle_single_mode,
            key_fn=_idle_single_mode_key,
            writer=_write_idle_single_mode_json,
    ),
)

RACEMANAGER_STATIC_ROOT = "racemanager_static"


def _init_singleton_roots() -> ResolvedSingletonRoots:
    roots: ResolvedSingletonRoots = {spec.name: None for spec in SINGLETON_SPEC_REGISTRY.values()}
    roots[RACEMANAGER_STATIC_ROOT] = None
    return roots


def _invalidate_singleton_roots(roots: ResolvedSingletonRoots) -> None:
    for name in roots:
        roots[name] = None


def _root_type_metadata_handle(root: C_Ptr[Any]) -> Optional[int]:
    if not root:
        return None
    klass = root.contents._il2cpp_obj.klass
    if not klass:
        return None
    type_metadata_handle = klass.contents.typeMetadataHandle.address
    return int(type_metadata_handle) if type_metadata_handle else None


def _cached_singleton_roots_are_valid(roots: ResolvedSingletonRoots) -> bool:
    for spec in SINGLETON_SPEC_REGISTRY.values():
        root = roots.get(spec.name)
        if not root:
            continue

        expected_handle = RuntimeValidatableIl2CppClassManager.get_expected_type_metadata_handle(spec.output_type)
        if expected_handle is None:
            continue

        try:
            actual_handle = _root_type_metadata_handle(root)
        except Exception as exc:
            logger.debug("%s singleton root validation failed: %s", spec.name, exc)
            return False

        if actual_handle != expected_handle:
            logger.info(
                    "%s singleton root is stale; refreshing anchors (expected=0x%X, actual=%s)",
                    spec.name,
                    expected_handle,
                    f"0x{actual_handle:X}" if actual_handle is not None else "null",
            )
            return False

    return True


def _refresh_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots) -> None:
    """Resolve roots that are not established yet, leaving non-null anchors unchanged."""
    for spec in SINGLETON_SPEC_REGISTRY.values():
        if roots.get(spec.name) is None:
            roots[spec.name] = resolve_singleton(resolver, spec, singleton_index)

    if roots.get(RACEMANAGER_STATIC_ROOT) is not None:
        return

    roots[RACEMANAGER_STATIC_ROOT] = resolver.static_fields_from_instance_or_typeinfo_method(
            roots.get(RACEMANAGER_SINGLETON_SPEC.name),
            "Gallop",
            "RaceManager",
            RaceManagerStaticFields,
            "get_RaceInfo",
    )


def _refresh_live_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots) -> None:
    if not _cached_singleton_roots_are_valid(roots):
        _invalidate_singleton_roots(roots)
    _refresh_singleton_roots(resolver, singleton_index, roots)


def _dump_from_singleton_roots(
        roots: ResolvedSingletonRoots,
        state: Optional[ExtractionRunState] = None) -> float:
    """Run all extractors from already-resolved singleton roots and return elapsed seconds."""
    t_start = time.perf_counter()
    _run_extractors(EXTRACTORS, ExtractionContext(roots), state)
    return time.perf_counter() - t_start


def _prepare_memory_pass(mem: MemoryReader) -> None:
    mem.clear_cache()


def _finish_memory_pass(mem: MemoryReader) -> None:
    mem.clear_cache()
    gc.collect()


def _run_live_extractor_pass(
        mem: MemoryReader,
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots,
        state: ExtractionRunState,
        pass_num: int,
        label: str,
        log: Callable[..., None]) -> float:
    _prepare_memory_pass(mem)
    try:
        if pass_num > 1:
            log("Refreshing singleton roots before %s pass %d", label.lower(), pass_num)
        _refresh_live_singleton_roots(resolver, singleton_index, roots)

        log("%s extractor pass %d", label, pass_num)
        return _dump_from_singleton_roots(roots, state)
    finally:
        _finish_memory_pass(mem)


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
    parser.add_argument("--rerun-mode", choices=("once", "prompt", "daemon"),
                        help="Live rerun behavior. Defaults to prompt in live mode and once in minidump mode.")
    parser.add_argument("--poll-interval", type=float, default=2.0,
                        help="Seconds between daemon extraction passes")
    parser.add_argument("--validate-only", action="store_true",
                        help="Only validate registered classes and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()
    if args.minidump and not args.metadata_path:
        parser.error("--metadata-path is required when using --minidump")
    if args.minidump and args.rerun_mode in {"prompt", "daemon"}:
        parser.error("--rerun-mode prompt/daemon requires live process mode")
    if args.poll_interval <= 0:
        parser.error("--poll-interval must be greater than 0")
    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _run_live_reload_loop(
        mem: MemoryReader,
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots,
        poll_interval: float) -> None:
    """Repeatedly rerun extractors using fixed singleton roots and fresh memory reads."""
    state = ExtractionRunState()
    pass_num = 1
    while True:
        if not mem.is_alive():
            logger.info("Target process has exited; stopping live reload")
            return

        elapsed = _run_live_extractor_pass(
                mem, resolver, singleton_index, roots, state, pass_num, "Reload", logger.info)
        logger.info("Reload extractor pass %d completed in %.2fs", pass_num, elapsed)

        try:
            response = input("Press Enter to rescan, type d for daemon mode, or type q then Enter to exit...")
        except EOFError:
            return

        response = response.strip().lower()
        if response in {"q", "quit", "exit"}:
            return
        if response in {"d", "daemon"}:
            _run_live_daemon_loop(mem, resolver, singleton_index, roots, poll_interval, state)
            return

        pass_num += 1


def _run_live_daemon_loop(
        mem: MemoryReader,
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots,
        poll_interval: float,
        state: Optional[ExtractionRunState] = None) -> None:
    """Run extractors repeatedly without prompting until the target exits."""
    state = state or ExtractionRunState()
    pass_num = 1
    poll_interval = max(0.1, float(poll_interval))
    logger.info("Daemon mode started; polling every %.2fs", poll_interval)
    while mem.is_alive():
        elapsed = _run_live_extractor_pass(
                mem, resolver, singleton_index, roots, state, pass_num, "Daemon", logger.debug)
        logger.debug("Daemon extractor pass %d completed in %.2fs", pass_num, elapsed)

        pass_num += 1
        try:
            time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Stopping daemon mode")
            return

    logger.info("Target process has exited; stopping daemon mode")


def main() -> None:
    args = _parse_args()
    configure_logging(args.verbose)
    t_start = time.perf_counter()

    logger.info("umadump %s", CURRENT_VERSION)
    if not args.no_update_check:
        notify_if_update_available(CURRENT_VERSION)

    setup = setup_memory(args.minidump, args.metadata_path)
    logger.info("Metadata path: %s", setup.metadata_path)

    with setup.mem:
        try:
            try:
                resolver = build_resolver(setup.mem, setup.metadata_path)
            finally:
                setup.mem.clear_cache()
                gc.collect()

            if args.validate_only:
                return

            _prepare_memory_pass(setup.mem)
            try:
                logger.info("Scanning %d generic class instantiations...", resolver.meta_reg.genericClassesCount)
                singleton_index = _build_singleton_generic_index(resolver.meta_reg)
                roots = _init_singleton_roots()
                _refresh_singleton_roots(resolver, singleton_index, roots)
            finally:
                _finish_memory_pass(setup.mem)

            rerun_mode = args.rerun_mode or ("once" if args.minidump else "prompt")
            if rerun_mode == "daemon":
                _run_live_daemon_loop(setup.mem, resolver, singleton_index, roots, args.poll_interval)
            elif rerun_mode == "prompt":
                _run_live_reload_loop(setup.mem, resolver, singleton_index, roots, args.poll_interval)
            else:
                _prepare_memory_pass(setup.mem)
                try:
                    elapsed = _dump_from_singleton_roots(roots)
                finally:
                    _finish_memory_pass(setup.mem)
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
