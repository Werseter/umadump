#!/usr/bin/env python3
"""Structured game-data extraction from live processes and full-memory minidumps."""
from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, cast as type_cast

from career_archive import CAREER_ARCHIVE_OUTPUT_FOLDER, write_career_archive_snapshot
from extractors.cards import extract_card_data, extract_support_cards, resolve_card_data, resolve_support_cards
from extractors.career import career_snapshot_output_key, extract_career_snapshot, resolve_career_snapshot_data
from extractors.common import ExtractorFingerprint, FingerprintableExtractionData
from extractors.friends import extract_friend_data, resolve_friend_data
from extractors.gallery import extract_event_gallery, resolve_event_gallery
from extractors.honors import extract_honor_list, resolve_honor_list
from extractors.idle_single_mode import (IdleSingleModeOutput, extract_idle_single_mode, idle_single_mode_output_key,
                                         resolve_idle_single_mode_data)
from extractors.race import (RaceReplayOutput, extract_race_info_replay, race_replay_output_key,
                             resolve_race_info_replay)
from extractors.talk_gallery import extract_talk_gallery, resolve_talk_gallery
from extractors.team_stadium import extract_team_stadium_replay, resolve_team_stadium_replay
from extractors.trained_chara import extract_trained_chara_data, resolve_trained_chara_data
from extractors.trophies import TrophyDataOutput, extract_trophy_data, resolve_trophy_data, trophy_data_output_key
from il2cpp_runtime import build_resolver, setup_memory
from il2cpp_utils import Il2CppResolutionManager
from logger import configure_logging, logger
from memory import MemoryReader, TransientMemoryReadError
from schema_validation import RuntimeTypeMetadataHandleMismatchError, TransientRuntimeValidationError
from singleton_roots import (ExtractionContext, ResolvedSingletonRoots, SingletonGenericClassMatch,
                             build_singleton_generic_index, init_singleton_roots, refresh_live_singleton_roots,
                             refresh_singleton_roots)
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


@dataclass(frozen=True)
class PreparedExtractorRun:
    """Resolved extractor input and fingerprint, retained for one memory pass."""

    extractor: Extractor[Any, Any, Any]
    extraction_data: FingerprintableExtractionData
    fingerprint: ExtractorFingerprint


@dataclass
class ExtractorPassSkips:
    """Routine skipped extractors, reported once after a completed pass."""

    unavailable: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    def log(self) -> None:
        groups = []
        if self.unchanged:
            groups.append(f"unchanged=[{', '.join(self.unchanged)}]")
        if self.unavailable:
            groups.append(f"unavailable=[{', '.join(self.unavailable)}]")
        if groups:
            logger.debug("Extractor pass skips: %s", "; ".join(groups))


METADATA_HANDLE_MISMATCH_QUARANTINE_THRESHOLD = 3


@dataclass
class ExtractionRunState:
    fingerprints: dict[str, ExtractorFingerprint] = field(default_factory=dict)
    metadata_handle_mismatch_streaks: dict[str, int] = field(default_factory=dict)

    def note_metadata_handle_mismatch(self, name: str) -> int:
        failures = self.metadata_handle_mismatch_streaks.get(name, 0) + 1
        self.metadata_handle_mismatch_streaks[name] = failures
        return failures

    def clear_metadata_handle_mismatch(self, name: str) -> None:
        self.metadata_handle_mismatch_streaks.pop(name, None)

    def should_run(self, name: str, fingerprint: ExtractorFingerprint) -> bool:
        return self.fingerprints.get(name) != fingerprint

    def record(self, name: str, fingerprint: ExtractorFingerprint) -> None:
        self.fingerprints[name] = fingerprint


def _prepare_extractor_runs(
        extractors: tuple[Extractor[Any, Any, Any], ...],
        data: Any,
        state: Optional[ExtractionRunState],
        skips: Optional[ExtractorPassSkips] = None) -> tuple[PreparedExtractorRun, ...]:
    """Prepare one pass; transients defer it while persistent type mismatches are isolated."""
    prepared_runs: list[PreparedExtractorRun] = []
    for extractor in extractors:
        try:
            maybe_extraction_data = extractor.resolve(data)
            if maybe_extraction_data is None:
                if state is not None:
                    state.clear_metadata_handle_mismatch(extractor.name)
                if skips is not None:
                    skips.unavailable.append(extractor.name)
                continue
            extraction_data = type_cast(FingerprintableExtractionData, maybe_extraction_data)
            fingerprint = extraction_data.fingerprint()
        except RuntimeTypeMetadataHandleMismatchError as exc:
            failures = state.note_metadata_handle_mismatch(extractor.name) if state is not None else 1
            if failures < METADATA_HANDLE_MISMATCH_QUARANTINE_THRESHOLD:
                logger.warning(
                        "%s: type metadata mismatch (%d/%d); extractor pass deferred: %s",
                        extractor.name, failures, METADATA_HANDLE_MISMATCH_QUARANTINE_THRESHOLD, exc)
                return ()
            if failures == METADATA_HANDLE_MISMATCH_QUARANTINE_THRESHOLD:
                logger.error(
                        "%s: type metadata mismatch persisted across %d prechecks; "
                        "quarantining extractor until it recovers: %s",
                        extractor.name, METADATA_HANDLE_MISMATCH_QUARANTINE_THRESHOLD, exc)
            else:
                logger.debug("%s: quarantined type metadata mismatch persists: %s", extractor.name, exc)
            continue
        except (TransientMemoryReadError, TransientRuntimeValidationError) as exc:
            logger.warning("%s: transient memory state; extractor pass deferred: %s", extractor.name, exc)
            return ()
        except Exception:
            logger.exception("Error preparing extractor %s", extractor.name)
            continue
        if state is not None:
            state.clear_metadata_handle_mismatch(extractor.name)
        if _skip_unchanged_extractor(extractor.name, fingerprint, state, skips):
            continue
        prepared_runs.append(PreparedExtractorRun(extractor, extraction_data, fingerprint))
    return tuple(prepared_runs)


def _prepared_fingerprint_is_current(prepared: PreparedExtractorRun) -> bool:
    """Reject a payload if its live source changed after the access precheck."""
    try:
        current_fingerprint = prepared.extraction_data.fingerprint()
    except RuntimeTypeMetadataHandleMismatchError as exc:
        logger.warning("%s: post-decode type metadata mismatch; extraction skipped: %s",
                       prepared.extractor.name, exc)
        return False
    except (TransientMemoryReadError, TransientRuntimeValidationError) as exc:
        logger.debug("%s: post-decode fingerprint check deferred: %s", prepared.extractor.name, exc)
        return False
    except Exception:
        logger.exception("Error verifying extractor %s fingerprint", prepared.extractor.name)
        return False
    if current_fingerprint == prepared.fingerprint:
        return True
    logger.debug("%s: input changed after access precheck; extraction deferred", prepared.extractor.name)
    return False


def _run_extractor_runs(prepared_runs: tuple[PreparedExtractorRun, ...], state: Optional[ExtractionRunState]) -> None:
    """Decode and persist every prepared run."""
    for prepared in prepared_runs:
        _run_extractor_run(prepared, state)


def _run_extractor_run(prepared: PreparedExtractorRun, state: Optional[ExtractionRunState]) -> None:
    """Decode, validate, and persist one already-prepared extractor run."""
    extractor = prepared.extractor
    try:
        logger.info("Running extractor: %s", extractor.name)
        payload = extractor.extract(prepared.extraction_data)
        if not _prepared_fingerprint_is_current(prepared):
            return
        _write_extractor_payload(extractor, payload)
        if state is not None:
            state.record(extractor.name, prepared.fingerprint)
    except RuntimeTypeMetadataHandleMismatchError as exc:
        logger.warning("%s: type metadata mismatch; extraction skipped: %s", extractor.name, exc)
    except (TransientMemoryReadError, TransientRuntimeValidationError) as exc:
        # Pointers below the precheck boundary can still change before decode.
        logger.warning("%s: transient memory state; extraction skipped: %s", extractor.name, exc)
    except Exception:
        logger.exception("Error in extractor %s", extractor.name)


def _skip_unchanged_extractor(
        name: str,
        fingerprint: ExtractorFingerprint,
        state: Optional[ExtractionRunState],
        skips: Optional[ExtractorPassSkips] = None) -> bool:
    if state is None or state.should_run(name, fingerprint):
        return False
    if skips is not None:
        skips.unchanged.append(name)
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


def _write_race_replay_json(output_folder: Path, key: str, replay: RaceReplayOutput) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, replay.payload)


def _write_idle_single_mode_json(output_folder: Path, key: str, ism: IdleSingleModeOutput) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, ism.payload)


def _write_trophy_data_json(output_folder: Path, key: str, trophies: TrophyDataOutput) -> None:
    _write_json_file(key, output_folder / f"{key}.json", trophies.payload)


EXTRACTORS: tuple[Extractor[Any, Any, Any], ...] = (
    Extractor(
            name="support_cards",
            output_path=Path("support_card_data.json"),
            resolve=resolve_support_cards,
            extract=extract_support_cards,
    ),
    Extractor(
            name="trained_chara_data",
            output_path=Path("trained_chara_data.json"),
            resolve=resolve_trained_chara_data,
            extract=extract_trained_chara_data,
    ),
    Extractor(
            name="card_data",
            output_path=Path("card_data.json"),
            resolve=resolve_card_data,
            extract=extract_card_data,
    ),
    Extractor(
            name="friend_data",
            output_path=Path("friend_data.json"),
            resolve=resolve_friend_data,
            extract=extract_friend_data,
    ),
    Extractor(
            name="honor_data",
            output_path=Path("honor_data.json"),
            resolve=resolve_honor_list,
            extract=extract_honor_list,
    ),
    Extractor(
            name="trophy_data",
            output_folder=Path("."),
            key_fn=trophy_data_output_key,
            writer=_write_trophy_data_json,
            resolve=resolve_trophy_data,
            extract=extract_trophy_data,
    ),
    Extractor(
            name="event_gallery_data",
            output_path=Path("event_data.json"),
            resolve=resolve_event_gallery,
            extract=extract_event_gallery,
    ),
    Extractor(
            name="talk_gallery_data",
            output_path=Path("talk_gallery_data.json"),
            resolve=resolve_talk_gallery,
            extract=extract_talk_gallery,
    ),
    Extractor(
            name="team_stadium_replay",
            output_folder=Path("race_replays"),
            resolve=resolve_team_stadium_replay,
            extract=extract_team_stadium_replay,
            key_fn=race_replay_output_key,
            writer=_write_race_replay_json,
    ),
    Extractor(
            name="race_info_replay",
            output_folder=Path("race_replays"),
            resolve=resolve_race_info_replay,
            extract=extract_race_info_replay,
            key_fn=race_replay_output_key,
            writer=_write_race_replay_json,
    ),
    Extractor(
            name="career_data",
            output_folder=CAREER_ARCHIVE_OUTPUT_FOLDER,
            resolve=resolve_career_snapshot_data,
            extract=extract_career_snapshot,
            key_fn=career_snapshot_output_key,
            writer=write_career_archive_snapshot,
    ),
    Extractor(
            name="idle_single_mode",
            output_folder=Path("idle_single_mode"),
            resolve=resolve_idle_single_mode_data,
            extract=extract_idle_single_mode,
            key_fn=idle_single_mode_output_key,
            writer=_write_idle_single_mode_json,
    ),
)


def _dump_from_singleton_roots(
        roots: ResolvedSingletonRoots,
        state: Optional[ExtractionRunState] = None) -> float:
    """Run all extractors from already-resolved singleton roots and return elapsed seconds."""
    t_start = time.perf_counter()
    ctx = ExtractionContext(roots)
    skips = ExtractorPassSkips()
    prepared_runs = _prepare_extractor_runs(EXTRACTORS, ctx, state, skips)
    _run_extractor_runs(prepared_runs, state)
    skips.log()
    return time.perf_counter() - t_start


def _prepare_memory_pass(mem: MemoryReader) -> None:
    mem.clear_cache()


def _finish_memory_pass(mem: MemoryReader) -> None:
    mem.clear_cache()
    gc.collect()


def _run_extractor_pass(
        mem: MemoryReader,
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots,
        state: ExtractionRunState) -> float:
    _prepare_memory_pass(mem)
    try:
        refresh_live_singleton_roots(resolver, singleton_index, roots)
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

        elapsed = _run_extractor_pass(mem, resolver, singleton_index, roots, state)
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
        maybe_state: Optional[ExtractionRunState] = None) -> None:
    """Run extractors repeatedly without prompting until the target exits."""
    state = maybe_state or ExtractionRunState()
    pass_num = 1
    poll_interval = max(0.1, float(poll_interval))
    logger.info("Daemon mode started; polling every %.2fs", poll_interval)
    while mem.is_alive():
        elapsed = _run_extractor_pass(mem, resolver, singleton_index, roots, state)
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
                singleton_index = build_singleton_generic_index(resolver.meta_reg)
                roots = init_singleton_roots()
                refresh_singleton_roots(resolver, singleton_index, roots)
            finally:
                _finish_memory_pass(setup.mem)

            rerun_mode = args.rerun_mode or ("once" if args.minidump else "prompt")
            if rerun_mode == "daemon":
                _run_live_daemon_loop(setup.mem, resolver, singleton_index, roots, args.poll_interval)
            elif rerun_mode == "prompt":
                _run_live_reload_loop(setup.mem, resolver, singleton_index, roots, args.poll_interval)
            else:
                elapsed = _run_extractor_pass(setup.mem, resolver, singleton_index, roots, ExtractionRunState())
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
