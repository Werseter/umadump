#!/usr/bin/env python3
"""Structured game-data extraction from live processes and full-memory minidumps."""
from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from career_archive import CAREER_ARCHIVE_OUTPUT_FOLDER, write_career_archive_snapshot
from extractors.cards import extract_card_data, extract_support_cards, resolve_card_data, resolve_support_cards
from extractors.career import career_snapshot_output_key, extract_career_snapshot, resolve_career_snapshot_data
from extractors.common import FingerprintableExtractionData
from extractors.friends import extract_friend_data, resolve_friend_data
from extractors.gacha import extract_gacha_data, resolve_gacha_data
from extractors.gallery import extract_event_gallery, resolve_event_gallery
from extractors.honors import extract_honor_list, resolve_honor_list
from extractors.idle_single_mode import (IdleSingleModeOutput, extract_idle_single_mode, idle_single_mode_output_key,
                                         resolve_idle_single_mode_data)
from extractors.race import (RaceReplayOutput, extract_race_info_replay, race_replay_output_key,
                             resolve_race_info_replay)
from extractors.runner import (ExtractionRunState, ExtractorPassSkips, prepare_extractor_runs, run_extractor_runs,
                               write_json_file)
from extractors.talk_gallery import extract_talk_gallery, resolve_talk_gallery
from extractors.team_stadium import extract_team_stadium_replay, resolve_team_stadium_replay
from extractors.trained_chara import extract_trained_chara_data, resolve_trained_chara_data
from extractors.trophies import TrophyDataOutput, extract_trophy_data, resolve_trophy_data, trophy_data_output_key
from gacha_archive import gacha_output_key, write_gacha_archive
from il2cpp_runtime import build_resolver, setup_memory
from il2cpp_utils import Il2CppResolutionManager
from logger import configure_logging, logger
from memory import MemoryReader
from singleton_roots import (ExtractionContext, ResolvedSingletonRoots, SingletonGenericIndex,
                             build_singleton_generic_index, refresh_live_singleton_roots, refresh_singleton_roots)
from update_check import CURRENT_VERSION, notify_if_update_available


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


def _write_race_replay_json(output_folder: Path, key: str, replay: RaceReplayOutput) -> None:
    output_path = output_folder / f"{key}.json"
    write_json_file(f"{output_folder.name}[{key}]", output_path, replay.payload)


def _write_idle_single_mode_json(output_folder: Path, key: str, ism: IdleSingleModeOutput) -> None:
    output_path = output_folder / f"{key}.json"
    write_json_file(f"{output_folder.name}[{key}]", output_path, ism.payload)


def _write_trophy_data_json(output_folder: Path, key: str, trophies: TrophyDataOutput) -> None:
    write_json_file(key, output_folder / f"{key}.json", trophies.payload)


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
    Extractor(
            name="gacha_data",
            output_folder=Path("gacha_history"),
            resolve=resolve_gacha_data,
            extract=extract_gacha_data,
            key_fn=gacha_output_key,
            writer=write_gacha_archive,
    ),
)


def _dump_from_singleton_roots(
        roots: ResolvedSingletonRoots,
        state: Optional[ExtractionRunState] = None) -> float:
    """Run all extractors from already-resolved singleton roots and return elapsed seconds."""
    t_start = time.perf_counter()
    ctx = ExtractionContext(roots)
    skips = ExtractorPassSkips()
    prepared_runs = prepare_extractor_runs(EXTRACTORS, ctx, state, skips)
    run_extractor_runs(prepared_runs, state)
    skips.log()
    return time.perf_counter() - t_start


def _clear_memory_cache(mem: MemoryReader) -> None:
    mem.clear_cache()


def _run_extractor_pass(
        mem: MemoryReader,
        resolver: Il2CppResolutionManager,
        singleton_index: SingletonGenericIndex,
        roots: ResolvedSingletonRoots,
        state: ExtractionRunState) -> float:
    _clear_memory_cache(mem)
    try:
        refresh_live_singleton_roots(resolver, singleton_index, roots)
        return _dump_from_singleton_roots(roots, state)
    finally:
        _clear_memory_cache(mem)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parse CLI flags for live/minidump mode and optional validation-only run."""

    parser = argparse.ArgumentParser(
            description="Resolve Gallop.WorkDataManager from a live process or an offline minidump")
    parser.add_argument("--version", action="version", version=f"%(prog)s {CURRENT_VERSION}")
    parser.add_argument("--minidump", help="Path to full-memory .dmp or .dmp.zst minidump (offline mode)")
    parser.add_argument("--metadata-path", help="global-metadata.dat path override")
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
        singleton_index: SingletonGenericIndex,
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
        singleton_index: SingletonGenericIndex,
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
    with setup.mem:
        try:
            try:
                resolver = build_resolver(setup.mem, setup.metadata_path)
            finally:
                setup.mem.clear_cache()

            if args.validate_only:
                return

            _clear_memory_cache(setup.mem)
            try:
                logger.info("Scanning %d generic class instantiations...", resolver.meta_reg.genericClassesCount)
                singleton_index = build_singleton_generic_index(resolver.meta_reg)
                roots = ResolvedSingletonRoots()
                refresh_singleton_roots(resolver, singleton_index, roots)
            finally:
                _clear_memory_cache(setup.mem)

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
