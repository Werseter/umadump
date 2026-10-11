"""Extractor preflight, fingerprint verification, persistence, and per-run bookkeeping."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING, cast as type_cast

from logger import logger
from memory import TransientMemoryReadError
from schema_validation import RuntimeTypeMetadataHandleMismatchError, TransientRuntimeValidationError
from .common import ExtractorFingerprint, FingerprintableExtractionData

if TYPE_CHECKING:
    from main import Extractor


def write_json_file(name: str, output_path: Path, payload: Any) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pretty_json = json.dumps(payload, indent=2, ensure_ascii=False)
    output_path.write_text(pretty_json, encoding="utf-8")
    logger.info("%s: wrote JSON to %s", name, output_path)


def _write_multi_output_json(output_folder: Path, key: str, payload: Any) -> None:
    output_path = output_folder / f"{key}.json"
    write_json_file(f"{output_folder.name}[{key}]", output_path, payload)


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


def prepare_extractor_runs(
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


def run_extractor_runs(prepared_runs: tuple[PreparedExtractorRun, ...], state: Optional[ExtractionRunState]) -> None:
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
        write_json_file(extractor.name, extractor.output_path, payload)
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
