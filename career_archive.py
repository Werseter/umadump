from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Buffer
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING

from logger import logger
from update_check import CURRENT_VERSION

if TYPE_CHECKING:
    from extractors.career import CareerDataExtractionData

type CareerArchiveIdentity = dict[str, int | str]

CAREER_ARCHIVE_OUTPUT_FOLDER = Path("career_data")
_TURN_SNAPSHOT_FILE_RE = re.compile(r"turn_(?P<turn>\d+)(?:_(?P<revision>\d+))?\.json$")


@dataclass(frozen=True)
class CareerArchiveSnapshot:
    """One immutable TurnStart observation."""

    key: str
    turn: int
    identity: CareerArchiveIdentity
    payload: dict[str, Any]


def _write_json_file(name: str, output_path: Path, payload: Any) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pretty_json = json.dumps(payload, indent=2, ensure_ascii=False)
    output_path.write_text(pretty_json, encoding="utf-8")
    logger.info("%s: wrote JSON to %s", name, output_path)


def career_archive_identity(data: CareerDataExtractionData) -> CareerArchiveIdentity:
    """Extract the persistent run identity without decoding a turn payload."""

    chara = data.career.fields.character.contents.fields
    identity: CareerArchiveIdentity = {
        "single_mode_chara_id": int(chara.id.value),
        "card_id": int(chara.cardId.value),
        "scenario_id": int(chara.scenarioId.value),
        "route_id": int(chara.routeId.value),
        "start_time": data.start_time,
    }
    if not identity["start_time"]:
        identity["fallback_career_pointer_address"] = f"0x{data.career_ptr.address:X}"
    return identity


def _career_archive_key(identity: CareerArchiveIdentity, *, fallback_address: int) -> str:
    """Build a readable path-safe directory name from a persistent identity."""

    start_time = str(identity["start_time"])
    safe_start_time = re.sub(r"[^A-Za-z0-9]+", "_", start_time).strip("_")
    if not safe_start_time:
        safe_start_time = f"unknown_start_{fallback_address:X}"
        logger.warning("Career start_time is unavailable; using archive fallback %s", safe_start_time)
    canonical_json = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    buffer: Buffer = canonical_json.encode("utf-8")
    identity_hash = hashlib.sha256(buffer).hexdigest()[:10]
    return (f"{safe_start_time}--smc-{identity['single_mode_chara_id']}--card-{identity['card_id']}"
            f"--scenario-{identity['scenario_id']}--{identity_hash}")


def career_archive_descriptor(data: CareerDataExtractionData) -> tuple[str, CareerArchiveIdentity]:
    identity = career_archive_identity(data)
    return _career_archive_key(identity, fallback_address=data.career_ptr.address), identity


def _career_payload_hash(payload: Any) -> str:
    """Hash semantic JSON content independently of pretty-print ordering."""

    canonical_json = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    buffer: Buffer = canonical_json.encode("utf-8")
    return hashlib.sha256(buffer).hexdigest()


def _career_payload_matches(output_path: Path, expected_hash: str) -> bool:
    try:
        payload = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return _career_payload_hash(payload) == expected_hash


def _career_manifest(identity: CareerArchiveIdentity) -> dict[str, Any]:
    """Describe the archive without duplicating API response fields."""

    return {
        "archive_type": "umadump-career",
        "created_utc": datetime.now(UTC).isoformat(),
        "dumper_version": CURRENT_VERSION,
        "identity": identity,
        "snapshot_phase": "turn_start",
        "snapshot_file_pattern": "turns/turn_{turn:03d}_{revision:03d}.json",
        "payload_format": "single_mode_load_response.data",
    }


def load_career_manifest(career_folder: Path, expected_identity: CareerArchiveIdentity) -> dict[str, Any]:
    """Load an archive manifest and reject identity collisions without migration."""

    manifest_path = career_folder / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError(f"Career archive manifest is missing: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Career archive manifest is unreadable: {manifest_path}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError(f"Career archive identity collision: {career_folder}")
    archive_type = manifest.get("archive_type")
    identity = manifest.get("identity")
    if archive_type != "umadump-career" or identity != expected_identity:
        raise RuntimeError(f"Career archive identity collision: {career_folder}")
    return manifest


def ensure_career_manifest(career_folder: Path, identity: CareerArchiveIdentity) -> dict[str, Any]:
    """Create an archive manifest once and never rewrite existing evidence."""

    manifest_path = career_folder / "manifest.json"
    if manifest_path.exists():
        return load_career_manifest(career_folder, identity)
    manifest = _career_manifest(identity)
    _write_json_file("career archive manifest", manifest_path, manifest)
    return manifest


def _write_immutable_career_payload(archive_key: str, label: str, output_path: Path, payload: dict[str, Any]) -> None:
    """Write first-seen evidence and retain it if a later view conflicts."""

    payload_hash = _career_payload_hash(payload)
    if output_path.exists():
        if _career_payload_matches(output_path, payload_hash):
            logger.debug("career_data: %s is unchanged; retaining %s", label, output_path)
        else:
            logger.warning("career_data: %s changed after its first capture; retaining %s", label, output_path)
        return
    _write_json_file(f"career_data[{archive_key}] {label}", output_path, payload)


def _turn_snapshot_paths(turns_folder: Path, turn: int) -> list[tuple[int, Path]]:
    """Return existing snapshots for one turn, ordered by their observation revision."""

    if not turns_folder.is_dir():
        return []
    snapshots: list[tuple[int, Path]] = []
    for output_path in turns_folder.iterdir():
        if not output_path.is_file():
            continue
        match = _TURN_SNAPSHOT_FILE_RE.fullmatch(output_path.name)
        if match is None or int(match["turn"]) != turn:
            continue
        snapshots.append((int(match["revision"] or 0), output_path))
    return sorted(snapshots)


def _next_turn_snapshot_path(turns_folder: Path, turn: int, payload: dict[str, Any]) -> Path | None:
    """Retain a duplicate or allocate the next immutable same-turn revision."""

    snapshots = _turn_snapshot_paths(turns_folder, turn)
    if not snapshots:
        return turns_folder / f"turn_{turn:03d}_000.json"

    latest_revision, latest_path = snapshots[-1]
    if _career_payload_matches(latest_path, _career_payload_hash(payload)):
        logger.debug("career_data: turn %d revision %d is unchanged; retaining %s", turn, latest_revision, latest_path)
        return None

    revision = latest_revision + 1
    output_path = turns_folder / f"turn_{turn:03d}_{revision:03d}.json"
    logger.debug("career_data: turn %d changed after revision %d; writing %s", turn, latest_revision, output_path)
    return output_path


def write_career_archive_snapshot(output_folder: Path, key: str, snapshot: CareerArchiveSnapshot) -> None:
    """Persist a TurnStart observation without overwriting prior evidence."""

    career_folder = output_folder / key
    ensure_career_manifest(career_folder, snapshot.identity)
    output_path = _next_turn_snapshot_path(career_folder / "turns", snapshot.turn, snapshot.payload)
    if output_path is None:
        return

    _write_immutable_career_payload(key, f"turn {snapshot.turn}", output_path, snapshot.payload)
