"""Reconcile the bounded game log once, then derive dialogue and event views."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from game_structs.enums import SingleModeLogGroupType, SingleModePlayingState, TrainingCommandId
from logger import logger


@dataclass(frozen=True)
class CareerLogEntry:
    group_address: int
    substance_address: int
    group: dict[str, Any]
    substance: dict[str, Any] | None

    @property
    def source(self) -> tuple[int, int]:
        return self.group_address, self.substance_address


@dataclass(frozen=True)
class CareerLogObservation:
    pool_address: int
    turn: int
    playing_state: int
    cursor: dict[str, Any]
    entries: tuple[CareerLogEntry, ...]


@dataclass
class CareerLogState:
    records: list[dict[str, Any]] = field(default_factory=list)
    window: list[int] = field(default_factory=list)
    sources: dict[tuple[int, int], int] = field(default_factory=dict)
    pool_address: int = 0
    restarting: bool = True
    cursor: dict[str, Any] = field(default_factory=dict)


def _record_timing(record: dict[str, Any]) -> dict[str, Any]:
    """Project the observation timing retained by a log record."""
    if record.get("preexisting", False):
        return {"preexisting": True}
    return {
        "turn": record["turn"],
        "playing_state": record["playing_state"],
    }


def _load_log(path: Path) -> CareerLogState:
    if not path.exists():
        return CareerLogState()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("archive_type") != "umadump-career-rolling-log" or payload.get("format_version") != 1:
        raise ValueError(f"Unrecognized career log: {path}")
    records, window = payload["entries"], payload["active_window"]
    if not isinstance(records, list) or not isinstance(window, list):
        raise ValueError(f"Invalid career log records/window: {path}")
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict) or record.get("sequence") != index:
            raise ValueError(f"Invalid career log sequence: {path}")
    if any(type(index) is not int or not 1 <= index <= len(records) for index in window):
        raise ValueError(f"Invalid career log window: {path}")
    return CareerLogState(records=records, window=window, cursor=payload.get("cursor", {}))


def _same_payload(record: dict[str, Any], entry: CareerLogEntry) -> bool:
    return bool(record["group"] == entry.group and record["substance"] == entry.substance)


def _restart_overlap(state: CareerLogState, entries: tuple[CareerLogEntry, ...]) -> list[int]:
    """Only reuse a substantial exact suffix/prefix after losing source identities."""
    for count in range(min(len(state.window), len(entries)), 2, -1):
        suffix = state.window[-count:]
        if all(_same_payload(state.records[index - 1], entry) for index, entry in zip(suffix, entries[:count])):
            signatures = {json.dumps(state.records[index - 1]["substance"], sort_keys=True) for index in suffix}
            if len(signatures) >= 3:
                return suffix
    return []


def reconcile_career_log(previous: CareerLogState, observation: CareerLogObservation) -> CareerLogState:
    """Source identity wins during a run; repeated text at a new source stays repeated.

    Groups always have a heading record, including before their first substance.
    Only the previous tail substance may change in place (AddLog can merge text).
    Previously retained groups have no trustworthy historical turn attribution.
    """
    entries = observation.entries
    same_pool = previous.pool_address == observation.pool_address and not previous.restarting
    sources = previous.sources if same_pool else {}
    overlap = _restart_overlap(previous, entries) if previous.restarting else []
    state = CareerLogState(records=list(previous.records), pool_address=observation.pool_address,
                           restarting=False, cursor=dict(observation.cursor))
    group_sequence = 0
    tail = previous.window[-1] if previous.window else 0
    for position, entry in enumerate(entries):
        sequence = sources.get(entry.source, 0)
        if sequence and previous.records[sequence - 1]["substance"] != entry.substance:
            if sequence != tail and entry.substance is not None:
                sequence = 0
        if not sequence and position < len(overlap):
            sequence = overlap[position]
        if sequence:
            old = state.records[sequence - 1]
            group_sequence = old.get("event_sequence", sequence) if entry.substance is None else group_sequence
            if not _same_payload(old, entry):
                state.records[sequence - 1] = {**old, "group": entry.group, "substance": entry.substance}
        else:
            sequence = len(state.records) + 1
            if entry.substance is None:
                group_sequence = sequence
            state.records.append({
                "sequence": sequence,
                "event_sequence": group_sequence,
                **({"preexisting": True} if previous.restarting else {
                    "turn": observation.turn,
                    "playing_state": SingleModePlayingState(observation.playing_state).name,
                }),
                "group": entry.group,
                "substance": entry.substance,
            })
        state.sources[entry.source] = sequence
        state.window.append(sequence)
    current_index = state.cursor.pop("current_group_window_index", None)
    state.cursor["current_event_sequence"] = (
        state.window[current_index] if current_index is not None and 0 <= current_index < len(state.window) else None
    )
    return state


def _event_heading(group: dict[str, Any]) -> dict[str, Any]:
    """Keep useful action metadata; the complete runtime group remains in log.json."""
    kind = group["type"]["name"]
    title = group["event_title"]
    if not title:
        title = kind.removesuffix("Event")
        if group["type"]["value"] == SingleModeLogGroupType.TrainingEvent:
            command = TrainingCommandId(group["training_kind"])
            title = f"Training: {command.name} (level {group['training_level']})"
    details = {key: group[key] for key in ("training_kind", "training_level", "support_card_id", "dress_id")
               if group.get(key, -1) > 0}
    return {"kind": kind, "title": title, "details": details}


def career_events_payload(state: CareerLogState) -> dict[str, Any]:
    """A projection of reconciled headings and result effects, not another matcher."""
    events: dict[int, dict[str, Any]] = {}
    for record in state.records:
        event_sequence = record.get("event_sequence", record["sequence"])
        event = events.setdefault(event_sequence, {
            "sequence": event_sequence,
            **_record_timing(record),
            **_event_heading(record["group"]),
            "effects": [],
        })
        substance = record["substance"]
        if substance is not None and substance.get("is_result"):
            text = re.sub(r"</?color(?:=[^>]+)?>", "", substance["text"])
            event["effects"].append({"sequence": record["sequence"], "text": text,
                                     **_record_timing(record)})
    return {
        "archive_type": "umadump-career-events",
        "source": "UI log groups; sequence identifies an occurrence, not an API event ID",
        "cursor": state.cursor,
        "events": list(events.values()),
    }


def _replace_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


class CareerLogManager:
    """Keep process-local pointer identities out of persistent archive records."""

    _states: dict[Path, CareerLogState] = {}

    @classmethod
    def write(cls, folder: Path, observation: CareerLogObservation) -> None:
        path = folder / "log.json"
        previous = cls._states.get(folder)
        if previous is None:
            previous = _load_log(path)
        state = reconcile_career_log(previous, observation)
        changed = (state.records != previous.records or state.window != previous.window
                   or state.cursor != previous.cursor)
        if changed or not path.exists() or not (folder / "events.json").exists():
            payload = {
                "format_version": 1,
                "archive_type": "umadump-career-rolling-log",
                "source": "WorkSingleModeData.groupLogPool",
                "updated_utc": datetime.now(UTC).isoformat(),
                "entries": state.records,
                "active_window": state.window,
                "cursor": state.cursor,
            }
            # Commit the canonical log last. A failed companion write must not make
            # a retry reload the newly persisted short window as an unknown restart.
            _replace_json(folder / "events.json", career_events_payload(state))
            _replace_json(path, payload)
            logger.info("career_data[%s]: updated log.json and events.json", folder.name)
        cls._states[folder] = state
