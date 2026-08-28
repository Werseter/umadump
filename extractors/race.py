from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from ctypes_utils import C_Ptr
from game_structs.race import RaceInfoObject, RaceManagerStaticFields
from json_encoders.race import decode_race_info
from logger import logger
from .common import (ExtractorContext, ExtractorFingerprint, safe_filename_component,
                     validated_object_pointer_fingerprint)


@dataclass(frozen=True)
class RaceReplayOutput:
    key: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class RaceInfoReplayExtractionData:
    race_info: C_Ptr[RaceInfoObject]
    race_type: int
    random_seed: int
    race_horse_trained_chara_pointers: tuple[tuple[int, int], ...]

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "race_info_replay",
            validated_object_pointer_fingerprint(self.race_info),
            self.race_type,
            self.random_seed,
            self.race_horse_trained_chara_pointers,
        )


def _race_horse_trained_chara_pointer_signature(race_info: RaceInfoObject) -> tuple[tuple[int, int], ...]:
    return tuple(
            (horse.address, horse.contents.fields.trainedCharaData.address) if horse else (0, 0)
            for horse in race_info.fields.raceHorse
    )


def resolve_race_info_replay_extraction_data(
        race_manager_static: RaceManagerStaticFields) -> Optional[RaceInfoReplayExtractionData]:
    if not race_manager_static.raceInfo:
        return None
    race_info = race_manager_static.raceInfo.contents
    f = race_info.fields
    if not f.simDataBase64.inner_ptr:
        logger.debug("RaceInfo replay data is not ready: simDataBase64 is null")
        return None
    race_horse_trained_chara_pointers = _race_horse_trained_chara_pointer_signature(race_info)
    return RaceInfoReplayExtractionData(
            race_info=race_manager_static.raceInfo,
            race_type=f.raceType,
            random_seed=f.randomSeed,
            race_horse_trained_chara_pointers=race_horse_trained_chara_pointers,
    )


def resolve_race_info_replay(context: ExtractorContext) -> Optional[RaceInfoReplayExtractionData]:
    race_manager_static = context.race_manager_static
    if race_manager_static is None:
        return None
    return resolve_race_info_replay_extraction_data(race_manager_static)


def _race_type_folder(race_type: object) -> str:
    return f"{re.sub(r'(?<!^)(?=[A-Z])', '_', str(race_type or 'Other')).lower()}_race"


def _race_info_replay_key(payload: dict[str, Any], winner: dict[str, Any]) -> str:
    folder = _race_type_folder(payload["raceType"])
    name = str(winner["charaName"]) or "Unknown"
    raw_time = float(winner["finishTimeRaw"])
    date_str = datetime.now().strftime("%Y%m%d")
    return f"{folder}/{safe_filename_component(name)}-{raw_time:.4f}s-{date_str}"


def extract_race_info_replay(data: RaceInfoReplayExtractionData) -> RaceReplayOutput:
    """Decode the current live RaceInfo replay."""

    payload = decode_race_info(data.race_info.contents)
    winner = next(horse for horse in payload["raceHorse"] if horse["finishOrder"] == 0)

    return RaceReplayOutput(key=_race_info_replay_key(payload, winner), payload=payload)


def race_replay_output_key(replay: RaceReplayOutput) -> str:
    return replay.key
