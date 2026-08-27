from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ctypes_utils import C_Ptr
from game_structs.enums import IdleSingleModePlayingState
from game_structs.idle_single_mode import ObscuredIdleSingleModeProgressLogInfoObject, WorkIdleSingleModeDataObject
from game_structs.single_mode import SingleModeCharaObject, WorkSingleModeDataObject
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.common import timestamp_to_str
from json_encoders.idle_single_mode import decode_idle_single_mode
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, pointer_fingerprint, safe_filename_component


@dataclass(frozen=True)
class IdleSingleModeOutput:
    key: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class IdleSingleModeExtractionData:
    state: IdleSingleModePlayingState
    chara_info: C_Ptr[SingleModeCharaObject]
    start_time: int
    end_time: int
    progress_log_info: C_Ptr[ObscuredIdleSingleModeProgressLogInfoObject]
    finalized_chara_info: C_Ptr[SingleModeCharaObject]

    def fingerprint(self) -> ExtractorFingerprint:
        if self.chara_info:
            _ = self.chara_info.contents.fields
        if self.progress_log_info:
            _ = self.progress_log_info.contents.fields
        if self.finalized_chara_info:
            _ = self.finalized_chara_info.contents.fields
        return (
            "idle_single_mode",
            self.state,
            pointer_fingerprint(self.chara_info),
            self.start_time,
            self.end_time,
            pointer_fingerprint(self.progress_log_info),
            pointer_fingerprint(self.finalized_chara_info),
        )


def _resolve_career_data_ptr(wdm: WorkDataManagerObject) -> Optional[C_Ptr[WorkSingleModeDataObject]]:
    career_data_ptr = wdm.fields.singleMode
    if not career_data_ptr:
        logger.warning("WorkDataManager.singleMode is null")
        return None

    f = career_data_ptr.contents.fields
    if f.totalTurnNum == 0:
        return None

    return career_data_ptr


def _resolve_idle_career_data_ptr(wdm: WorkDataManagerObject) -> Optional[C_Ptr[WorkIdleSingleModeDataObject]]:
    idle_career_data_ptr = wdm.fields.idleSingleModeData
    if not idle_career_data_ptr:
        logger.warning("WorkDataManager.idleSingleModeData is null")
        return None

    f = idle_career_data_ptr.contents.fields
    if f.state.value == IdleSingleModePlayingState.None_:
        return None

    if not f.progressLogInfo:
        return None

    return idle_career_data_ptr


def resolve_idle_single_mode(wdm: WorkDataManagerObject) -> Optional[IdleSingleModeExtractionData]:
    if not (idle_career_data_ptr := _resolve_idle_career_data_ptr(wdm)):
        return None
    idle_career_data = idle_career_data_ptr.contents.fields

    if not (career_data_ptr := _resolve_career_data_ptr(wdm)):
        return None
    career_data = career_data_ptr.contents
    if not (race_start_result_info_data_ptr := career_data.fields.raceStartResultInfoData):
        return None
    race_start_result_info_data = race_start_result_info_data_ptr.contents

    # idle mode makes a confusing datapath reuse here - this retrieval is intentional
    if not (finalized_chara_info_ptr := race_start_result_info_data.fields.charaInfo):
        return None

    return IdleSingleModeExtractionData(
            state=IdleSingleModePlayingState(idle_career_data.state.value),
            chara_info=idle_career_data.charaInfo,
            start_time=idle_career_data.startTime,
            end_time=idle_career_data.endTime,
            progress_log_info=idle_career_data.progressLogInfo,
            finalized_chara_info=finalized_chara_info_ptr,
    )


def resolve_idle_single_mode_data(context: ExtractorContext) -> Optional[IdleSingleModeExtractionData]:
    return resolve_idle_single_mode(context.work_data_manager)


def extract_idle_single_mode(data: IdleSingleModeExtractionData) -> IdleSingleModeOutput:
    chara = data.finalized_chara_info.contents
    timestamp = timestamp_to_str(data.start_time)
    key = f"{chara.fields.single_mode_chara_id} {safe_filename_component(timestamp)} {chara.fields.card_id}"
    return IdleSingleModeOutput(key=key, payload=decode_idle_single_mode(data))


def idle_single_mode_output_key(output: IdleSingleModeOutput) -> str:
    return output.key
