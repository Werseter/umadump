from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ctypes_utils import C_Ptr
from game_structs.enums import IdleSingleModePlayingState, SingleModeState
from game_structs.idle_single_mode import ObscuredIdleSingleModeProgressLogInfoObject, WorkIdleSingleModeDataObject
from game_structs.single_mode import SingleModeCharaObject, WorkSingleModeDataObject
from game_structs.trained_chara import TrainedCharaDataObject
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.common import timestamp_to_str
from json_encoders.idle_single_mode import decode_idle_single_mode
from logger import logger
from .common import (ExtractorContext, ExtractorFingerprint, safe_filename_component,
                     validated_object_pointer_fingerprint)
from .trained_chara import resolve_trained_chara_extraction_data


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
    finalized_veteran: C_Ptr[TrainedCharaDataObject] | None = None

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "idle_single_mode",
            self.state,
            validated_object_pointer_fingerprint(self.chara_info),
            self.start_time,
            self.end_time,
            validated_object_pointer_fingerprint(self.progress_log_info),
            validated_object_pointer_fingerprint(self.finalized_chara_info),
            validated_object_pointer_fingerprint(self.finalized_veteran) if self.finalized_veteran else ("ptr", 0),
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


def _retrieve_finalized_veteran(wdm: WorkDataManagerObject,
                                chara_info: SingleModeCharaObject) -> Optional[C_Ptr[TrainedCharaDataObject]]:
    # NOTE: The fans are a tentative identity member but can't find a better match
    trained_chara_data = resolve_trained_chara_extraction_data(wdm)
    if trained_chara_data is not None and len(trained_chara_data.entries) > 0:
        if last_veteran_ptr := trained_chara_data.entries.span()[trained_chara_data.entries.fields.count - 1].value:
            last_veteran = last_veteran_ptr.contents.fields
            last_veteran_identity = {
                'card_id': last_veteran.cardId.value,
                'scenario_id': last_veteran.scenarioId.value,
                'fans': last_veteran.fans.value,
            }
            chara_info_identity = {
                'card_id': chara_info.fields.card_id,
                'scenario_id': chara_info.fields.scenario_id,
                'fans': chara_info.fields.fans,
            }
            if last_veteran_identity == chara_info_identity:
                return last_veteran_ptr
    return None


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

    finalized_veteran: C_Ptr[TrainedCharaDataObject] | None = None
    if career_data.fields.state.value == SingleModeState.FinishComplete:
        finalized_veteran = _retrieve_finalized_veteran(wdm, finalized_chara_info_ptr.contents)

    return IdleSingleModeExtractionData(
            state=IdleSingleModePlayingState(idle_career_data.state.value),
            chara_info=idle_career_data.charaInfo,
            start_time=idle_career_data.startTime,
            end_time=idle_career_data.endTime,
            progress_log_info=idle_career_data.progressLogInfo,
            finalized_chara_info=finalized_chara_info_ptr,
            finalized_veteran=finalized_veteran,
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
