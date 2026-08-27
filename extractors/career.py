from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, TypeAlias

from career_archive import CareerArchiveSnapshot, career_archive_descriptor
from ctypes_utils import C_Ptr
from game_structs.collections import GenericDictionary, GenericList
from game_structs.enums import SingleModePlayingState, SingleModeScenarioId
from game_structs.single_mode import (WorkSingleModeChangeParameterInfoObject, WorkSingleModeCharaDataObject,
                                      WorkSingleModeCharaDataSuccessionFactorInfoObject, WorkSingleModeDataObject,
                                      WorkSingleModeDataParamsIncDecInfoDictionaryEntry,
                                      WorkSingleModeDataTurnInfoObject, WorkSingleModeHomeInfoObject,
                                      WorkSingleModeRaceDataObject, WorkSingleModeScenarioFreeObject,
                                      WorkSingleModeScenarioLiveObject, WorkSingleModeScenarioTeamRaceObject)
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.career import decode_career_data
from logger import logger
from .common import (ExtractorContext, ExtractorFingerprint, array_fingerprint, dictionary_pointer_fingerprint,
                     list_pointer_fingerprint, object_array_fingerprint, object_list_fingerprint,
                     object_pointer_fingerprint, pointer_fingerprint)

ParamDeltaDictPtr: TypeAlias = C_Ptr[GenericDictionary[WorkSingleModeDataParamsIncDecInfoDictionaryEntry]]
SuccessionFactorInfoObjectPtr: TypeAlias = C_Ptr[WorkSingleModeCharaDataSuccessionFactorInfoObject]
ChangeParameterInfoObjectPtr: TypeAlias = C_Ptr[WorkSingleModeChangeParameterInfoObject]
DataTurnInfoListPtr: TypeAlias = C_Ptr[GenericList[C_Ptr[WorkSingleModeDataTurnInfoObject]]]


def _parameter_delta_dictionary_fingerprint(dictionary_ptr: ParamDeltaDictPtr) -> ExtractorFingerprint:
    first_value: ExtractorFingerprint = "first", ("ptr", 0)
    if dictionary_ptr and (entry := dictionary_ptr.contents.first()) is not None:
        first_value = object_pointer_fingerprint("first", entry.value)
    return "parameter_deltas", dictionary_pointer_fingerprint(dictionary_ptr), first_value


def _career_succession_factor_fingerprint(value: SuccessionFactorInfoObjectPtr) -> ExtractorFingerprint:
    if not value:
        return "succession_factor", pointer_fingerprint(value)
    fields = value.contents.fields
    if fields.infoList and (first_info := fields.infoList.contents.first()) is not None and first_info:
        first_info_fields = first_info.contents.fields
        factor_ids_fingerprint = "factor_ids", list_pointer_fingerprint(first_info_fields.factorIdList)
    else:
        factor_ids_fingerprint = "factor_ids", ("list", 0, 0, 0)
    return (
        "succession_factor",
        pointer_fingerprint(value),
        object_list_fingerprint("factor_info", fields.infoList),
        factor_ids_fingerprint,
    )


def _career_lottery_program_fingerprint(value: C_Ptr[WorkSingleModeRaceDataObject]) -> ExtractorFingerprint:
    if not value:
        return "lottery_programs", pointer_fingerprint(value)
    lottery_program_data_dict = value.contents.fields.lotteryProgramDataDict
    if lottery_program_data_dict and (first_entry := lottery_program_data_dict.contents.first()) is not None:
        program_list_fingerprint = object_list_fingerprint("programs", first_entry.value)
    else:
        program_list_fingerprint = "programs", ("list", 0, 0, 0), ("first", ("ptr", 0))
    return (
        "lottery_programs",
        pointer_fingerprint(value),
        dictionary_pointer_fingerprint(lottery_program_data_dict),
        program_list_fingerprint,
    )


def _career_live_change_parameter_fingerprint(value: ChangeParameterInfoObjectPtr) -> ExtractorFingerprint:
    if not value:
        return "change_parameter", pointer_fingerprint(value)
    fields = value.contents.fields
    return (
        "change_parameter",
        pointer_fingerprint(value),
        object_pointer_fingerprint("performance", fields.performance),
        object_pointer_fingerprint("performance_max", fields.performanceMax),
        ("limit_performance", list_pointer_fingerprint(fields.limitPerformanceTypeList)),
    )


def _career_live_state_fingerprint(value: C_Ptr[WorkSingleModeScenarioLiveObject]) -> ExtractorFingerprint:
    if not value:
        return "scenario_live", pointer_fingerprint(value)
    fields = value.contents.fields
    return (
        "scenario_live",
        pointer_fingerprint(value),
        object_pointer_fingerprint("performance", fields.performance),
        object_pointer_fingerprint("performance_max", fields.performanceMax),
        ("next_music", array_fingerprint(fields.nextMusicIdArray)),
        ("total_music", array_fingerprint(fields.totalMusicIdArray)),
        ("effected_music", array_fingerprint(fields.currentLiveBonusMusicIdArray)),
        object_array_fingerprint("tree_squares", fields.treeSquareInfoArray),
        ("reservedTreeSquareId", fields.reservedTreeSquareId),
        object_array_fingerprint("training_bonus", fields.trainingBonusArray),
        object_list_fingerprint("live_evaluations", fields.evaluationInfoList),
        object_list_fingerprint("live_results", fields.liveResultList),
    )


def _career_team_state_fingerprint(value: C_Ptr[WorkSingleModeScenarioTeamRaceObject]) -> ExtractorFingerprint:
    if not value:
        return "scenario_team", pointer_fingerprint(value)
    fields = value.contents.fields
    return (
        "scenario_team",
        pointer_fingerprint(value),
        object_list_fingerprint("team_members", fields.teamMemberList),
        object_list_fingerprint("team_deck", fields.deckDataList),
    )


def _career_free_change_parameter_fingerprint(value: ChangeParameterInfoObjectPtr) -> ExtractorFingerprint:
    if not value:
        return "change_parameter", pointer_fingerprint(value)
    fields = value.contents.fields
    commands = fields.scenarioFreeCommandInfo
    if commands and (first_command := commands.contents.first()) is not None and first_command:
        first_command_fields = first_command.contents.fields
        command_parameter_deltas = object_array_fingerprint("command_parameter_deltas",
                                                            first_command_fields.params_inc_dec_info_array)
    else:
        command_parameter_deltas = "command_parameter_deltas", ("array", 0, 0), ("first", ("ptr", 0))
    return (
        "change_parameter",
        pointer_fingerprint(value),
        object_list_fingerprint("free_commands", commands),
        command_parameter_deltas,
    )


def _career_free_state_fingerprint(value: C_Ptr[WorkSingleModeScenarioFreeObject]) -> ExtractorFingerprint:
    if not value:
        return "scenario_free", pointer_fingerprint(value)
    fields = value.contents.fields
    npcs = fields.singleModeFreeTwinkleRaceNpcInfoList
    results = fields.singleModeTwikleRaceNpcResultList
    if npcs and (first_npc := npcs.contents.first()) is not None and first_npc:
        first_npc_fields = first_npc.contents.fields
        npc_skills_fingerprint = object_array_fingerprint("npc_skills", first_npc_fields.skillArray)
    else:
        npc_skills_fingerprint = "npc_skills", ("array", 0, 0), ("first", ("ptr", 0))
    if results and (first_result := results.contents.first()) is not None and first_result:
        first_result_fields = first_result.contents.fields
        npc_results_fingerprint = object_list_fingerprint("npc_results", first_result_fields.raceResultList)
    else:
        npc_results_fingerprint = "npc_results", ("list", 0, 0, 0), ("first", ("ptr", 0))
    return (
        "scenario_free",
        pointer_fingerprint(value),
        fields.coinNum.value,
        fields.gainedCoinNum.value,
        fields.shopId.value,
        fields.saleValue.value,
        fields.winPoints.value,
        fields.twinkleRaceRanking.value,
        fields.uncheckedEventAchievementId.value,
        object_array_fingerprint("user_items", fields.userItemInfoArray),
        object_array_fingerprint("shop_items", fields.pickUpItemInfoArray),
        object_array_fingerprint("item_effects", fields.singleModeFreeItemEffectArray),
        object_array_fingerprint("rival_races", fields.singleModeRivalRaceInfoArray),
        object_list_fingerprint("twinkle_npcs", npcs),
        npc_skills_fingerprint,
        object_list_fingerprint("twinkle_results", results),
        npc_results_fingerprint,
    )


def _career_scenario_fingerprint(career: WorkSingleModeDataObject,
                                 chara: WorkSingleModeCharaDataObject) -> ExtractorFingerprint:
    fields = career.fields
    chara_fields = chara.fields
    scenario_id = chara_fields.scenarioId.value
    if scenario_id == SingleModeScenarioId.URA:
        ura = chara_fields.workScenarioURA
        if not ura:
            return "scenario_ura", pointer_fingerprint(ura)
        return "scenario_ura", pointer_fingerprint(ura), ura.contents.fields.versusLevel.value
    if scenario_id == SingleModeScenarioId.TeamRace:
        return _career_team_state_fingerprint(chara_fields.teamRace)
    if scenario_id == SingleModeScenarioId.Live:
        return (
            "scenario_live",
            _career_live_change_parameter_fingerprint(fields.changeParameterInfo),
            _career_live_state_fingerprint(chara_fields.scenarioLive),
        )
    if scenario_id == SingleModeScenarioId.Free:
        return (
            "scenario_free",
            _career_free_change_parameter_fingerprint(fields.changeParameterInfo),
            _career_free_state_fingerprint(chara_fields.workScenarioFree),
        )
    return "scenario_unsupported", scenario_id


def _career_active_chara_collections_fingerprint(chara: WorkSingleModeCharaDataObject) -> ExtractorFingerprint:
    fields = chara.fields
    return (
        "chara_collections",
        object_pointer_fingerprint("succession_first", fields.successionTrainedCharaInfoFirst),
        object_pointer_fingerprint("succession_second", fields.successionTrainedCharaInfoSecond),
        object_list_fingerprint("acquired_skills", fields.acquiredSkillList),
        ("disabled_skills", list_pointer_fingerprint(fields.disableSkillIdList)),
        object_list_fingerprint("skill_tips", fields.skillTipsList),
        object_array_fingerprint("support_cards", fields.equipSupportCardArray),
        dictionary_pointer_fingerprint(fields.trainingLevelDic),
        object_list_fingerprint("evaluations", fields.evaluationList),
        ("nicknames", array_fingerprint(fields.acquiredNickNameIdArray)),
        ("chara_effects", array_fingerprint(fields.charaEffectIdArray)),
        ("route_races", array_fingerprint(fields.routeRaceIdArray)),
    )


def _career_turn_command_list_fingerprint(value: DataTurnInfoListPtr) -> ExtractorFingerprint:
    if value and (first_command := value.contents.first()) is not None and first_command:
        first_command_fields = first_command.contents.fields
        parameter_deltas = _parameter_delta_dictionary_fingerprint(first_command_fields.paramIncDecInfoDic)
        bonus_parameter_deltas = _parameter_delta_dictionary_fingerprint(first_command_fields.bonusParamIncDecInfoDic)
        live_parameter_deltas = ("live_parameter_deltas",
                                 dictionary_pointer_fingerprint(first_command_fields.livePerformanceIncDecInfoDic))
    else:
        parameter_deltas = "parameter_deltas", ("dict", 0, 0, 0), ("first", ("ptr", 0))
        bonus_parameter_deltas = parameter_deltas
        live_parameter_deltas = "live_parameter_deltas", ("dict", 0, 0, 0)
    return (
        "commands",
        object_list_fingerprint("turn_info", value),
        parameter_deltas,
        ("bonus_parameter_deltas", bonus_parameter_deltas),
        live_parameter_deltas,
    )


def _active_home_info_fingerprint(home_info: C_Ptr[WorkSingleModeHomeInfoObject]) -> ExtractorFingerprint:
    if not home_info:
        return "home_info", pointer_fingerprint(home_info)
    command_lists_dict = home_info.contents.fields.turnInfoListDic
    if command_lists_dict and (first_command_list := command_lists_dict.contents.first()) is not None:
        command_list_fingerprint = _career_turn_command_list_fingerprint(first_command_list.value)
    else:
        command_list_fingerprint = "commands", ("turn_info", ("list", 0, 0, 0), ("first", ("ptr", 0)))
    return (
        "home_info",
        pointer_fingerprint(home_info),
        dictionary_pointer_fingerprint(command_lists_dict),
        command_list_fingerprint,
    )


@dataclass(frozen=True)
class CareerDataExtractionData:
    """Stable active-career input rooted at ``WorkDataManager.singleMode``."""

    career_ptr: C_Ptr[WorkSingleModeDataObject]

    @property
    def career(self) -> WorkSingleModeDataObject:
        return self.career_ptr.contents

    @property
    def start_time(self) -> str:
        career_fields = self.career.fields
        chara = career_fields.character.contents
        return chara.fields.startTime.value_or()

    def fingerprint(self) -> ExtractorFingerprint:
        career = self.career
        fields = career.fields
        chara = fields.character.contents
        chara_fields = chara.fields
        active_view = (
            pointer_fingerprint(self.career_ptr),
            chara_fields.id.value,
            chara_fields.cardId.value,
            chara_fields.scenarioId.value,
            chara_fields.routeId.value,
            chara_fields.startTime.value_or(),
            fields.totalTurnNum.value,
            _active_home_info_fingerprint(fields.homeInfo),
            _career_active_chara_collections_fingerprint(chara),
            _career_scenario_fingerprint(career, chara),
        )
        return (
            "career_data",
            active_view,
            object_list_fingerprint("race_conditions", fields.raceConditions),
            object_list_fingerprint("race_history", fields.raceHistoryInfoList),
            object_array_fingerprint("win_saddles", fields.winSaddleArray),
            _career_succession_factor_fingerprint(chara_fields.successionFactor),
            _career_lottery_program_fingerprint(chara_fields.race),
        )


def resolve_active_career_data_ptr(wdm: WorkDataManagerObject) -> Optional[C_Ptr[WorkSingleModeDataObject]]:
    career_data_ptr = wdm.fields.singleMode
    if not career_data_ptr:
        return None
    fields = career_data_ptr.contents.fields
    if not fields.isPlaying:
        return None
    if not fields.character:
        logger.debug("WorkSingleModeData.character is null")
        return None
    return career_data_ptr


def career_home_info_is_ready(career: WorkSingleModeDataObject) -> bool:
    home_info = career.fields.homeInfo
    if not home_info:
        logger.debug("career_data: waiting for WorkSingleModeData.homeInfo")
        return False
    turn_info_list_dic = home_info.contents.fields.turnInfoListDic
    if not turn_info_list_dic:
        logger.debug("career_data: waiting for WorkSingleModeHomeInfo.turnInfoListDic")
        return False
    dictionary = turn_info_list_dic.contents
    if len(dictionary) == 0:
        logger.debug("career_data: waiting for HomeInfo command lists")
        return False
    for entry in dictionary:
        if entry.value and len(entry.value.contents) > 0:
            return True
    logger.debug("career_data: waiting for populated HomeInfo commands")
    return False


def is_career_data_ready(data: CareerDataExtractionData) -> bool:
    career = data.career
    if career.fields.playingState.value != SingleModePlayingState.TurnStart:
        return False
    return career_home_info_is_ready(career)


def resolve_career_data_inputs(wdm: WorkDataManagerObject) -> Optional[CareerDataExtractionData]:
    """Resolve active career state without applying the TurnStart snapshot gate."""

    career_ptr = resolve_active_career_data_ptr(wdm)
    if career_ptr is None:
        return None
    return CareerDataExtractionData(career_ptr=career_ptr)


def resolve_career_snapshot(wdm: WorkDataManagerObject) -> Optional[CareerDataExtractionData]:
    """Resolve only a TurnStart for turn snapshots."""

    data = resolve_career_data_inputs(wdm)
    if data is None or not is_career_data_ready(data):
        return None
    return data


def resolve_career_snapshot_data(context: ExtractorContext) -> Optional[CareerDataExtractionData]:
    return resolve_career_snapshot(context.work_data_manager)


def extract_career_snapshot(data: CareerDataExtractionData) -> CareerArchiveSnapshot:
    payload = decode_career_data(data)
    chara_info = payload["single_mode_load_common"]["chara_info"]
    key, identity = career_archive_descriptor(data)
    logger.info("Decoded active career data: chara=%d card=%d turn=%d",
                chara_info["single_mode_chara_id"], chara_info["card_id"], chara_info["turn"])
    return CareerArchiveSnapshot(key, int(chara_info["turn"]), identity, payload)


def career_snapshot_output_key(snapshot: CareerArchiveSnapshot) -> str:
    return snapshot.key
