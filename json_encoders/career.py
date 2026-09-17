"""Active-career extraction and API-shaped snapshot decoding."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any, TYPE_CHECKING, TypeAlias

from career_log import CareerLogEntry, CareerLogObservation
from ctypes_utils import C_Ptr
from game_structs.collections import GenericArrayPtr, GenericDictionary, GenericList
from game_structs.enums import (SingleModeCommandType, SingleModeLiveGainParameterType, SingleModeParameterType,
                                SingleModePlayingState, SingleModeScenarioId)
from game_structs.master_data import MasterSingleModeWinsSaddleSingleModeWinsSaddleObject
from game_structs.obscured import ObscuredInt
from game_structs.race import (CharaRaceRewardObject, RaceHorseDataObject, RaceHorseDataRaceResultObject,
                               RaceRewardDataObject, RaceRewardSetDataObject)
from game_structs.single_mode import (EquipSupportCardObject, SingleModeFreeCommandInfoObject,
                                      SingleModeFreeItemEffectObject, SingleModeFreePickUpItemObject,
                                      SingleModeFreeUserItemObject, SingleModeLogSubstanceObject,
                                      SingleModeNpcTeamDataObject, SingleModeRivalRaceInfoObject,
                                      SingleModeTeamEventEffectInfoObject, SingleModeTeamFrameOrderObject,
                                      SingleModeTeamOpponentListObject, SingleModeTeamRaceCharaResultObject,
                                      SingleModeTeamRaceHistoryObject, SingleModeTeamRandomInfoObject,
                                      TeamSoulSkillDictionaryEntry, WorkSingleModeCharaDataEvaluationObject,
                                      WorkSingleModeCharaDataGroupOutingInfoObject, WorkSingleModeCharaDataObject,
                                      WorkSingleModeCharaDataSkillTipsObject,
                                      WorkSingleModeCharaDataSuccessionFactorInfoObject,
                                      WorkSingleModeDataEventInfoObject,
                                      WorkSingleModeDataLivePerformanceIncDecInfoDictionaryEntry,
                                      WorkSingleModeDataObject, WorkSingleModeDataParamsIncDecInfoDictionaryEntry,
                                      WorkSingleModeDataRaceConditionObject,
                                      WorkSingleModeDataSuccessionEventInfoObject, WorkSingleModeDataTurnInfoObject,
                                      WorkSingleModeHomeInfoObject, WorkSingleModeScenarioFreeNpcResultObject,
                                      WorkSingleModeScenarioFreeTwinkleRaceNpcInfoObject,
                                      WorkSingleModeScenarioFreeTwinkleRaceNpcResultObject,
                                      WorkSingleModeScenarioLivePerformanceDataObject,
                                      WorkSingleModeScenarioLiveTrainingBonusObject,
                                      WorkSingleModeScenarioTeamRaceDeckDataObject,
                                      WorkSingleModeScenarioTeamRaceObject,
                                      WorkSingleModeScenarioTeamRaceSingleTeamRaceResultObject,
                                      WorkSingleModeScenarioTeamRaceTeamMemberObject)
from game_structs.skills import SkillTipsObject
from game_structs.trained_chara import RaceHistoryInfoObject
from .race import _decode_skill_data_entry
from .trained_chara import _decode_acquired_skill_entry, _decode_factor_info_entry

if TYPE_CHECKING:
    from extractors.career import CareerDataExtractionData

ParamIncDecInfoDictPtr: TypeAlias = C_Ptr[GenericDictionary[WorkSingleModeDataParamsIncDecInfoDictionaryEntry]]
HomeCommand: TypeAlias = tuple[int, WorkSingleModeDataTurnInfoObject]
RaceHistoryListPtr: TypeAlias = C_Ptr[GenericList[C_Ptr[RaceHistoryInfoObject]]]
WinsSaddleArrayPtr: TypeAlias = GenericArrayPtr[C_Ptr[MasterSingleModeWinsSaddleSingleModeWinsSaddleObject]]
RaceConditionListPtr: TypeAlias = C_Ptr[GenericList[C_Ptr[WorkSingleModeDataRaceConditionObject]]]
SuccessionFactorInfoPtr: TypeAlias = C_Ptr[WorkSingleModeCharaDataSuccessionFactorInfoObject]
LivePerformanceIncDecInfoDictPtr: TypeAlias = C_Ptr[
    GenericDictionary[WorkSingleModeDataLivePerformanceIncDecInfoDictionaryEntry]]
LivePerformancePtr: TypeAlias = C_Ptr[WorkSingleModeScenarioLivePerformanceDataObject]
LiveTrainingBonusArrayPtr: TypeAlias = GenericArrayPtr[C_Ptr[WorkSingleModeScenarioLiveTrainingBonusObject]]
RaceRewardSets: TypeAlias = GenericArrayPtr[C_Ptr[RaceRewardSetDataObject]]

_LIVE_TRAINING_BONUS_TARGET_TYPES: dict[SingleModeParameterType, SingleModeLiveGainParameterType] = {
    SingleModeParameterType.Speed: SingleModeLiveGainParameterType.Speed,
    SingleModeParameterType.Stamina: SingleModeLiveGainParameterType.Stamina,
    SingleModeParameterType.Power: SingleModeLiveGainParameterType.Power,
    SingleModeParameterType.Guts: SingleModeLiveGainParameterType.Guts,
    SingleModeParameterType.Wiz: SingleModeLiveGainParameterType.Wiz,
    SingleModeParameterType.SkillPoint: SingleModeLiveGainParameterType.SkillPt,
}


def _decode_active_skill_tip_entry(entry: WorkSingleModeCharaDataSkillTipsObject) -> dict[str, int]:
    f = entry.fields
    return {
        "group_id": f.groupId.value,
        "rarity": f.rarity.value,
        "level": f.level.value,
    }


def _decode_active_support_card_entry(entry: EquipSupportCardObject) -> dict[str, int]:
    f = entry.fields
    return {
        "position": f.position.value,
        "support_card_id": f.supportCardId.value,
        "limit_break_count": f.limitBreakCount.value,
        "exp": f.exp.value,
        "owner_viewer_id": 0,
    }


def _decode_active_group_outing_info_entry(entry: WorkSingleModeCharaDataGroupOutingInfoObject) -> dict[str, int]:
    f = entry.fields
    return {
        "chara_id": f.charaId.value,
        "is_outing": int(f.isOuting.value),
        "story_step": f.storyStep.value,
    }


def _decode_active_evaluation_info_entry(entry: WorkSingleModeCharaDataEvaluationObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "target_id": f.targetId.value,
        "training_partner_id": f.targetId.value,
        "evaluation": f.value.value,
        "is_outing": int(f.isOuting.value),
        "story_step": f.storyStep.value,
        "is_appear": int(f.isAppear.value),
        "group_outing_info_array": [
            _decode_active_group_outing_info_entry(group_outing_info_ptr.contents)
            for group_outing_info_ptr in f.groupOutingInfoList.contents
            if group_outing_info_ptr
        ] if f.groupOutingInfoList else [],
    }


def _decode_active_training_levels(entry: WorkSingleModeCharaDataObject) -> dict[int, int]:
    training_level_dic = entry.fields.trainingLevelDic
    if not training_level_dic:
        return {}
    return {
        int(training_level.key): int(training_level.value)
        for training_level in training_level_dic.contents
    }


def _decode_active_training_partners(entry: WorkSingleModeDataTurnInfoObject) -> list[dict[str, int]]:
    training_horse_list = entry.fields.trainingHorseList
    if not training_horse_list:
        return []
    partners: list[dict[str, int]] = []
    for training_horse_ptr in training_horse_list.contents:
        if not training_horse_ptr:
            continue
        training_horse_fields = training_horse_ptr.contents.fields
        partners.append({
            "position_id": training_horse_fields.positionId.value,
            "is_tips": int(training_horse_fields.isTips.value),
            "is_versus_event": int(training_horse_fields.isVersusEvent.value),
            "is_guide": int(training_horse_fields.isGuide.value),
            "is_soul_explode": int(training_horse_fields.isSoulExplode.value),
            "is_sp_soul_explode": int(training_horse_fields.isSpSoulExplode.value),
        })
    return partners


def _decode_active_params_inc_dec_info_array(params_inc_dec_info_dic: ParamIncDecInfoDictPtr) -> list[dict[str, int]]:
    if not params_inc_dec_info_dic:
        return []
    deltas: list[dict[str, int]] = []
    for parameter_delta in params_inc_dec_info_dic.contents:
        value = parameter_delta.value
        if not value:
            continue
        delta_fields = value.contents.fields
        deltas.append({
            "target_type": int(parameter_delta.key),
            "value": delta_fields.value.value,
        })
    return deltas


def _iter_active_home_commands(home: C_Ptr[WorkSingleModeHomeInfoObject]) -> Iterator[HomeCommand]:
    """Yield typed commands in their dictionary/list order, skipping null pointers."""
    if not home or not (command_lists := home.contents.fields.turnInfoListDic):
        return
    for command_list in command_lists.contents:
        if not command_list.value:
            continue
        for command in command_list.value.contents:
            if command:
                yield int(command_list.key), command.contents


def _decode_active_home_command_info(entry: WorkSingleModeDataTurnInfoObject, command_type: int,
                                     training_levels: dict[int, int]) -> dict[str, Any]:
    command_fields = entry.fields
    partners = _decode_active_training_partners(entry)
    command_id = command_fields.commandId.value
    return {
        "command_type": command_type,
        "command_id": command_id,
        "is_enable": int(command_fields.isEnable.value),
        "training_partner_array": [partner["position_id"] for partner in partners],
        "tips_event_partner_array": [partner["position_id"] for partner in partners if partner["is_tips"]],
        "params_inc_dec_info_array": _decode_active_params_inc_dec_info_array(command_fields.paramIncDecInfoDic),
        "failure_rate": command_fields.trainingFailureRate,
        "level": training_levels.get(command_id, 0),
    }


def _decode_active_home_info(entry: C_Ptr[WorkSingleModeHomeInfoObject],
                             training_levels: dict[int, int]) -> dict[str, Any]:
    if not entry:
        return {
            "command_info_array": [],
            "race_entry_restriction": 0,
            "disable_command_id_array": [],
            "available_continue_num": 0,
            "available_free_continue_num": 0,
            "free_continue_num": 0,
            "free_continue_time": 0,
            "shortened_race_state": 0,
        }

    home_info_fields = entry.contents.fields
    return {
        "command_info_array": [
            _decode_active_home_command_info(command, command_type, training_levels)
            for command_type, command in _iter_active_home_commands(entry)
        ],
        # HomeInfo.Apply does not retain this API field; RaceEntry.is_enable is not equivalent.
        "race_entry_restriction": 0,
        "disable_command_id_array": (
            [command_id.value for command_id in home_info_fields.disableCommandIdList.contents]
            if home_info_fields.disableCommandIdList else []
        ),
        "available_continue_num": home_info_fields.availableContinueNum.value,
        "available_free_continue_num": home_info_fields.availableFreeContinueNum.value,
        "free_continue_num": home_info_fields.freeContinueNum.value,
        "free_continue_time": home_info_fields.prevFreeContinueTime.value,
        "shortened_race_state": home_info_fields.shortenedRaceState.value,
    }


def _decode_pending_event(entry: WorkSingleModeDataEventInfoObject,
                          succession: WorkSingleModeDataSuccessionEventInfoObject | None = None) -> dict[str, Any]:
    f = entry.fields
    array_tuple = (f.selectIndexArray, f.receiveItemIdArray, f.targetRaceIdArray, f.gainSelectIdIndexArray,
                   f.selectIconArray)
    choices = [
        {"select_index": index.value, "receive_item_id": item.value, "target_race_id": race.value,
         "gain_select_id_index": gain.value, "select_icon": icon.value}
        for index, item, race, gain, icon in zip(*array_tuple, strict=True)
    ]
    succession_info = None
    if succession:
        succession_fields = succession.fields
        if (succession_fields.eventId.value, succession_fields.charaId.value) == (f.eventId.value, f.charaId.value):
            succession_info = {"effect_type": succession_fields.effectType.value}
    return {
        "event_id": f.eventId.value,
        "chara_id": f.charaId.value,
        "story_id": f.storyId.value,
        "play_timing": f.playTiming.value,
        "event_contents_info": {
            "support_card_id": f.contentsInfoSupportCardId.value,
            "show_clear": f.contentsInfoShowClear.value,
            "show_clear_sort_id": f.contentsInfoShowClearSortId.value,
            "choice_array": choices,
            "is_effected_multi_chara": f.isEffectedMultiChara.value,
            "tips_training_partner_id": f.tipsTrainingPartnerId.value or None,
        },
        "succession_event_info": succession_info,
        "minigame_result": None,
    }


def _decode_pending_events(career: WorkSingleModeDataObject) -> list[dict[str, Any]]:
    queues = career.fields.storyInfoListDic
    if not queues:
        return []
    succession = career.fields.successionEventInfo.contents if career.fields.successionEventInfo else None
    return [_decode_pending_event(event.contents, succession) for queue in queues.contents if queue.value
            for event in queue.value.contents if event]


def _decode_reserved_races(chara: WorkSingleModeCharaDataObject) -> list[dict[str, Any]]:
    context = chara.fields.raceReserveContext
    if not context or not (repository := context.contents.fields.reserveRepository):
        return []
    result: list[dict[str, Any]] = []
    for entity in repository.contents.fields.entities:
        if not entity or not (deck := entity.contents.fields.deckInfo):
            continue
        f = deck.contents.fields
        result.append({
            "deck_num": f.deck_num,
            "deck_name": f.deck_name.value_or(),
            "race_array": [{"year": race.contents.fields.year, "program_id": race.contents.fields.program_id}
                           for race in f.race_array if race],
        })
    return result


def _decode_resume_factor_select(career: WorkSingleModeDataObject) -> dict[str, Any] | None:
    if not (value := career.fields.resumeFactorSelect):
        return None
    f = value.contents.fields
    return {
        "rank_score": f.rank_score,
        "rank": f.rank,
        "lottery_remain_num": f.lottery_remain_num,
        "lottery_count": f.lottery_count,
        "select_lottery_id": f.select_lottery_id,
        "factor_select_info_array": [
            {"lottery_id": item.contents.fields.lottery_id,
             "factor_info_array": [_decode_factor_info_entry(factor.contents)
                                   for factor in item.contents.fields.factor_info_array if factor]}
            for item in f.factor_select_info_array if item
        ],
    }


def _decode_active_chara_info(entry: WorkSingleModeCharaDataObject, *, turn: int, state: int,
                              playing_state: int, training_levels: dict[int, int]) -> dict[str, Any]:
    f = entry.fields
    return {
        "single_mode_chara_id": f.id.value,
        "card_id": f.cardId.value,
        "chara_grade": f.charaGrade.value,
        "speed": f.speed.value,
        "stamina": f.stamina.value,
        "power": f.power.value,
        "wiz": f.wiz.value,
        "guts": f.guts.value,
        "vital": f.hp.value,
        "max_speed": f.maxSpeed.value,
        "max_stamina": f.maxStamina.value,
        "max_power": f.maxPower.value,
        "max_wiz": f.maxWiz.value,
        "max_guts": f.maxGuts.value,
        "default_max_speed": f.defaultMaxSpeed.value,
        "default_max_stamina": f.defaultMaxStamina.value,
        "default_max_power": f.defaultMaxPower.value,
        "default_max_wiz": f.defaultMaxWiz.value,
        "default_max_guts": f.defaultMaxGuts.value,
        "max_vital": f.maxHp.value,
        "motivation": f.motivation.value,
        "fans": f.fanCount.value,
        "rarity": f.limitBreakCount.value,
        "race_program_id": f.entryProgramId.value,
        "reserve_race_program_id": f.reservedRaceProgramId.value,
        "race_running_style": f.runningStyle.value,
        "is_short_race": int(f.isShortRace.value),
        "proper_ground_turf": f.properGroundTurf.value,
        "proper_ground_dirt": f.properGroundDirt.value,
        "proper_running_style_nige": f.properRunningStyleNige.value,
        "proper_running_style_senko": f.properRunningStyleSenko.value,
        "proper_running_style_sashi": f.properRunningStyleSashi.value,
        "proper_running_style_oikomi": f.properRunningStyleOikomi.value,
        "proper_distance_short": f.properDistanceShort.value,
        "proper_distance_mile": f.properDistanceMile.value,
        "proper_distance_middle": f.properDistanceMiddle.value,
        "proper_distance_long": f.properDistanceLong.value,
        "talent_level": f.talentLevel.value,
        "skill_array": [
            _decode_acquired_skill_entry(skill.contents) for skill in f.acquiredSkillList.contents if skill
        ] if f.acquiredSkillList else [],
        "disable_skill_id_array": [
            skill_id.value
            for skill_id in f.disableSkillIdList.contents
        ] if f.disableSkillIdList else [],
        "skill_tips_array": [
            _decode_active_skill_tip_entry(tip.contents) for tip in f.skillTipsList.contents if tip
        ] if f.skillTipsList else [],
        "support_card_array": [
            _decode_active_support_card_entry(support_card_ptr.contents)
            for support_card_ptr in f.equipSupportCardArray
            if support_card_ptr
        ],
        "succession_trained_chara_id_1": (
            f.successionTrainedCharaInfoFirst.contents.fields.trainedCharaId.value
            if f.successionTrainedCharaInfoFirst else 0
        ),
        "succession_trained_chara_id_2": (
            f.successionTrainedCharaInfoSecond.contents.fields.trainedCharaId.value
            if f.successionTrainedCharaInfoSecond else 0
        ),
        "turn": turn,
        "skill_point": f.skillPoint.value,
        "short_cut_state": f.eventShortcutType.value,
        "state": state,
        "playing_state": playing_state,
        "scenario_id": f.scenarioId.value,
        "route_id": f.routeId.value,
        "start_time": f.startTime.value_or(),
        "evaluation_info_array": [
            _decode_active_evaluation_info_entry(evaluation.contents)
            for evaluation in f.evaluationList.contents if evaluation
        ] if f.evaluationList else [],
        "training_level_info_array": [
            {"command_id": command_id, "level": level} for command_id, level in sorted(training_levels.items())
        ],
        "nickname_id_array": [nickname_id.value for nickname_id in f.acquiredNickNameIdArray],
        "chara_effect_id_array": [chara_effect_id.value for chara_effect_id in f.charaEffectIdArray],
        "route_race_id_array": [route_race_id.value for route_race_id in f.routeRaceIdArray],
        "guest_outing_info_array": [],
        "skill_upgrade_info_array": [],
    }


def _decode_active_race_history_entry(entry: RaceHistoryInfoObject) -> dict[str, int]:
    f = entry.fields
    return {
        "turn": f.turn.value,
        "program_id": f.programId.value,
        "weather": f.weather.value,
        "ground_condition": f.groundCondition.value,
        "running_style": f.runningStyle.value,
        "result_rank": f.resultRank.value,
        "frame_order": f.frameOrder.value,
        "npc_count": f.npcCount.value,
    }


def _decode_active_race_history(value: RaceHistoryListPtr) -> list[dict[str, int]]:
    """Decode the current race-history list without assuming a lifecycle phase."""

    if not value:
        return []
    return [_decode_active_race_history_entry(entry.contents) for entry in value.contents if entry]


def _decode_active_integer_array(value: GenericArrayPtr[ObscuredInt]) -> list[int]:
    return [item.value for item in value]


def _decode_active_win_saddle_ids(value: WinsSaddleArrayPtr) -> list[int]:
    return [int(saddle.contents.fields.id) for saddle in value if saddle]


def _decode_active_race_conditions(value: RaceConditionListPtr) -> list[dict[str, int]]:
    if not value:
        return []
    return [
        {
            "program_id": condition.contents.fields.programId.value,
            "weather": condition.contents.fields.weather.value,
            "ground_condition": condition.contents.fields.groundCondition.value,
        }
        for condition in value.contents
        if condition
    ]


def _decode_active_effected_factor_array(value: SuccessionFactorInfoPtr) -> list[dict[str, Any]] | None:
    """Decode succession factors in their API position order when typed data exists."""

    if not value:
        return None
    info_list = value.contents.fields.infoList
    if not info_list:
        return None

    if len(info_list.contents) == 0:
        return None

    factors: list[dict[str, Any]] = []
    for info in info_list.contents:
        if not info:
            continue
        fields = info.contents.fields
        factor_ids: list[int] = []
        if fields.factorIdList:
            factor_ids = [factor_id.value for factor_id in fields.factorIdList.contents]
        factors.append({
            "position": fields.position.value,
            "factor_info_array": [{"factor_id": factor_id, "level": 0} for factor_id in factor_ids],
        })
    return sorted(factors, key=lambda item: int(item["position"]))


def _decode_active_race_random_program_array(chara: WorkSingleModeCharaDataObject) -> list[dict[str, int]]:
    """Decode unique lottery selections in turn/program order."""
    if not (race := chara.fields.race):
        return []
    if not (programs := race.contents.fields.lotteryProgramDataDict):
        return []
    selected: set[tuple[int, int]] = set()
    for entry in programs.contents:
        if not entry.value:
            continue
        for program in entry.value.contents:
            if not program:
                continue
            fields = program.contents.fields
            if program_id := fields.programId.value:
                selected.add((fields.turn.value or int(entry.key), program_id))
    return [{"turn": turn, "program_id": program_id} for turn, program_id in sorted(selected)]


def _decode_active_live_performance_delta_array(value: LivePerformanceIncDecInfoDictPtr) -> list[dict[str, int]]:
    if not value:
        return []
    return [{"performance_type": delta.key, "value": delta.value} for delta in value.contents]


def _decode_active_live_training_bonus_array(value: LiveTrainingBonusArrayPtr) -> list[dict[str, int]]:
    """Translate Work's parameter enum back to the API's Live-bonus enum."""

    bonuses: list[dict[str, int]] = []
    for entry in value:
        if not entry:
            continue
        fields = entry.contents.fields
        target_type = _LIVE_TRAINING_BONUS_TARGET_TYPES.get(SingleModeParameterType(fields.parameterType))
        bonuses.append({"target_type": target_type.value if target_type is not None else 0,
                        "effect_value": fields.value})
    return bonuses


def _decode_active_live_command_info(home_info: C_Ptr[WorkSingleModeHomeInfoObject]) -> list[dict[str, Any]]:
    """Decode the Live-only part of training command data when it is reflected."""

    command_info_array: list[dict[str, Any]] = []
    for command_type, command in _iter_active_home_commands(home_info):
        if command_type != SingleModeCommandType.Training:
            continue
        fields = command.fields
        command_info_array.append({
            "command_type": command_type,
            "command_id": fields.commandId.value,
            "performance_inc_dec_info_array": _decode_active_live_performance_delta_array(
                    fields.livePerformanceIncDecInfoDic),
            # ApplyLiveCommandInfo stores the scenario deltas separately from the common command gains.
            "params_inc_dec_info_array": _decode_active_params_inc_dec_info_array(fields.bonusParamIncDecInfoDic),
        })
    return command_info_array


def _decode_active_live_performance(value: LivePerformancePtr | None) -> dict[str, int]:
    values = (0, 0, 0, 0, 0)
    if value:
        f = value.contents.fields
        values = (f.dance.value, f.passion.value, f.vocal.value, f.visual.value, f.mental.value)
    return dict(zip(("dance", "passion", "vocal", "visual", "mental"), values))


def _decode_active_live_data_set(
        career: WorkSingleModeDataObject,
        chara: WorkSingleModeCharaDataObject,
        home_info: C_Ptr[WorkSingleModeHomeInfoObject],
) -> dict[str, Any]:
    chara_fields = chara.fields
    if not (live := chara_fields.scenarioLive):
        return {}

    live_fields = live.contents.fields
    performance_source = live_fields.performance
    maximum_source = live_fields.performanceMax
    evaluation_info_array: list[dict[str, int]] = []
    if live_fields.evaluationInfoList:
        evaluation_info_array = [
            {
                "target_id": entry.contents.fields.target_id,
                "chara_id": entry.contents.fields.chara_id,
                "member_state": entry.contents.fields.member_state,
            }
            for entry in live_fields.evaluationInfoList.contents
            if entry
        ]
    live_result_array: list[dict[str, int]] = []
    if live_fields.liveResultList:
        live_result_array = [
            {
                "live_type": entry.contents.fields.liveType.value,
                "result_state": entry.contents.fields.result.value,
            }
            for entry in live_fields.liveResultList.contents
            if entry
        ]
    performance_type_array: list[int] = []
    career_fields = career.fields
    change = career_fields.changeParameterInfo
    if change:
        change_fields = change.contents.fields
        performance_source = performance_source or change_fields.performance
        maximum_source = maximum_source or change_fields.performanceMax
        if limit_performance_types := change_fields.limitPerformanceTypeList:
            performance_type_array = [value.value for value in limit_performance_types.contents]

    performance = _decode_active_live_performance(performance_source)
    maximum = _decode_active_live_performance(maximum_source)
    return {
        "live_performance_info": {**performance, **{f"max_{name}": value for name, value in maximum.items()}},
        "command_info_array": _decode_active_live_command_info(home_info),
        "evaluation_info_array": evaluation_info_array,
        "next_square_info_array": [
            {"square_id": square.contents.fields.squareId.value, "square_num": square.contents.fields.squareNum.value}
            for square in live_fields.treeSquareInfoArray if square
        ],
        "master_live_id_array": _decode_active_integer_array(live_fields.totalMusicIdArray),
        "next_live_id_array": _decode_active_integer_array(live_fields.nextMusicIdArray),
        "effected_live_id_array": _decode_active_integer_array(live_fields.currentLiveBonusMusicIdArray),
        "not_up_parameter_info": {"performance_type_array": performance_type_array},
        "live_result_array": live_result_array,
        "reserve_square_id": live_fields.reservedTreeSquareId.value,
        "training_bonus_array": _decode_active_live_training_bonus_array(live_fields.trainingBonusArray),
    }


def _decode_active_team_member(value: WorkSingleModeScenarioTeamRaceTeamMemberObject) -> dict[str, int]:
    """Decode one persistent Aoharu team member into its API response shape."""

    fields = value.fields
    return {
        "training_partner_id": fields.charaId.value,
        "speed": fields.speed.value,
        "stamina": fields.stamina.value,
        "power": fields.power.value,
        "wiz": fields.wiz.value,
        "guts": fields.guts.value,
        "speed_limit": fields.speedLimit.value,
        "stamina_limit": fields.staminaLimit.value,
        "power_limit": fields.powerLimit.value,
        "wiz_limit": fields.wizLimit.value,
        "guts_limit": fields.gutsLimit.value,
        "speed_limit_base": fields.speedLimitBase.value,
        "stamina_limit_base": fields.staminaLimitBase.value,
        "power_limit_base": fields.powerLimitBase.value,
        "wiz_limit_base": fields.wizLimitBase.value,
        "guts_limit_base": fields.gutsLimitBase.value,
        "rank_score": fields.rankScore.value,
    }


def _decode_active_team_deck_entry(value: WorkSingleModeScenarioTeamRaceDeckDataObject) -> dict[str, int]:
    """Decode one current Aoharu deck assignment without exposing its work wrapper."""

    fields = value.fields
    return {
        "distance_type": fields.distanceType.value,
        "member_id": fields.memberId.value,
        "chara_id": fields.charaId.value,
        "running_style": fields.runningStyle.value,
    }


def _decode_active_team_command_info(home: C_Ptr[WorkSingleModeHomeInfoObject]) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for command_type, command in _iter_active_home_commands(home):
        if command_type != SingleModeCommandType.Training:
            continue
        partners = _decode_active_training_partners(command)
        fields = command.fields
        commands.append({
            "command_type": command_type,
            "command_id": fields.commandId.value,
            "guide_event_partner_array": [partner["position_id"] for partner in partners if partner["is_guide"]],
            "soul_event_partner_array": [partner["position_id"] for partner in partners if partner["is_soul_explode"]],
            "sp_soul_event_partner_array": [
                partner["position_id"] for partner in partners if partner["is_sp_soul_explode"]
            ],
            "params_inc_dec_info_array": _decode_active_params_inc_dec_info_array(fields.bonusParamIncDecInfoDic),
        })
    return commands


def _decode_career_race_horse_result(entry: RaceHorseDataRaceResultObject) -> dict[str, int]:
    """Decode the retained values and explicit unavailable result fields."""
    fields = entry.fields
    return {
        "viewer_id": 0,
        "single_mode_chara_id": 0,
        "race_num": 0,
        "turn": fields.turn,
        "program_id": fields.program_id,
        "frame_order": 0,
        "weather": 0,
        "ground_condition": 0,
        "running_style": 0,
        "popularity": 0,
        "result_rank": fields.result_rank,
        "result_time": 0,
        "bashin_diff": 0,
        "bashin_diff_from_top": 0,
        "skill_activate_count": 0,
        "start_dash_state": 0,
        "motivation": 0,
        "is_excitement": 0,
        "is_running_alone": 0,
        "last_straight_line_rank": 0,
        "auto_continue_num": 0,
        "state": 0,
    }


def _decode_career_race_horse(entry: RaceHorseDataObject) -> dict[str, Any]:
    fields = entry.fields
    trainer_name = fields.trainer_name.value_or()
    return {
        "frame_order": fields.frame_order,
        "viewer_id": fields.viewer_id,
        "trainer_name": trainer_name if trainer_name else None,
        "owner_viewer_id": fields.owner_viewer_id,
        "owner_trainer_name": fields.owner_trainer_name.value_or(),
        "single_mode_chara_id": fields.single_mode_chara_id,
        "trained_chara_id": fields.trained_chara_id,
        "nickname_id": fields.nickname_id,
        "chara_id": fields.chara_id,
        "card_id": fields.card_id,
        "mob_id": fields.mob_id,
        "rarity": fields.rarity,
        "talent_level": fields.talent_level,
        "skill_array": [_decode_skill_data_entry(skill.contents) for skill in fields.skill_array if skill],
        "stamina": fields.stamina,
        "speed": fields.speed,
        "pow": fields.pow,
        "guts": fields.guts,
        "wiz": fields.wiz,
        "running_style": fields.running_style,
        "race_dress_id": fields.race_dress_id,
        "chara_color_type": fields.chara_color_type,
        "npc_type": fields.npc_type,
        "final_grade": fields.final_grade,
        "popularity": fields.popularity,
        "popularity_mark_rank_array": [value.value for value in fields.popularity_mark_rank_array],
        "proper_distance_short": fields.proper_distance_short,
        "proper_distance_mile": fields.proper_distance_mile,
        "proper_distance_middle": fields.proper_distance_middle,
        "proper_distance_long": fields.proper_distance_long,
        "proper_running_style_nige": fields.proper_running_style_nige,
        "proper_running_style_senko": fields.proper_running_style_senko,
        "proper_running_style_sashi": fields.proper_running_style_sashi,
        "proper_running_style_oikomi": fields.proper_running_style_oikomi,
        "proper_ground_turf": fields.proper_ground_turf,
        "proper_ground_dirt": fields.proper_ground_dirt,
        "motivation": fields.motivation,
        "win_saddle_id_array": [value.value for value in fields.win_saddle_id_array],
        "race_result_array": [
            _decode_career_race_horse_result(race_result.contents)
            for race_result in fields.race_result_array
            if race_result
        ],
        "team_id": fields.team_id,
        "team_member_id": fields.team_member_id,
        "team_rank": fields.team_rank,
        "single_mode_win_count": fields.single_mode_win_count,
        "fan_count": fields.fan_count,
        "item_id_array": [value.value for value in fields.item_id_array],
        "motivation_change_flag": fields.motivation_change_flag,
        "frame_order_change_flag": fields.frame_order_change_flag,
    }


def _decode_career_race_reward_data(entry: RaceRewardDataObject) -> dict[str, int]:
    fields = entry.fields
    return {
        "item_type": fields.item_type,
        "item_id": fields.item_id,
        "item_num": fields.item_num,
    }


def _decode_career_race_reward(reward_info: C_Ptr[CharaRaceRewardObject]) -> dict[str, Any] | None:
    if not reward_info:
        return None
    fields = reward_info.contents.fields
    return {
        "result_rank": fields.result_rank,
        "result_time": fields.result_time,
        "race_reward": [
            _decode_career_race_reward_data(reward.contents)
            for reward in fields.race_reward
            if reward
        ],
        "race_reward_bonus": [
            _decode_career_race_reward_data(reward.contents)
            for reward in fields.race_reward_bonus
            if reward
        ],
        "gained_fans": fields.gained_fans,
        "campaign_id_array": [value.value for value in fields.campaign_id_array],
        "race_reward_plus_bonus": [
            _decode_career_race_reward_data(reward.contents)
            for reward in fields.race_reward_plus_bonus
            if reward
        ],
        "race_reward_bonus_win": [
            _decode_career_race_reward_data(reward.contents)
            for reward in fields.race_reward_bonus_win
            if reward
        ],
    }


def _decode_career_race_reward_set_array(value: RaceRewardSets) -> list[dict[str, int]]:
    """Flatten current RaceInfo reward sets into the endpoint's reward list."""

    rewards: list[dict[str, int]] = []
    for reward_set in value:
        if not reward_set:
            continue
        rewards.extend(
                _decode_career_race_reward_data(reward.contents)
                for reward in reward_set.contents.fields.reward_list
                if reward
        )
    return rewards


def _decode_runtime_race_reward(data: CareerDataExtractionData) -> dict[str, Any] | None:
    """Decode a race-end reward from the current RaceInfo source.

    ``ApplyRaceEnd`` updates RaceInfo directly, unlike the load-hydrated
    RaceStartResultInfo reward pointer.  Do not substitute the latter here: a
    stale reward would become immutable evidence for the wrong race program.
    """
    race_info = data.race_info
    if not race_info or not (reward_single := race_info.contents.fields.raceRewardSingle):
        return None
    reward_single_fields = reward_single.contents.fields
    if not reward_single_fields.reward:
        return None
    # RaceRewardInfoSingle has no rank. Only use history belonging to this turn and program.
    career = data.career.fields
    if not (history_ptr := career.raceHistoryInfoList):
        return None
    history = history_ptr.contents
    if not len(history) or not (last_ptr := history.span()[len(history) - 1]):
        return None
    last = last_ptr.contents.fields
    current_race = (career.totalTurnNum.value, race_info.contents.fields.singleRaceProgramId)
    if (last.turn.value, last.programId.value) != current_race:
        return None
    reward_fields = reward_single_fields.reward.contents.fields
    return {
        "result_rank": last.resultRank.value,
        "result_time": 0,
        "race_reward": _decode_career_race_reward_set_array(reward_fields.rewardSetArray),
        "race_reward_bonus": _decode_career_race_reward_set_array(reward_fields.bonusRewardSetArray),
        "gained_fans": reward_single_fields.raceGainedFanCount,
        "campaign_id_array": [],
        "race_reward_plus_bonus": _decode_career_race_reward_set_array(reward_fields.rewardPlusBonusSetArray),
        "race_reward_bonus_win": _decode_career_race_reward_set_array(reward_fields.bonusRewardWinSetArray),
    }


def _decode_team_random(entry: SingleModeTeamRandomInfoObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "team_race_set_id": f.team_race_set_id,
        "member_id": f.member_id,
        "chara_id": f.chara_id,
        "npc_id": f.npc_id,
        "running_style": f.running_style,
        "frame_order": f.frame_order,
        "motivation": f.motivation,
        "stamina": f.stamina,
        "speed": f.speed,
        "pow": f.pow,
        "guts": f.guts,
        "wiz": f.wiz,
    }


def _decode_team_npc(entry: SingleModeNpcTeamDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "distance_type": f.distance_type,
        "member_id": f.member_id,
        "base_npc_id": f.base_npc_id,
        "npc_id": f.npc_id,
        "running_style": f.running_style,
    }


def _decode_team_history(entry: SingleModeTeamRaceHistoryObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "race_num": f.race_num,
        "turn": f.turn,
        "team_race_set_id": f.team_race_set_id,
        "result_state": f.result_state,
    }


def _decode_team_effect(entry: SingleModeTeamEventEffectInfoObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "is_summarize_team_member": f.is_summarize_team_member,
        "gain_speed": f.gain_speed,
        "gain_stamina": f.gain_stamina,
        "gain_power": f.gain_power,
        "gain_guts": f.gain_guts,
        "gain_wiz": f.gain_wiz,
    }


def _decode_team_frame(entry: SingleModeTeamFrameOrderObject) -> dict[str, Any]:
    f = entry.fields
    return {"distance_type": f.distance_type, "race_order": f.race_order,
            "random_info_array": [_decode_team_random(item.contents) for item in f.random_info_array if item]}


def _decode_team_opponent(entry: SingleModeTeamOpponentListObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "team_race_set_id": f.team_race_set_id, "team_power": f.team_power, "team_rank": f.team_rank,
        "team_data_array": [_decode_team_npc(item.contents) for item in f.team_data_array if item],
        "win_up_rank": f.win_up_rank, "lose_down_rank": f.lose_down_rank, "draw_rank": f.draw_rank,
    }


def _decode_skill_tips_entry(entry: SkillTipsObject) -> dict[str, int]:
    f = entry.fields
    return {"group_id": f.group_id, "rarity": f.rarity, "level": f.level}


def _decode_team_chara_result(entry: SingleModeTeamRaceCharaResultObject) -> dict[str, int]:
    f = entry.fields
    return {
        "frame_order": f.frame_order,
        "chara_id": f.chara_id,
        "npc_id": f.npc_id,
        "team_id": f.team_id,
        "finish_order": f.finish_order,
        "finish_time": f.finish_time,
        "popularity": f.popularity,
    }


def _decode_team_result(entry: WorkSingleModeScenarioTeamRaceSingleTeamRaceResultObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "distance_type": f.raceNum.value,
        "race_instance_id": f.raceInstanceId.value,
        "season": f.season.value,
        "weather": f.weather.value,
        "ground_condition": f.groundCondition.value,
        "random_seed": f.randomSeed.value,
        "race_horse_data_array": [_decode_career_race_horse(item.contents) for item in f.raceHorseData if item],
        "race_scenario": f.raceScenario.value_or(None),
        "round": f.round.value,
        "win_type": f.roundResult,
        "chara_result_array": [_decode_team_chara_result(item.contents) for item in f.charaResultArray if item],
        "continue_num": f.continueNum.value,
    }


def _decode_team_soul_tips(value: C_Ptr[GenericDictionary[TeamSoulSkillDictionaryEntry]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for entry in value.contents if value else ():
        if not entry.value:
            continue
        f = entry.value.contents.fields
        result.append({
            "training_partner_id": entry.key,
            "skill_tips_array": [_decode_skill_tips_entry(item.contents) for item in f.skillTips if item],
            "not_up_skill_tips_array": [_decode_skill_tips_entry(item.contents) for item in f.notUpSkillTips if item],
            "not_up_skill_id_array": [item.value for item in f.notGetSkill],
        })
    return result


def _decode_team_command_result(team: WorkSingleModeScenarioTeamRaceObject) -> dict[str, Any] | None:
    f = team.fields
    skills = [_decode_skill_tips_entry(item.contents) for item in f.skillTipsArray if item]
    soul = _decode_team_soul_tips(f.soulSkillTipsDictionary)
    special = _decode_team_soul_tips(f.spSoulSkillTipsDictionary)
    if not (skills or soul or special):
        return None
    return {"skill_tips_array": skills, "soul_skill_tips_array": soul, "sp_soul_skill_tips_array": special}


def _decode_active_team_data_set(chara: WorkSingleModeCharaDataObject,
                                 home: C_Ptr[WorkSingleModeHomeInfoObject]) -> dict[str, Any]:
    chara_fields = chara.fields
    if not (team := chara_fields.teamRace):
        return {}

    team_fields = team.contents.fields
    team_info = {
        "team_name_id": team_fields.teamNameId,
        "speed_rank": int(team_fields.teamParameterRankSpeed),
        "stamina_rank": int(team_fields.teamParameterRankStamina),
        "power_rank": int(team_fields.teamParameterRankPower),
        "guts_rank": int(team_fields.teamParameterRankGuts),
        "wiz_rank": int(team_fields.teamParameterRankWiz),
        "team_power": team_fields.teamTotalPower.value,
        "team_rank": team_fields.teamRanking.value,
        "team_rank_state": 0,
        "team_title": team_fields.teamHonorId.value,
        "guide_partner_count": team_fields.guidePartnerCount,
        "is_scout_enable": team_fields.isScoutEnable,
        "team_chara_info_array": [
            _decode_active_team_member(member.contents) for member in team_fields.teamMemberList.contents if member
        ] if team_fields.teamMemberList else [],
        "team_data_array": [
            _decode_active_team_deck_entry(entry.contents) for entry in team_fields.deckDataList.contents if entry
        ] if team_fields.deckDataList else [],
        "team_edit_flag": int(team_fields.teamEditFlag),
    }

    evaluation_info_array: list[dict[str, int]] = []
    if chara_fields.evaluationList:
        evaluation_info_array = [
            {
                "target_id": evaluation.contents.fields.targetId.value,
                "chara_id": evaluation.contents.fields.guestCharaId.value,
                "member_state": evaluation.contents.fields.interestState.value,
                "soul_threshold_id": evaluation.contents.fields.soulThresholdId.value,
                "soul_event_state": evaluation.contents.fields.soulEventState.value,
            }
            for evaluation in chara_fields.evaluationList.contents
            if evaluation
        ]

    race_results = []
    if results := team_fields.singleTeamResultList:
        race_results = [_decode_team_result(item.contents) for item in results.contents if item]
    return {
        "team_info": team_info,
        "command_info_array": _decode_active_team_command_info(home),
        "evaluation_info_array": evaluation_info_array,
        "scenario_progress": chara_fields.scenarioProgress.value,
        "frame_order_info_array": [
            _decode_team_frame(item.contents) for item in team_fields.teamFrameOrderArray if item
        ] if team_fields.teamFrameOrderArray else None,
        "race_result_array": race_results or None,
        "final_win_type": team_fields.finalWinType if race_results else None,
        "opponent_info_array": [
            _decode_team_opponent(item.contents) for item in team_fields.opponentListArray if item
        ] if team_fields.opponentListArray else None,
        "event_effect_info": (
            _decode_team_effect(team_fields.teamEventEffectInfo.contents) if team_fields.teamEventEffectInfo else None
        ),
        "not_up_team_parameter_info": {"status_array": []},
        "team_race_history_array": [
            _decode_team_history(item.contents) for item in team_fields.teamRaceHistoryArray if item
        ],
        "command_result": _decode_team_command_result(team.contents),
    }


def _decode_active_ura_command_info(home_info: C_Ptr[WorkSingleModeHomeInfoObject]) -> list[dict[str, int]]:
    """Rebuild the URA command extension from the authoritative HomeInfo partner flags."""

    result: list[dict[str, int]] = []
    for command_type, command in _iter_active_home_commands(home_info):
        partners = _decode_active_training_partners(command)
        versus_partner_id = next((partner["position_id"] for partner in partners if partner["is_versus_event"]), 0)
        result.append({
            "command_type": command_type,
            "command_id": command.fields.commandId.value,
            "versus_event_partner_id": versus_partner_id,
        })
    return result


def _decode_active_ura_data_set(
        chara: WorkSingleModeCharaDataObject,
        home_info: C_Ptr[WorkSingleModeHomeInfoObject],
) -> dict[str, Any]:
    """Return the observed ``ura_data_set`` shape from persistent URA work state."""

    chara_fields = chara.fields
    if not (ura_data := chara_fields.workScenarioURA):
        return {}

    return {
        "command_info_array": _decode_active_ura_command_info(home_info),
        "evaluation_info_array": [
            {
                "target_id": evaluation.contents.fields.targetId.value,
                "chara_id": evaluation.contents.fields.guestCharaId.value,
                "member_state": evaluation.contents.fields.interestState.value,
            }
            for evaluation in chara_fields.evaluationList.contents
            if evaluation
        ] if chara_fields.evaluationList else [],
        "versus_level": ura_data.contents.fields.versusLevel.value,
    }


def _decode_free_command_info(command: SingleModeFreeCommandInfoObject) -> dict[str, Any]:
    fields = command.fields
    return {
        "command_type": fields.command_type,
        "command_id": fields.command_id,
        "params_inc_dec_info_array": [
            {"target_type": value.contents.fields.target_type, "value": value.contents.fields.value}
            for value in fields.params_inc_dec_info_array if value
        ],
    }


def _decode_free_user_item(value: SingleModeFreeUserItemObject) -> dict[str, int]:
    return {"item_id": value.fields.item_id, "num": value.fields.num}


def _decode_free_pick_up_item(value: SingleModeFreePickUpItemObject) -> dict[str, int]:
    return {
        "shop_item_id": value.fields.shop_item_id,
        "item_id": value.fields.item_id,
        "coin_num": value.fields.coin_num,
        "original_coin_num": value.fields.original_coin_num,
        "item_buy_num": value.fields.item_buy_num,
        "limit_buy_count": value.fields.limit_buy_count,
        "limit_turn": value.fields.limit_turn,
    }


def _decode_free_item_effect(value: SingleModeFreeItemEffectObject) -> dict[str, int]:
    return {
        "use_id": value.fields.use_id,
        "item_id": value.fields.item_id,
        "effect_type": value.fields.effect_type,
        "effect_value_1": value.fields.effect_value_1,
        "effect_value_2": value.fields.effect_value_2,
        "effect_value_3": value.fields.effect_value_3,
        "effect_value_4": value.fields.effect_value_4,
        "begin_turn": value.fields.begin_turn,
        "end_turn": value.fields.end_turn,
    }


def _decode_free_rival_race(value: SingleModeRivalRaceInfoObject) -> dict[str, int]:
    return {"program_id": value.fields.program_id, "chara_id": value.fields.chara_id}


def _decode_free_twinkle_race_npc(value: WorkSingleModeScenarioFreeTwinkleRaceNpcInfoObject) -> dict[str, Any]:
    fields = value.fields
    return {
        "npc_id": fields.npcId.value,
        "chara_id": fields.charaId.value,
        "dress_id": fields.dressId.value,
        "talent_level": fields.talentLevel.value,
        "win_points": fields.winPoints.value,
        "speed": fields.speed.value,
        "stamina": fields.stamina.value,
        "power": fields.power.value,
        "guts": fields.guts.value,
        "wiz": fields.wiz.value,
        "proper_ground_turf": fields.properGroundTurf.value,
        "proper_ground_dirt": fields.properGroundDirt.value,
        "proper_running_style_nige": fields.properRunningStyleNige.value,
        "proper_running_style_senko": fields.properRunningStyleSenko.value,
        "proper_running_style_sashi": fields.properRunningStyleSashi.value,
        "proper_running_style_oikomi": fields.properRunningStyleOikomi.value,
        "proper_distance_short": fields.properDistanceShort.value,
        "proper_distance_mile": fields.properDistanceMile.value,
        "proper_distance_middle": fields.properDistanceMiddle.value,
        "proper_distance_long": fields.properDistanceLong.value,
        "skill_array": [_decode_skill_data_entry(skill.contents) for skill in fields.skillArray if skill],
    }


def _decode_free_npc_result(value: WorkSingleModeScenarioFreeNpcResultObject) -> dict[str, int]:
    return {"npc_id": value.fields.npcId.value, "result_rank": value.fields.resultRank.value}


def _decode_free_twinkle_race_result(value: WorkSingleModeScenarioFreeTwinkleRaceNpcResultObject) -> dict[str, Any]:
    fields = value.fields
    return {
        "turn": fields.turn.value,
        "program_id": fields.programId.value,
        "race_result_array": [
            _decode_free_npc_result(result.contents)
            for result in fields.raceResultList.contents
            if result
        ] if fields.raceResultList else [],
    }


def _decode_active_free_command_info(
        career: WorkSingleModeDataObject,
        home_info: C_Ptr[WorkSingleModeHomeInfoObject],
) -> list[dict[str, Any]]:
    change = career.fields.changeParameterInfo
    if change and (scenario_free_commands := change.contents.fields.scenarioFreeCommandInfo):
        return [
            _decode_free_command_info(command.contents)
            for command in scenario_free_commands.contents
            if command
        ]
    command_info_array: list[dict[str, Any]] = []
    for command_type, command in _iter_active_home_commands(home_info):
        fields = command.fields
        command_info_array.append({
            "command_type": command_type,
            "command_id": fields.commandId.value,
            # ApplyFreeCommandInfo uses the same scenario-bonus dictionary as Team and Live.
            "params_inc_dec_info_array": _decode_active_params_inc_dec_info_array(fields.bonusParamIncDecInfoDic),
        })
    return command_info_array


def _decode_active_free_data_set(
        career: WorkSingleModeDataObject,
        chara: WorkSingleModeCharaDataObject,
        home_info: C_Ptr[WorkSingleModeHomeInfoObject],
) -> dict[str, Any]:
    """Return the observed ``free_data_set`` shape from persistent Climax state."""

    chara_fields = chara.fields
    if not (free_state := chara_fields.workScenarioFree):
        return {}

    free_fields = free_state.contents.fields
    return {
        "shop_id": free_fields.shopId.value,
        "sale_value": free_fields.saleValue.value,
        "win_points": free_fields.winPoints.value,
        "prev_win_points": 0,
        "gained_coin_num": free_fields.gainedCoinNum.value,
        "coin_num": free_fields.coinNum.value,
        "twinkle_race_ranking": free_fields.twinkleRaceRanking.value,
        "user_item_info_array": [
            _decode_free_user_item(item.contents)
            for item in free_fields.userItemInfoArray
            if item
        ],
        "pick_up_item_info_array": [
            _decode_free_pick_up_item(item.contents)
            for item in free_fields.pickUpItemInfoArray
            if item
        ],
        "twinkle_race_npc_info_array": [
            _decode_free_twinkle_race_npc(npc.contents)
            for npc in free_fields.singleModeFreeTwinkleRaceNpcInfoList.contents
            if npc
        ] if free_fields.singleModeFreeTwinkleRaceNpcInfoList else [],
        "item_effect_array": [
            _decode_free_item_effect(effect.contents)
            for effect in free_fields.singleModeFreeItemEffectArray
            if effect
        ] if free_fields.singleModeFreeItemEffectArray else None,
        "twinkle_race_npc_result_array": [
            _decode_free_twinkle_race_result(race_result.contents)
            for race_result in free_fields.singleModeTwikleRaceNpcResultList.contents
            if race_result
        ] if free_fields.singleModeTwikleRaceNpcResultList else [],
        "command_info_array": _decode_active_free_command_info(career, home_info),
        "rival_race_info_array": [
            _decode_free_rival_race(race.contents)
            for race in free_fields.singleModeRivalRaceInfoArray
            if race
        ],
        "unchecked_event_achievement_id": free_fields.uncheckedEventAchievementId.value or None,
    }


def _decode_active_scenario_data_set(
        career: WorkSingleModeDataObject,
        chara: WorkSingleModeCharaDataObject,
) -> dict[str, Any]:
    """Decode the one API scenario extension selected by the authoritative scenario ID."""

    career_fields = career.fields
    chara_fields = chara.fields

    scenario_id = chara_fields.scenarioId.value
    if scenario_id == SingleModeScenarioId.URA:
        return {"ura_data_set": _decode_active_ura_data_set(chara, career_fields.homeInfo)}
    if scenario_id == SingleModeScenarioId.TeamRace:
        return {"team_data_set": _decode_active_team_data_set(chara, career_fields.homeInfo)}
    if scenario_id == SingleModeScenarioId.Live:
        return {"live_data_set": _decode_active_live_data_set(career, chara, career_fields.homeInfo)}
    if scenario_id == SingleModeScenarioId.Free:
        return {"free_data_set": _decode_active_free_data_set(career, chara, career_fields.homeInfo)}
    return {}


def _decode_career_race_context(data: CareerDataExtractionData) -> dict[str, Any]:
    """Decode only sources associated by the extractor with this observation."""
    sources = data.race_sources()
    context: dict[str, Any] = {
        "race_start_info": None,
        "race_scenario": None,
        "race_reward_info": None,
        "add_trophy_info": None,
        "trophy_reward_info": None,
        "prev_chara_grade": None,
        "race_add_reward_info": [],
    }
    if sources is None:
        return context
    start = sources.start.contents.fields
    context["race_start_info"] = {
        "program_id": start.program_id,
        "random_seed": start.random_seed,
        "season": sources.runtime.contents.fields.season if sources.runtime else 0,
        "weather": start.weather,
        "ground_condition": start.ground_condition,
        "race_horse_data": [_decode_career_race_horse(horse.contents) for horse in start.race_horse_data if horse],
        "continue_num": start.continue_num,
        "is_force_running_style": start.is_force_running_style,
    }
    if sources.loaded:
        loaded = sources.loaded.contents.fields
        context["race_scenario"] = loaded.raceScenario.value_or(None)
        if loaded.rewardInfo:
            context["race_reward_info"] = _decode_career_race_reward(loaded.rewardInfo)
            context["prev_chara_grade"] = loaded.prevGradeType
    if sources.runtime:
        runtime = sources.runtime.contents.fields
        if runtime.simDataBase64:
            context["race_scenario"] = runtime.simDataBase64.value_or(None)
        if (reward := _decode_runtime_race_reward(data)) is not None:
            context["race_reward_info"] = reward
            context["prev_chara_grade"] = runtime.prevGradeType
    return context


def _decode_log_substance(entry: SingleModeLogSubstanceObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "chara_id_array": [value.value for value in f.charaIdList.contents] if f.charaIdList else [],
        "name": f.name.value_or(),
        "text": f.text.value_or(),
        "color_text": f.colorText.value_or(),
        "type": {"value": f.logType, "name": f.logType.name},
        "sheet_id": f.sheetId.value_or(),
        "voice_index": f.voiceIndex,
        "selector_label": f.selectorLabel.value_or(),
        "sound_type": {"value": f.soundType, "name": f.soundType.name},
        "is_result": f.isResult,
        "force_set_mob_icon": f.forceSetMobIcon,
        "analyze_result_icon_id": f.analyzeResultIconId,
    }


def decode_career_log(data: CareerDataExtractionData) -> CareerLogObservation | None:
    fields = data.career.fields
    if not (pool_ptr := fields.groupLogPool):
        return None
    pool = pool_ptr.contents.fields
    if not pool.logGroupPool:
        return None
    entries: list[CareerLogEntry] = []
    current_sequence: int | None = None
    for group_ptr in pool.logGroupPool.contents:
        if not group_ptr:
            continue
        group = group_ptr.contents.fields
        if group_ptr.address == pool.currentGroup.address:
            current_sequence = len(entries)
        payload = {
            "type": {"value": group.groupType, "name": group.groupType.name},
            "event_title": group.eventTitle.value_or(),
            "dress_id": group.dressId,
            "gender_id": group.genderId,
            "training_level": group.trainingLev,
            "training_kind": group.trainingKind,
            "support_card_id": group.supportCardId,
            "talker_id": group.talkerId,
        }
        entries.append(CareerLogEntry(group_ptr.address, 0, payload, None))
        if group.substList:
            entries.extend(CareerLogEntry(group_ptr.address, ptr.address, payload, _decode_log_substance(ptr.contents))
                           for ptr in group.substList.contents if ptr)
    cursor = {
        "turn": fields.totalTurnNum.value,
        "playing_state": SingleModePlayingState(fields.playingState.value).name,
        "current_group_window_index": current_sequence,
        "event_contents_type": {"value": pool.currentEventInfoType, "name": pool.currentEventInfoType.name},
        "event_title": pool.eventTitleName.value_or(),
    }
    return CareerLogObservation(pool_ptr.address, fields.totalTurnNum.value, fields.playingState.value,
                                cursor, tuple(entries))


def decode_career_data(data: CareerDataExtractionData) -> dict[str, Any]:
    """Decode an API-shaped active-career snapshot from reflected work state.

    Each section is built once, retaining observed keys and typed placeholders
    for unavailable sources. Account/event state deliberately remains empty.
    """
    career = data.career
    fields = career.fields
    chara = fields.character.contents
    chara_fields = chara.fields
    training_levels = _decode_active_training_levels(chara)
    common: dict[str, Any] = {
        "chara_info": _decode_active_chara_info(
                chara,
                turn=fields.totalTurnNum.value,
                state=fields.state.value,
                playing_state=fields.playingState.value,
                training_levels=training_levels,
        ),
        "race_condition_array": _decode_active_race_conditions(fields.raceConditions),
        "race_random_program_array": (
            _decode_active_race_random_program_array(chara)
            if chara_fields.scenarioId.value != SingleModeScenarioId.TeamRace else None
        ),
        "home_info": _decode_active_home_info(fields.homeInfo, training_levels),
        "unchecked_event_array": _decode_pending_events(career),
        "race_history": _decode_active_race_history(fields.raceHistoryInfoList),
        "win_saddle_id_array": _decode_active_win_saddle_ids(fields.winSaddleArray),
        "effected_factor_array": _decode_active_effected_factor_array(chara_fields.successionFactor),
        **_decode_career_race_context(data),
        "reserved_race_array": _decode_reserved_races(chara),
        "mission_list": [],
        "story_event_mission_list": [],
        "story_event_chara_bonus_list": [],
        "start_dress_info": [],
        "resume_factor_select": _decode_resume_factor_select(career),
    }

    payload = {"single_mode_load_common": common}
    payload.update(_decode_active_scenario_data_set(career, chara))
    return payload
