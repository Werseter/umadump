from __future__ import annotations

from ctypes import c_bool, c_int32, c_int64
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Bool, C_Enum, C_EnumIn, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr, GenericDictionary, GenericList
from game_structs.enums import (CharaGradeType, ProperGrade, RaceMotivation, RoundResultType, RunningStyle,
                                SingleModeCommandType, SingleModeEventPlayTiming, SingleModeParameterType,
                                SingleModePlayingState, SingleModeState, TeamEditFlag, TeamParameterRank,
                                TrainingCommandId)
from game_structs.master_data import MasterSingleModeWinsSaddleSingleModeWinsSaddleObject
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredLong, ObscuredStringPtr
from game_structs.race import CharaRaceRewardObject, RaceHorseDataObject, SingleRaceStartInfoObject
from game_structs.skills import AcquiredSkillObject, SkillDataObject, SkillTipsObject
from game_structs.strings import SystemStringObjectPtr
from game_structs.trained_chara import FactorInfoObject, RaceHistoryInfoObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.SingleModeSupportCard
# ---------------------------------------------------------------------------

class SingleModeSupportCardFields(CStructureDataclass):
    position: C_Int[c_int32]
    support_card_id: C_Int[c_int32]
    limit_break_count: C_Int[c_int32]
    exp: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: training_partner_state
    owner_viewer_id: C_Int[c_int64]
    _ignored_2: c_int32  # omitted: rental_type


@register_runtime_validatable('Gallop::SingleModeSupportCard')
class SingleModeSupportCardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeSupportCardFields


# ---------------------------------------------------------------------------
# Gallop.GroupOutingInfo
# ---------------------------------------------------------------------------

class GroupOutingInfoFields(CStructureDataclass):
    chara_id: C_Int[c_int32]
    is_outing: C_Int[c_int32]
    story_step: C_Int[c_int32]


@register_runtime_validatable('Gallop::GroupOutingInfo')
class GroupOutingInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GroupOutingInfoFields


# ---------------------------------------------------------------------------
# Gallop.EvaluationInfo
# ---------------------------------------------------------------------------

class EvaluationInfoFields(CStructureDataclass):
    target_id: C_Int[c_int32]
    evaluation: C_Int[c_int32]
    is_outing: C_Int[c_int32]
    story_step: C_Int[c_int32]
    is_appear: C_Int[c_int32]
    group_outing_info_array: GenericArrayPtr[C_Ptr[GroupOutingInfoObject]]


@register_runtime_validatable('Gallop::EvaluationInfo')
class EvaluationInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: EvaluationInfoFields


# ---------------------------------------------------------------------------
# Gallop.TrainingLevelInfo
# ---------------------------------------------------------------------------

class TrainingLevelInfoFields(CStructureDataclass):
    command_id: C_Int[c_int32]
    level: C_Int[c_int32]


@register_runtime_validatable('Gallop::TrainingLevelInfo')
class TrainingLevelInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainingLevelInfoFields


# ---------------------------------------------------------------------------
# Gallop.GuestOutingInfo
# ---------------------------------------------------------------------------

class GuestOutingInfoFields(CStructureDataclass):
    support_card_id: C_Int[c_int32]
    story_step: C_Int[c_int32]
    group_outing_info_array: GenericArrayPtr[C_Ptr[GroupOutingInfoObject]]


@register_runtime_validatable('Gallop::GuestOutingInfo')
class GuestOutingInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GuestOutingInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeSkillUpgrade
# ---------------------------------------------------------------------------

class SingleModeSkillUpgradeFields(CStructureDataclass):
    condition_id: C_Int[c_int32]
    total_count: C_Int[c_int32]
    current_count: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeSkillUpgrade')
class SingleModeSkillUpgradeObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeSkillUpgradeFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeChara
# ---------------------------------------------------------------------------

class SingleModeCharaFields(CStructureDataclass):
    single_mode_chara_id: C_Int[c_int32]
    card_id: C_Int[c_int32]
    chara_grade: C_Int[c_int32]
    speed: C_Int[c_int32]
    stamina: C_Int[c_int32]
    power: C_Int[c_int32]
    wiz: C_Int[c_int32]
    guts: C_Int[c_int32]
    vital: C_Int[c_int32]
    max_speed: C_Int[c_int32]
    max_stamina: C_Int[c_int32]
    max_power: C_Int[c_int32]
    max_wiz: C_Int[c_int32]
    max_guts: C_Int[c_int32]
    default_max_speed: C_Int[c_int32]
    default_max_stamina: C_Int[c_int32]
    default_max_power: C_Int[c_int32]
    default_max_wiz: C_Int[c_int32]
    default_max_guts: C_Int[c_int32]
    max_vital: C_Int[c_int32]
    motivation: C_Int[c_int32]
    fans: C_Int[c_int32]
    rarity: C_Int[c_int32]
    race_program_id: C_Int[c_int32]
    reserve_race_program_id: C_Int[c_int32]
    race_running_style: C_Int[c_int32]
    is_short_race: C_Int[c_int32]
    talent_level: C_Int[c_int32]
    skill_array: GenericArrayPtr[C_Ptr[SkillDataObject]]
    disable_skill_id_array: GenericArrayPtr[c_int32]
    skill_tips_array: GenericArrayPtr[C_Ptr[SkillTipsObject]]
    support_card_array: GenericArrayPtr[C_Ptr[SingleModeSupportCardObject]]
    succession_trained_chara_id_1: C_Int[c_int32]
    succession_trained_chara_id_2: C_Int[c_int32]
    proper_distance_short: C_Int[c_int32]
    proper_distance_mile: C_Int[c_int32]
    proper_distance_middle: C_Int[c_int32]
    proper_distance_long: C_Int[c_int32]
    proper_running_style_nige: C_Int[c_int32]
    proper_running_style_senko: C_Int[c_int32]
    proper_running_style_sashi: C_Int[c_int32]
    proper_running_style_oikomi: C_Int[c_int32]
    proper_ground_turf: C_Int[c_int32]
    proper_ground_dirt: C_Int[c_int32]
    turn: C_Int[c_int32]
    skill_point: C_Int[c_int32]
    short_cut_state: C_Int[c_int32]
    state: C_Int[c_int32]
    playing_state: C_Int[c_int32]
    scenario_id: C_Int[c_int32]
    route_id: C_Int[c_int32]
    start_time: SystemStringObjectPtr
    evaluation_info_array: GenericArrayPtr[C_Ptr[EvaluationInfoObject]]
    training_level_info_array: GenericArrayPtr[C_Ptr[TrainingLevelInfoObject]]
    nickname_id_array: GenericArrayPtr[c_int32]
    chara_effect_id_array: GenericArrayPtr[c_int32]
    route_race_id_array: GenericArrayPtr[c_int32]
    guest_outing_info_array: GenericArrayPtr[C_Ptr[GuestOutingInfoObject]]
    skill_upgrade_info_array: GenericArrayPtr[C_Ptr[SingleModeSkillUpgradeObject]]


@register_runtime_validatable('Gallop::SingleModeChara')
class SingleModeCharaObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeCharaFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.Evaluation.GroupOutingInfo
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataGroupOutingInfoFields(CStructureDataclass):
    charaId: ObscuredInt
    isOuting: ObscuredBool
    storyStep: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeCharaData.Evaluation.GroupOutingInfo')
class WorkSingleModeCharaDataGroupOutingInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeCharaDataGroupOutingInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.Evaluation
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataEvaluationFields(CStructureDataclass):
    targetId: ObscuredInt
    value: ObscuredInt
    isOuting: ObscuredBool
    storyStep: ObscuredInt
    isAppear: ObscuredBool
    groupOutingInfoList: C_Ptr[GenericList[C_Ptr[WorkSingleModeCharaDataGroupOutingInfoObject]]]
    guestCharaId: ObscuredInt
    interestState: ObscuredInt
    soulEventState: ObscuredInt
    soulThresholdId: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeCharaData.Evaluation')
class WorkSingleModeCharaDataEvaluationObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeCharaDataEvaluationFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.EquipSupportCard
# ---------------------------------------------------------------------------

class EquipSupportCardFields(CStructureDataclass):
    position: ObscuredInt
    supportCardId: ObscuredInt
    limitBreakCount: ObscuredInt
    exp: ObscuredInt
    _ignored_1: c_int32  # omitted: rentalType


@register_runtime_validatable('Gallop::WorkSingleModeCharaData.EquipSupportCard')
class EquipSupportCardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: EquipSupportCardFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.SkillTips
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataSkillTipsFields(CStructureDataclass):
    groupId: ObscuredInt
    rarity: ObscuredInt
    level: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeCharaData.SkillTips')
class WorkSingleModeCharaDataSkillTipsObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeCharaDataSkillTipsFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.SuccessionFactorInfo.Info
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataSuccessionFactorInfoInfoFields(CStructureDataclass):
    position: ObscuredInt
    factorIdList: C_Ptr[GenericList[ObscuredInt]]


@register_runtime_validatable('Gallop::WorkSingleModeCharaData.SuccessionFactorInfo.Info')
class WorkSingleModeCharaDataSuccessionFactorInfoInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeCharaDataSuccessionFactorInfoInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.SuccessionFactorInfo
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataSuccessionFactorInfoFields(CStructureDataclass):
    infoList: C_Ptr[GenericList[C_Ptr[WorkSingleModeCharaDataSuccessionFactorInfoInfoObject]]]


@register_runtime_validatable('Gallop::WorkSingleModeCharaData.SuccessionFactorInfo')
class WorkSingleModeCharaDataSuccessionFactorInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeCharaDataSuccessionFactorInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.TrainingLevelDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataTrainingLevelDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Enum[TrainingCommandId]
    value: C_Int[c_int32]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData.SuccessionCharaInfo
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataSuccessionCharaInfoFields(CStructureDataclass):
    trainedCharaId: ObscuredInt
    _ignored_1: ObscuredInt  # omitted: changedModelDressId


@register_runtime_validatable('Gallop::WorkSingleModeCharaData.SuccessionCharaInfo')
class WorkSingleModeCharaDataSuccessionCharaInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeCharaDataSuccessionCharaInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeRaceData.LotteryProgramData
# ---------------------------------------------------------------------------

class WorkSingleModeRaceDataLotteryProgramDataFields(CStructureDataclass):
    programId: ObscuredInt
    turn: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeRaceData.LotteryProgramData')
class WorkSingleModeRaceDataLotteryProgramDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeRaceDataLotteryProgramDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeRaceData.LotteryProgramDataDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeRaceDataLotteryProgramDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Int[c_int32]
    value: C_Ptr[GenericList[C_Ptr[WorkSingleModeRaceDataLotteryProgramDataObject]]]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeRaceData
# ---------------------------------------------------------------------------

class WorkSingleModeRaceDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: character, cachePrograms
    lotteryProgramDataDict: C_Ptr[GenericDictionary[WorkSingleModeRaceDataLotteryProgramDataDictionaryEntry]]


@register_runtime_validatable('Gallop::WorkSingleModeRaceData')
class WorkSingleModeRaceDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeRaceDataFields


# ---------------------------------------------------------------------------
# Gallop.LiveEvaluationInfo
# ---------------------------------------------------------------------------

class LiveEvaluationInfoFields(CStructureDataclass):
    target_id: C_Int[c_int32]
    chara_id: C_Int[c_int32]
    member_state: C_Int[c_int32]


@register_runtime_validatable('Gallop::LiveEvaluationInfo')
class LiveEvaluationInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: LiveEvaluationInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioLive.PerformanceData
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioLivePerformanceDataFields(CStructureDataclass):
    vocal: ObscuredInt
    passion: ObscuredInt
    dance: ObscuredInt
    visual: ObscuredInt
    mental: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeScenarioLive.PerformanceData')
class WorkSingleModeScenarioLivePerformanceDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioLivePerformanceDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioLive.TreeSquareInfo
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioLiveTreeSquareInfoFields(CStructureDataclass):
    squareId: ObscuredInt
    squareNum: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeScenarioLive.TreeSquareInfo')
class WorkSingleModeScenarioLiveTreeSquareInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioLiveTreeSquareInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioLive.TrainingBonus
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioLiveTrainingBonusFields(CStructureDataclass):
    parameterType: C_Enum[SingleModeParameterType]
    value: C_Int[c_int32]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioLive.TrainingBonus')
class WorkSingleModeScenarioLiveTrainingBonusObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioLiveTrainingBonusFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioLive.LiveResultData
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioLiveLiveResultDataFields(CStructureDataclass):
    liveType: ObscuredInt
    result: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeScenarioLive.LiveResultData')
class WorkSingleModeScenarioLiveLiveResultDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioLiveLiveResultDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioLive
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioLiveFields(CStructureDataclass):
    nextMusicIdArray: GenericArrayPtr[ObscuredInt]
    totalMusicIdArray: GenericArrayPtr[ObscuredInt]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: nextLiveBonusEffect, currentLiveBonusEffect
    currentLiveBonusMusicIdArray: GenericArrayPtr[ObscuredInt]
    treeSquareInfoArray: GenericArrayPtr[C_Ptr[WorkSingleModeScenarioLiveTreeSquareInfoObject]]
    reservedTreeSquareId: ObscuredInt
    trainingBonusArray: GenericArrayPtr[C_Ptr[WorkSingleModeScenarioLiveTrainingBonusObject]]
    performance: C_Ptr[WorkSingleModeScenarioLivePerformanceDataObject]
    performanceMax: C_Ptr[WorkSingleModeScenarioLivePerformanceDataObject]
    evaluationInfoList: C_Ptr[GenericList[C_Ptr[LiveEvaluationInfoObject]]]
    liveResultList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioLiveLiveResultDataObject]]]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioLive')
class WorkSingleModeScenarioLiveObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioLiveFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioTeamRace.TeamMember
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioTeamRaceTeamMemberFields(CStructureDataclass):
    charaId: ObscuredInt
    _ignored_1: C_UDeclPtr  # omitted: masterScoutChara
    speed: ObscuredInt
    stamina: ObscuredInt
    power: ObscuredInt
    guts: ObscuredInt
    wiz: ObscuredInt
    speedLimit: ObscuredInt
    staminaLimit: ObscuredInt
    powerLimit: ObscuredInt
    gutsLimit: ObscuredInt
    wizLimit: ObscuredInt
    rankScore: ObscuredInt
    speedLimitBase: ObscuredInt
    staminaLimitBase: ObscuredInt
    powerLimitBase: ObscuredInt
    gutsLimitBase: ObscuredInt
    wizLimitBase: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeScenarioTeamRace.TeamMember')
class WorkSingleModeScenarioTeamRaceTeamMemberObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioTeamRaceTeamMemberFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioTeamRace.DeckData
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioTeamRaceDeckDataFields(CStructureDataclass):
    distanceType: ObscuredInt
    memberId: ObscuredInt
    charaId: ObscuredInt
    runningStyle: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeScenarioTeamRace.DeckData')
class WorkSingleModeScenarioTeamRaceDeckDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioTeamRaceDeckDataFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeTeamRandomInfo
# ---------------------------------------------------------------------------

class SingleModeTeamRandomInfoFields(CStructureDataclass):
    team_race_set_id: C_Int[c_int32]
    member_id: C_Int[c_int32]
    chara_id: C_Int[c_int32]
    npc_id: C_Int[c_int32]
    running_style: C_Int[c_int32]
    frame_order: C_Int[c_int32]
    motivation: C_Int[c_int32]
    stamina: C_Int[c_int32]
    speed: C_Int[c_int32]
    pow: C_Int[c_int32]
    guts: C_Int[c_int32]
    wiz: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeTeamRandomInfo')
class SingleModeTeamRandomInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeTeamRandomInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeNpcTeamData
# ---------------------------------------------------------------------------

class SingleModeNpcTeamDataFields(CStructureDataclass):
    distance_type: C_Int[c_int32]
    member_id: C_Int[c_int32]
    base_npc_id: C_Int[c_int32]
    npc_id: C_Int[c_int32]
    running_style: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeNpcTeamData')
class SingleModeNpcTeamDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeNpcTeamDataFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeTeamRaceHistory
# ---------------------------------------------------------------------------

class SingleModeTeamRaceHistoryFields(CStructureDataclass):
    race_num: C_Int[c_int32]
    turn: C_Int[c_int32]
    team_race_set_id: C_Int[c_int32]
    result_state: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeTeamRaceHistory')
class SingleModeTeamRaceHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeTeamRaceHistoryFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeTeamFrameOrder
# ---------------------------------------------------------------------------

class SingleModeTeamFrameOrderFields(CStructureDataclass):
    distance_type: C_Int[c_int32]
    race_order: C_Int[c_int32]
    random_info_array: GenericArrayPtr[C_Ptr[SingleModeTeamRandomInfoObject]]


@register_runtime_validatable('Gallop::SingleModeTeamFrameOrder')
class SingleModeTeamFrameOrderObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeTeamFrameOrderFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeTeamOpponentList
# ---------------------------------------------------------------------------

class SingleModeTeamOpponentListFields(CStructureDataclass):
    team_race_set_id: C_Int[c_int32]
    team_power: C_Int[c_int32]
    team_rank: C_Int[c_int32]
    team_data_array: GenericArrayPtr[C_Ptr[SingleModeNpcTeamDataObject]]
    win_up_rank: C_Int[c_int32]
    lose_down_rank: C_Int[c_int32]
    draw_rank: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeTeamOpponentList')
class SingleModeTeamOpponentListObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeTeamOpponentListFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeTeamEventEffectInfo
# ---------------------------------------------------------------------------

class SingleModeTeamEventEffectInfoFields(CStructureDataclass):
    is_summarize_team_member: C_Bool[c_bool]
    gain_speed: C_Int[c_int32]
    gain_stamina: C_Int[c_int32]
    gain_power: C_Int[c_int32]
    gain_guts: C_Int[c_int32]
    gain_wiz: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeTeamEventEffectInfo')
class SingleModeTeamEventEffectInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeTeamEventEffectInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeTeamRaceCharaResult
# ---------------------------------------------------------------------------

class SingleModeTeamRaceCharaResultFields(CStructureDataclass):
    frame_order: C_Int[c_int32]
    chara_id: C_Int[c_int32]
    npc_id: C_Int[c_int32]
    team_id: C_Int[c_int32]
    finish_order: C_Int[c_int32]
    finish_time: C_Int[c_int32]
    popularity: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeTeamRaceCharaResult')
class SingleModeTeamRaceCharaResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeTeamRaceCharaResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioTeamRace.SingleTeamRaceResult
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioTeamRaceSingleTeamRaceResultFields(CStructureDataclass):
    raceNum: ObscuredInt
    round: ObscuredInt
    raceInstanceId: ObscuredInt
    weather: ObscuredInt
    season: ObscuredInt
    groundCondition: ObscuredInt
    randomSeed: ObscuredInt
    raceScenario: ObscuredStringPtr
    roundResult: C_Enum[RoundResultType]
    continueNum: ObscuredInt
    charaResultArray: GenericArrayPtr[C_Ptr[SingleModeTeamRaceCharaResultObject]]
    raceHorseData: GenericArrayPtr[C_Ptr[RaceHorseDataObject]]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioTeamRace.SingleTeamRaceResult')
class WorkSingleModeScenarioTeamRaceSingleTeamRaceResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioTeamRaceSingleTeamRaceResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioTeamRace.SoulSkillInfo
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioTeamRaceSoulSkillInfoFields(CStructureDataclass):
    skillTips: GenericArrayPtr[C_Ptr[SkillTipsObject]]
    notUpSkillTips: GenericArrayPtr[C_Ptr[SkillTipsObject]]
    notGetSkill: GenericArrayPtr[c_int32]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioTeamRace.SoulSkillInfo')
class WorkSingleModeScenarioTeamRaceSoulSkillInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioTeamRaceSoulSkillInfoFields


class TeamSoulSkillDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Int[c_int32]
    value: C_Ptr[WorkSingleModeScenarioTeamRaceSoulSkillInfoObject]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioTeamRace
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioTeamRaceFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # omitted: teamName
    teamNameId: C_Int[c_int32]
    finalWinType: C_Enum[RoundResultType]
    _ignored_2: c_bool  # omitted: isBossBattle
    _ignored_3: ObscuredInt  # omitted: addMusicId
    teamParameterRankSpeed: C_Enum[TeamParameterRank]
    teamParameterRankStamina: C_Enum[TeamParameterRank]
    teamParameterRankPower: C_Enum[TeamParameterRank]
    teamParameterRankGuts: C_Enum[TeamParameterRank]
    teamParameterRankWiz: C_Enum[TeamParameterRank]
    guidePartnerCount: C_Int[c_int32]
    isScoutEnable: C_Bool[c_bool]
    teamTotalPower: ObscuredInt
    teamRanking: ObscuredInt
    _ignored_4: C_UDeclPtr  # omitted: teamHonorName
    teamHonorId: ObscuredInt
    teamMemberList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioTeamRaceTeamMemberObject]]]
    deckDataList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioTeamRaceDeckDataObject]]]
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # omitted: teamRaceDeckTeamMemberList, runRaceDeckDataList
    _ignored_6: c_int32  # omitted: selectedTeamRaceSetId
    singleTeamResultList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioTeamRaceSingleTeamRaceResultObject]]]
    teamFrameOrderArray: GenericArrayPtr[C_Ptr[SingleModeTeamFrameOrderObject]]
    opponentListArray: GenericArrayPtr[C_Ptr[SingleModeTeamOpponentListObject]]
    _ignored_7: C_UDeclPtr  # omitted: selectedOpponent
    teamEventEffectInfo: C_Ptr[SingleModeTeamEventEffectInfoObject]
    teamRaceHistoryArray: GenericArrayPtr[C_Ptr[SingleModeTeamRaceHistoryObject]]
    skillTipsArray: GenericArrayPtr[C_Ptr[SkillTipsObject]]
    soulSkillTipsDictionary: C_Ptr[GenericDictionary[TeamSoulSkillDictionaryEntry]]
    spSoulSkillTipsDictionary: C_Ptr[GenericDictionary[TeamSoulSkillDictionaryEntry]]
    _ignored_8: C_UDeclPtr  # omitted: deckBuilder
    _ignored_9: ArrayType[c_int32, L[2]]  # omitted: playerMemberCount, gameQuality
    teamEditFlag: C_Enum[TeamEditFlag]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioTeamRace')
class WorkSingleModeScenarioTeamRaceObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioTeamRaceFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeParamsIncDecInfo
# ---------------------------------------------------------------------------

class SingleModeParamsIncDecInfoFields(CStructureDataclass):
    target_type: C_Int[c_int32]
    value: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeParamsIncDecInfo')
class SingleModeParamsIncDecInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeParamsIncDecInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeFreeCommandInfo
# ---------------------------------------------------------------------------

class SingleModeFreeCommandInfoFields(CStructureDataclass):
    command_type: C_Int[c_int32]
    command_id: C_Int[c_int32]
    params_inc_dec_info_array: GenericArrayPtr[C_Ptr[SingleModeParamsIncDecInfoObject]]


@register_runtime_validatable('Gallop::SingleModeFreeCommandInfo')
class SingleModeFreeCommandInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeFreeCommandInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeFreeUserItem
# ---------------------------------------------------------------------------

class SingleModeFreeUserItemFields(CStructureDataclass):
    item_id: C_Int[c_int32]
    num: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeFreeUserItem')
class SingleModeFreeUserItemObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeFreeUserItemFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeFreePickUpItem
# ---------------------------------------------------------------------------

class SingleModeFreePickUpItemFields(CStructureDataclass):
    shop_item_id: C_Int[c_int32]
    item_id: C_Int[c_int32]
    coin_num: C_Int[c_int32]
    original_coin_num: C_Int[c_int32]
    item_buy_num: C_Int[c_int32]
    limit_buy_count: C_Int[c_int32]
    limit_turn: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeFreePickUpItem')
class SingleModeFreePickUpItemObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeFreePickUpItemFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeFreeItemEffect
# ---------------------------------------------------------------------------

class SingleModeFreeItemEffectFields(CStructureDataclass):
    use_id: C_Int[c_int32]
    item_id: C_Int[c_int32]
    effect_type: C_Int[c_int32]
    effect_value_1: C_Int[c_int32]
    effect_value_2: C_Int[c_int32]
    effect_value_3: C_Int[c_int32]
    effect_value_4: C_Int[c_int32]
    begin_turn: C_Int[c_int32]
    end_turn: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeFreeItemEffect')
class SingleModeFreeItemEffectObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeFreeItemEffectFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeRivalRaceInfo
# ---------------------------------------------------------------------------

class SingleModeRivalRaceInfoFields(CStructureDataclass):
    program_id: C_Int[c_int32]
    chara_id: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeRivalRaceInfo')
class SingleModeRivalRaceInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeRivalRaceInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioFree.SingleModeFreeTwinkleRaceNpcInfo
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioFreeTwinkleRaceNpcInfoFields(CStructureDataclass):
    npcId: ObscuredInt
    charaId: ObscuredInt
    dressId: ObscuredInt
    talentLevel: ObscuredInt
    winPoints: ObscuredInt
    speed: ObscuredInt
    stamina: ObscuredInt
    power: ObscuredInt
    guts: ObscuredInt
    wiz: ObscuredInt
    properDistanceShort: ObscuredInt
    properDistanceMile: ObscuredInt
    properDistanceMiddle: ObscuredInt
    properDistanceLong: ObscuredInt
    properRunningStyleNige: ObscuredInt
    properRunningStyleSenko: ObscuredInt
    properRunningStyleSashi: ObscuredInt
    properRunningStyleOikomi: ObscuredInt
    properGroundTurf: ObscuredInt
    properGroundDirt: ObscuredInt
    skillArray: GenericArrayPtr[C_Ptr[SkillDataObject]]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioFree.SingleModeFreeTwinkleRaceNpcInfo')
class WorkSingleModeScenarioFreeTwinkleRaceNpcInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioFreeTwinkleRaceNpcInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioFree.SingleModeNpcResult
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioFreeNpcResultFields(CStructureDataclass):
    npcId: ObscuredInt
    resultRank: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeScenarioFree.SingleModeNpcResult')
class WorkSingleModeScenarioFreeNpcResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioFreeNpcResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioFree.SingleModeTwikleRaceNpcResult
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioFreeTwinkleRaceNpcResultFields(CStructureDataclass):
    turn: ObscuredInt
    programId: ObscuredInt
    raceResultList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioFreeNpcResultObject]]]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioFree.SingleModeTwikleRaceNpcResult')
class WorkSingleModeScenarioFreeTwinkleRaceNpcResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioFreeTwinkleRaceNpcResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioFree
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioFreeFields(CStructureDataclass):
    coinNum: ObscuredInt
    gainedCoinNum: ObscuredInt
    userItemInfoArray: GenericArrayPtr[C_Ptr[SingleModeFreeUserItemObject]]
    shopId: ObscuredInt
    saleValue: ObscuredInt
    pickUpItemInfoArray: GenericArrayPtr[C_Ptr[SingleModeFreePickUpItemObject]]
    singleModeFreeItemEffectArray: GenericArrayPtr[C_Ptr[SingleModeFreeItemEffectObject]]
    winPoints: ObscuredInt
    singleModeRivalRaceInfoArray: GenericArrayPtr[C_Ptr[SingleModeRivalRaceInfoObject]]
    twinkleRaceRanking: ObscuredInt
    singleModeFreeTwinkleRaceNpcInfoList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioFreeTwinkleRaceNpcInfoObject]]]
    _ignored_1: C_UDeclPtr  # omitted: tempSingleModeFreeTwinkleRaceNpcInfoList
    singleModeTwikleRaceNpcResultList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioFreeTwinkleRaceNpcResultObject]]]
    _ignored_2: C_UDeclPtr  # omitted: lastCheckWinptNoticeTurn
    _ignored_3: ObscuredInt  # omitted: lastShopOpenTurn
    uncheckedEventAchievementId: ObscuredInt
    _ignored_4: c_int32  # omitted: lastTrainingEffectValue


@register_runtime_validatable('Gallop::WorkSingleModeScenarioFree')
class WorkSingleModeScenarioFreeObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioFreeFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioURA
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioURAFields(CStructureDataclass):
    versusLevel: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeScenarioURA')
class WorkSingleModeScenarioURAObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioURAFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeChangeParameterInfo
# ---------------------------------------------------------------------------

class WorkSingleModeChangeParameterInfoFields(CStructureDataclass):
    _ignored_1: ArrayType[ObscuredInt, L[15]]  # omitted: speed … maxHp
    _ignored_2: ArrayType[C_UDeclPtr, L[10]]  # omitted: properGroundTurf … properRunStyleOikomi
    _ignored_3: ObscuredInt  # omitted: charaGrade
    _ignored_4: ArrayType[C_UDeclPtr, L[17]]  # omitted: disableCommandIdList … appearCharaIdList
    _ignored_5: ArrayType[ObscuredInt, L[2]]  # omitted: deletedRouteRaceId, forcedRunStyle
    _ignored_6: ArrayType[C_UDeclPtr, L[16]]  # omitted: limitStatusTypeList … teamRaceLeaveMemberList
    _ignored_7: ArrayType[ObscuredInt, L[2]]  # omitted: teamRaceRankingUp, teamRaceRankingDown
    _ignored_8: C_UDeclPtr  # omitted: teamRaceTeamStatusUpDictionary
    _ignored_9: ObscuredInt  # omitted: teamRaceTotalPower
    _ignored_10: ArrayType[C_UDeclPtr, L[2]]  # omitted: scenarioFreeUseItemIdList, scenarioFreeEventShopItemAddList
    _ignored_11: ObscuredInt  # omitted: tscRankingUpDown
    scenarioFreeCommandInfo: C_Ptr[GenericList[C_Ptr[SingleModeFreeCommandInfoObject]]]
    performance: C_Ptr[WorkSingleModeScenarioLivePerformanceDataObject]
    performanceMax: C_Ptr[WorkSingleModeScenarioLivePerformanceDataObject]
    limitPerformanceTypeList: C_Ptr[GenericList[ObscuredInt]]
    _ignored_12: ObscuredInt  # omitted: liveGetMusicId
    _ignored_13: ArrayType[C_UDeclPtr, L[2]]  # omitted: liveMemberJoinCharaIdList, scenarioVenusSpiritInfoList
    _ignored_14: ArrayType[ObscuredBool, L[2]]  # omitted: appearVenus, scenarioVenusUsedSpirit
    _ignored_15: ObscuredInt  # omitted: scenarioVenusInfoLevelUp


@register_runtime_validatable('Gallop::WorkSingleModeChangeParameterInfo')
class WorkSingleModeChangeParameterInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeChangeParameterInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeReservedRace
# ---------------------------------------------------------------------------

class SingleModeReservedRaceFields(CStructureDataclass):
    year: C_Int[c_int32]
    program_id: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeReservedRace')
class SingleModeReservedRaceObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeReservedRaceFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeReservedRaceDeck
# ---------------------------------------------------------------------------

class SingleModeReservedRaceDeckFields(CStructureDataclass):
    deck_num: C_Int[c_int32]
    deck_name: SystemStringObjectPtr
    race_array: GenericArrayPtr[C_Ptr[SingleModeReservedRaceObject]]


@register_runtime_validatable('Gallop::SingleModeReservedRaceDeck')
class SingleModeReservedRaceDeckObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeReservedRaceDeckFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeRaceReserveDeckEntity
# ---------------------------------------------------------------------------

class SingleModeRaceReserveDeckEntityFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # omitted: reserveDict … programIdGetter
    deckInfo: C_Ptr[SingleModeReservedRaceDeckObject]
    _ignored_2: c_int32  # omitted: deckIndex
    _ignored_3: C_UDeclPtr  # omitted: deckName
    _ignored_4: c_int32  # omitted: reservedRaceCount


@register_runtime_validatable('Gallop::SingleModeRaceReserveDeckEntity')
class SingleModeRaceReserveDeckEntityObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeRaceReserveDeckEntityFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeRaceReserveRepository
# ---------------------------------------------------------------------------

class SingleModeRaceReserveRepositoryFields(CStructureDataclass):
    entities: GenericArrayPtr[C_Ptr[SingleModeRaceReserveDeckEntityObject]]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: conditionalProgramIdGetter, onUpdateEvent


@register_runtime_validatable('Gallop::SingleModeRaceReserveRepository')
class SingleModeRaceReserveRepositoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeRaceReserveRepositoryFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeRaceReserve.Context
# ---------------------------------------------------------------------------

class SingleModeRaceReserveContextFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # omitted: entryViewModel
    reserveRepository: C_Ptr[SingleModeRaceReserveRepositoryObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[6]]  # omitted: turnRepository … temp


@register_runtime_validatable('Gallop.SingleModeRaceReserve::Context')
class SingleModeRaceReserveContextObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeRaceReserveContextFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeCharaData
# ---------------------------------------------------------------------------

class WorkSingleModeCharaDataFields(CStructureDataclass):
    id: ObscuredInt
    cardId: ObscuredInt
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: cardData, cardRarityData
    successionTrainedCharaInfoFirst: C_Ptr[WorkSingleModeCharaDataSuccessionCharaInfoObject]
    successionTrainedCharaInfoSecond: C_Ptr[WorkSingleModeCharaDataSuccessionCharaInfoObject]
    talentLevel: ObscuredInt
    limitBreakCount: ObscuredInt
    _ignored_2: ObscuredInt  # omitted: saveNickNameId
    acquiredNickNameIdArray: GenericArrayPtr[ObscuredInt]
    equipSupportCardArray: GenericArrayPtr[C_Ptr[EquipSupportCardObject]]
    charaGrade: ObscuredInt
    _ignored_3: ObscuredInt  # omitted: changedModelDressId
    hp: ObscuredInt
    maxHp: ObscuredInt
    speed: ObscuredInt
    stamina: ObscuredInt
    power: ObscuredInt
    guts: ObscuredInt
    wiz: ObscuredInt
    maxSpeed: ObscuredInt
    maxStamina: ObscuredInt
    maxPower: ObscuredInt
    maxGuts: ObscuredInt
    maxWiz: ObscuredInt
    defaultMaxSpeed: ObscuredInt
    defaultMaxStamina: ObscuredInt
    defaultMaxPower: ObscuredInt
    defaultMaxGuts: ObscuredInt
    defaultMaxWiz: ObscuredInt
    entryProgramId: ObscuredInt
    scenarioId: ObscuredInt
    _ignored_4: ArrayType[ObscuredInt, L[2]]  # omitted: difficultyId, difficulty
    _ignored_5: ObscuredBool  # omitted: isDifficultyTpBoost
    routeId: ObscuredInt
    startTime: ObscuredStringPtr
    _ignored_6: c_int32  # omitted: trainingEventType
    acquiredSkillList: C_Ptr[GenericList[C_Ptr[AcquiredSkillObject]]]
    disableSkillIdList: C_Ptr[GenericList[ObscuredInt]]
    skillTipsList: C_Ptr[GenericList[C_Ptr[WorkSingleModeCharaDataSkillTipsObject]]]
    skillPoint: ObscuredInt
    trainingLevelDic: C_Ptr[GenericDictionary[WorkSingleModeCharaDataTrainingLevelDictionaryEntry]]
    properDistanceShort: C_EnumIn[ProperGrade, ObscuredInt]
    properDistanceMile: C_EnumIn[ProperGrade, ObscuredInt]
    properDistanceMiddle: C_EnumIn[ProperGrade, ObscuredInt]
    properDistanceLong: C_EnumIn[ProperGrade, ObscuredInt]
    properRunningStyleNige: C_EnumIn[ProperGrade, ObscuredInt]
    properRunningStyleSenko: C_EnumIn[ProperGrade, ObscuredInt]
    properRunningStyleSashi: C_EnumIn[ProperGrade, ObscuredInt]
    properRunningStyleOikomi: C_EnumIn[ProperGrade, ObscuredInt]
    properGroundTurf: C_EnumIn[ProperGrade, ObscuredInt]
    properGroundDirt: C_EnumIn[ProperGrade, ObscuredInt]
    runningStyle: C_EnumIn[RunningStyle, ObscuredInt]
    eventShortcutType: ObscuredInt
    fanCount: ObscuredInt
    evaluationList: C_Ptr[GenericList[C_Ptr[WorkSingleModeCharaDataEvaluationObject]]]
    reservedRaceProgramId: ObscuredInt
    _ignored_7: C_UDeclPtr  # omitted: updateReservedPaceProgramId
    motivation: C_EnumIn[RaceMotivation, ObscuredInt]
    charaEffectIdArray: GenericArrayPtr[ObscuredInt]
    routeRaceIdArray: GenericArrayPtr[ObscuredInt]
    successionFactor: C_Ptr[WorkSingleModeCharaDataSuccessionFactorInfoObject]
    isShortRace: ObscuredBool
    scenarioProgress: ObscuredInt
    _ignored_8: C_UDeclPtr  # omitted: guestOutingInfoList
    race: C_Ptr[WorkSingleModeRaceDataObject]
    _ignored_9: C_UDeclPtr  # omitted: skillUpgradeList
    workScenarioURA: C_Ptr[WorkSingleModeScenarioURAObject]
    teamRace: C_Ptr[WorkSingleModeScenarioTeamRaceObject]
    raceReserveContext: C_Ptr[SingleModeRaceReserveContextObject]
    workScenarioFree: C_Ptr[WorkSingleModeScenarioFreeObject]
    scenarioLive: C_Ptr[WorkSingleModeScenarioLiveObject]
    _ignored_10: C_UDeclPtr  # omitted: scenarioVenus


@register_runtime_validatable('Gallop::WorkSingleModeCharaData')
class WorkSingleModeCharaDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeCharaDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.ParamsIncDecInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataParamsIncDecInfoFields(CStructureDataclass):
    value: ObscuredInt
    _ignored_1: ObscuredInt  # omitted: bonusValue


@register_runtime_validatable('Gallop::WorkSingleModeData.ParamsIncDecInfo')
class WorkSingleModeDataParamsIncDecInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataParamsIncDecInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.ParamsIncDecInfoDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeDataParamsIncDecInfoDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Enum[SingleModeParameterType]
    value: C_Ptr[WorkSingleModeDataParamsIncDecInfoObject]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.TrainingHorse
# ---------------------------------------------------------------------------

class WorkSingleModeDataTrainingHorseFields(CStructureDataclass):
    positionId: ObscuredInt
    isTips: ObscuredBool
    isVersusEvent: ObscuredBool
    isGuide: ObscuredBool
    isSoulExplode: ObscuredBool
    isSpSoulExplode: ObscuredBool


@register_runtime_validatable('Gallop::WorkSingleModeData.TrainingHorse')
class WorkSingleModeDataTrainingHorseObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataTrainingHorseFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.LivePerformanceIncDecInfoDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeDataLivePerformanceIncDecInfoDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Int[c_int32]
    value: C_Int[c_int32]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.TurnInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataTurnInfoFields(CStructureDataclass):
    _ignored_1: ObscuredInt  # omitted: commandType
    commandId: ObscuredInt
    isEnable: ObscuredBool
    paramIncDecInfoDic: C_Ptr[GenericDictionary[WorkSingleModeDataParamsIncDecInfoDictionaryEntry]]
    bonusParamIncDecInfoDic: C_Ptr[GenericDictionary[WorkSingleModeDataParamsIncDecInfoDictionaryEntry]]
    trainingFailureRate: C_Int[c_int32]
    trainingHorseList: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataTrainingHorseObject]]]
    livePerformanceIncDecInfoDic: C_Ptr[GenericDictionary[WorkSingleModeDataLivePerformanceIncDecInfoDictionaryEntry]]
    _ignored_2: C_UDeclPtr  # omitted: venusSpiritEffectInfoList
    _ignored_3: ObscuredInt  # omitted: venusId


@register_runtime_validatable('Gallop::WorkSingleModeData.TurnInfo')
class WorkSingleModeDataTurnInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataTurnInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeHomeInfo.TurnInfoListDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeHomeInfoTurnInfoListDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Enum[SingleModeCommandType]
    value: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataTurnInfoObject]]]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeHomeInfo
# ---------------------------------------------------------------------------

class WorkSingleModeHomeInfoFields(CStructureDataclass):
    turnInfoListDic: C_Ptr[GenericDictionary[WorkSingleModeHomeInfoTurnInfoListDictionaryEntry]]
    disableCommandIdList: C_Ptr[GenericList[ObscuredInt]]
    availableContinueNum: ObscuredInt
    availableFreeContinueNum: ObscuredInt
    freeContinueNum: ObscuredInt
    prevFreeContinueTime: ObscuredLong
    shortenedRaceState: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeHomeInfo')
class WorkSingleModeHomeInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeHomeInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.RaceCondition
# ---------------------------------------------------------------------------

class WorkSingleModeDataRaceConditionFields(CStructureDataclass):
    programId: ObscuredInt
    weather: ObscuredInt
    groundCondition: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.RaceCondition')
class WorkSingleModeDataRaceConditionObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataRaceConditionFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.SuccessionEventInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataSuccessionEventInfoFields(CStructureDataclass):
    eventId: ObscuredInt
    charaId: ObscuredInt
    effectType: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.SuccessionEventInfo')
class WorkSingleModeDataSuccessionEventInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataSuccessionEventInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.RaceStartResultInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataRaceStartResultInfoFields(CStructureDataclass):
    startInfo: C_Ptr[SingleRaceStartInfoObject]
    raceScenario: SystemStringObjectPtr
    rewardInfo: C_Ptr[CharaRaceRewardObject]
    charaInfo: C_Ptr[SingleModeCharaObject]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: addTrophyInfo, trophyRewardInfo
    prevGradeType: C_Enum[CharaGradeType]


@register_runtime_validatable('Gallop::WorkSingleModeData.RaceStartResultInfo')
class WorkSingleModeDataRaceStartResultInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataRaceStartResultInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.EventInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataEventInfoFields(CStructureDataclass):
    eventId: ObscuredInt
    charaId: ObscuredInt
    storyId: ObscuredInt
    contentsInfoSupportCardId: ObscuredInt
    selectIndexArray: GenericArrayPtr[ObscuredInt]
    receiveItemIdArray: GenericArrayPtr[ObscuredInt]
    targetRaceIdArray: GenericArrayPtr[ObscuredInt]
    gainSelectIdIndexArray: GenericArrayPtr[ObscuredInt]
    selectIconArray: GenericArrayPtr[ObscuredInt]
    playTiming: C_EnumIn[SingleModeEventPlayTiming, ObscuredInt]
    contentsInfoShowClear: ObscuredInt
    contentsInfoShowClearSortId: ObscuredInt
    isEffectedMultiChara: ObscuredBool
    tipsTrainingPartnerId: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.EventInfo')
class WorkSingleModeDataEventInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataEventInfoFields


class WorkSingleModeDataStoryInfoListDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Enum[SingleModeEventPlayTiming]
    value: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataEventInfoObject]]]


# ---------------------------------------------------------------------------
# Gallop.FactorSelectInfo
# ---------------------------------------------------------------------------

class FactorSelectInfoFields(CStructureDataclass):
    lottery_id: C_Int[c_int32]
    factor_info_array: GenericArrayPtr[C_Ptr[FactorInfoObject]]


@register_runtime_validatable('Gallop::FactorSelectInfo')
class FactorSelectInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorSelectInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeFactorSelectCommon
# ---------------------------------------------------------------------------

class SingleModeFactorSelectCommonFields(CStructureDataclass):
    rank_score: C_Int[c_int32]
    rank: C_Int[c_int32]
    lottery_remain_num: C_Int[c_int32]
    lottery_count: C_Int[c_int32]
    select_lottery_id: C_Int[c_int32]
    factor_select_info_array: GenericArrayPtr[C_Ptr[FactorSelectInfoObject]]


@register_runtime_validatable('Gallop::SingleModeFactorSelectCommon')
class SingleModeFactorSelectCommonObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeFactorSelectCommonFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData
# ---------------------------------------------------------------------------

class WorkSingleModeDataFields(CStructureDataclass):
    storyInfoListDic: C_Ptr[GenericDictionary[WorkSingleModeDataStoryInfoListDictionaryEntry]]
    _ignored_1: c_bool  # omitted: isExistPlayingData
    isPlaying: C_Bool[c_bool]
    totalTurnNum: ObscuredInt
    character: C_Ptr[WorkSingleModeCharaDataObject]
    raceConditions: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataRaceConditionObject]]]
    homeInfo: C_Ptr[WorkSingleModeHomeInfoObject]
    _ignored_2: ObscuredInt  # omitted: addMusicId
    state: C_EnumIn[SingleModeState, ObscuredInt]
    playingState: C_EnumIn[SingleModePlayingState, ObscuredInt]
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # omitted: scenarioIdList, difficultyInfoList
    changeParameterInfo: C_Ptr[WorkSingleModeChangeParameterInfoObject]
    raceHistoryInfoList: C_Ptr[GenericList[C_Ptr[RaceHistoryInfoObject]]]
    winSaddleArray: GenericArrayPtr[C_Ptr[MasterSingleModeWinsSaddleSingleModeWinsSaddleObject]]
    groupLogPool: C_UDeclPtr
    _ignored_4: ArrayType[ObscuredBool, L[4]]  # omitted: isStepTurn … isForceChangeViewMonthStartView
    _ignored_5: ArrayType[ObscuredInt, L[2]]  # omitted: selectedTrainingCommandId, rentalCount
    _ignored_6: ObscuredLong  # omitted: prevFreeRentalTime
    successionEventInfo: C_Ptr[WorkSingleModeDataSuccessionEventInfoObject]
    raceStartResultInfoData: C_Ptr[WorkSingleModeDataRaceStartResultInfoObject]
    _ignored_7: ArrayType[C_UDeclPtr, L[2]]  # omitted: racePieceCampaignInfoList, storyEventBonusDict
    resumeFactorSelect: C_Ptr[SingleModeFactorSelectCommonObject]
    _ignored_8: ArrayType[C_UDeclPtr, L[2]]  # omitted: skillUpgradeFactorSelect, eventChoiceRewardDict
    _ignored_9: c_int32  # omitted: cachedRewardEventId
    _ignored_10: C_UDeclPtr  # omitted: defaultRunningStyleArray
    _ignored_11: ObscuredBool  # omitted: isUmaplan
    _ignored_12: C_UDeclPtr  # omitted: logAdditiveBuffer


@register_runtime_validatable('Gallop::WorkSingleModeData')
class WorkSingleModeDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataFields
