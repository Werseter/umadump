from __future__ import annotations

from ctypes import c_bool, c_float, c_int32, c_int64, c_uint32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Bool, C_Enum, C_Float, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr
from game_structs.enums import (BgSeason, CardRarity, CharaGradeType, CourseDistanceType, DefeatType, InitialLaneType,
                                MainStoryRaceGimmickType, ProperGrade, RaceDifficulty, RaceGroundCondition,
                                RaceMotivation, RaceRunningType, RaceTime, RaceType, RaceWeather,
                                ResultBoardConditionType, Rotation, RunningStyleEx, TurfVisionType)
from game_structs.skills import SkillDataObject
from game_structs.strings import SystemStringObjectPtr
from game_structs.trained_chara import TrainedCharaDataObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.SingleRaceHistory
# ---------------------------------------------------------------------------

class SingleRaceHistoryFields(CStructureDataclass):
    turn: C_Int[c_int32]
    program_id: C_Int[c_int32]
    weather: C_Int[c_int32]
    ground_condition: C_Int[c_int32]
    running_style: C_Int[c_int32]
    result_rank: C_Int[c_int32]
    frame_order: C_Int[c_int32]
    npc_count: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleRaceHistory')
class SingleRaceHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleRaceHistoryFields


# ---------------------------------------------------------------------------
# Gallop.RaceRewardData
# ---------------------------------------------------------------------------

class RaceRewardDataFields(CStructureDataclass):
    item_type: C_Int[c_int32]
    item_id: C_Int[c_int32]
    item_num: C_Int[c_int32]


@register_runtime_validatable('Gallop::RaceRewardData')
class RaceRewardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceRewardDataFields


# ---------------------------------------------------------------------------
# Gallop.CharaRaceReward
# ---------------------------------------------------------------------------

class CharaRaceRewardFields(CStructureDataclass):
    result_rank: C_Int[c_int32]
    result_time: C_Int[c_int32]
    race_reward: GenericArrayPtr[C_Ptr[RaceRewardDataObject]]
    race_reward_bonus: GenericArrayPtr[C_Ptr[RaceRewardDataObject]]
    race_reward_plus_bonus: GenericArrayPtr[C_Ptr[RaceRewardDataObject]]
    race_reward_bonus_win: GenericArrayPtr[C_Ptr[RaceRewardDataObject]]
    _ignored_1: C_UDeclPtr  # omitted: race_reward_limit
    gained_fans: C_Int[c_int32]
    campaign_id_array: GenericArrayPtr[c_int32]


@register_runtime_validatable('Gallop::CharaRaceReward')
class CharaRaceRewardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: CharaRaceRewardFields


# ---------------------------------------------------------------------------
# Gallop.RaceHorseDataRaceResult
# ---------------------------------------------------------------------------

class RaceHorseDataRaceResultFields(CStructureDataclass):
    turn: C_Int[c_int32]
    program_id: C_Int[c_int32]
    result_rank: C_Int[c_int32]


@register_runtime_validatable('Gallop::RaceHorseDataRaceResult')
class RaceHorseDataRaceResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceHorseDataRaceResultFields


# ---------------------------------------------------------------------------
# Gallop.RaceHorseData
# ---------------------------------------------------------------------------

class RaceHorseDataFields(CStructureDataclass):
    viewer_id: C_Int[c_int64]
    owner_viewer_id: C_Int[c_int64]
    trainer_name: SystemStringObjectPtr
    owner_trainer_name: SystemStringObjectPtr
    single_mode_chara_id: C_Int[c_int32]
    trained_chara_id: C_Int[c_int32]
    nickname_id: C_Int[c_int32]
    card_id: C_Int[c_int32]
    chara_id: C_Int[c_int32]
    rarity: C_Int[c_int32]
    talent_level: C_Int[c_int32]
    frame_order: C_Int[c_int32]
    skill_array: GenericArrayPtr[C_Ptr[SkillDataObject]]
    stamina: C_Int[c_int32]
    speed: C_Int[c_int32]
    pow: C_Int[c_int32]
    guts: C_Int[c_int32]
    wiz: C_Int[c_int32]
    running_style: C_Int[c_int32]
    race_dress_id: C_Int[c_int32]
    chara_color_type: C_Int[c_int32]
    npc_type: C_Int[c_int32]
    final_grade: C_Int[c_int32]
    popularity: C_Int[c_int32]
    popularity_mark_rank_array: GenericArrayPtr[c_int32]
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
    motivation: C_Int[c_int32]
    mob_id: C_Int[c_int32]
    win_saddle_id_array: GenericArrayPtr[c_int32]
    race_result_array: GenericArrayPtr[C_Ptr[RaceHorseDataRaceResultObject]]
    team_id: C_Int[c_int32]
    team_member_id: C_Int[c_int32]
    item_id_array: GenericArrayPtr[c_int32]
    motivation_change_flag: C_Int[c_int32]
    frame_order_change_flag: C_Int[c_int32]
    team_rank: C_Int[c_int32]
    single_mode_win_count: C_Int[c_int32]
    fan_count: C_Int[c_int32]


@register_runtime_validatable('Gallop::RaceHorseData')
class RaceHorseDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceHorseDataFields


# ---------------------------------------------------------------------------
# Gallop.HorseData
# ---------------------------------------------------------------------------

class RaceParameterFields(CStructureDataclass):
    rawSpeed: C_Int[c_int32]
    rawStamina: C_Int[c_int32]
    rawPow: C_Int[c_int32]
    rawGuts: C_Int[c_int32]
    rawWiz: C_Int[c_int32]
    baseSpeed: C_Float[c_float]
    baseStamina: C_Float[c_float]
    basePow: C_Float[c_float]
    baseGuts: C_Float[c_float]
    baseWiz: C_Float[c_float]
    motivation: C_Enum[RaceMotivation]
    motivationCoef: C_Float[c_float]


@register_runtime_validatable('Gallop::RaceParameter')
class RaceParameterObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceParameterFields


class HorseDataFields(CStructureDataclass):
    horseIndex: C_Int[c_int32]
    postNumber: C_Int[c_int32]
    charaId: C_Int[c_int32]
    charaName: SystemStringObjectPtr
    finishOrder: C_Int[c_int32]
    finishTimeRaw: C_Float[c_float]
    finishTimeScaled: C_Float[c_float]
    finishDiffTimeFromPrev: C_Float[c_float]
    raceParam: C_Ptr[RaceParameterObject]
    responseHorseData: C_Ptr[RaceHorseDataObject]
    popularity: C_Int[c_int32]
    popularityRankLeft: C_Int[c_int32]
    popularityRankCenter: C_Int[c_int32]
    popularityRankRight: C_Int[c_int32]
    gateInPopularity: C_Int[c_int32]
    rarity: C_Enum[CardRarity]
    trainerName: SystemStringObjectPtr
    isGhost: C_Bool[c_bool]
    isRunningStyleExInitialized: C_Bool[c_bool]
    runningStyleEx: C_Enum[RunningStyleEx]
    defeat: C_Enum[DefeatType]
    raceDressId: C_Int[c_int32]
    raceDressIdWithOption: C_Int[c_int32]
    runningType: C_Enum[RaceRunningType]
    activeProperDistance: C_Enum[ProperGrade]
    activeProperGroundType: C_Enum[ProperGrade]
    mobId: C_Int[c_int32]
    _ignored_1: C_UDeclPtr  # omitted: raceRecord
    finishOrderRawScore: C_Int[c_int32]
    trainedCharaData: C_Ptr[TrainedCharaDataObject]


@register_runtime_validatable('Gallop::HorseData')
class HorseDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: HorseDataFields


# ---------------------------------------------------------------------------
# Gallop.MasterRaceCourseSet.RaceCourseSet
# ---------------------------------------------------------------------------

class RaceCourseSetFields(CStructureDataclass):
    id: C_Int[c_int32]
    raceTrackId: C_Int[c_int32]
    distance: C_Int[c_int32]
    ground: C_Int[c_int32]
    inout: C_Int[c_int32]
    turn: C_Int[c_int32]
    fenceSet: C_Int[c_int32]
    floatLaneMax: C_Int[c_int32]
    courseSetStatusId: C_Int[c_int32]
    finishTimeMin: C_Int[c_int32]
    finishTimeMinRandomRange: C_Int[c_int32]
    finishTimeMax: C_Int[c_int32]
    finishTimeMaxRandomRange: C_Int[c_int32]


@register_runtime_validatable('Gallop::MasterRaceCourseSet.RaceCourseSet')
class RaceCourseSetObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceCourseSetFields


# ---------------------------------------------------------------------------
# Gallop.RaceInfo
# ---------------------------------------------------------------------------

class RaceInfoFields(CStructureDataclass):
    raceType: C_Enum[RaceType]
    isExistPlayerRace: C_Bool[c_bool]
    isExistGhostRace: C_Bool[c_bool]
    isExistFollowRace: C_Bool[c_bool]
    isMultiplePlayerRace: C_Bool[c_bool]
    randomSeed: C_Int[c_int32]
    singleRaceProgramId: C_Int[c_int32]
    opponentEvaluate: C_Int[c_int32]
    selfEvaluate: C_Int[c_int32]
    supportCardScoreBonus: C_Int[c_int32]
    scoreCalcTeamId: C_Int[c_int32]
    raceNo: C_Int[c_int32]
    raceCourseSet: C_Ptr[RaceCourseSetObject]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: fenceSet, raceTrack
    goalGate: C_Int[c_int32]
    goalGateFlower: C_Int[c_int32]
    initialLaneType: C_Enum[InitialLaneType]
    rotationCategory: C_Enum[Rotation]
    resultBoardConditionType: C_Enum[ResultBoardConditionType]
    courseSectionDistance: C_Float[c_float]
    courseDistanceType: C_Enum[CourseDistanceType]
    courseFurlongNum: C_Int[c_int32]
    isHalfGate: C_Bool[c_bool]
    isHorseNumVariationGate: C_Bool[c_bool]
    turfVisionType: C_Enum[TurfVisionType]
    groundCondition: C_Enum[RaceGroundCondition]
    weather: C_Enum[RaceWeather]
    season: C_Enum[BgSeason]
    time: C_Enum[RaceTime]
    baseSpeed: C_Float[c_float]
    borderTimeScaled: C_Float[c_float]
    challengeMatchDifficulty: C_Enum[RaceDifficulty]
    numRaceHorses: C_Int[c_int32]
    postNumberMax: C_Int[c_int32]
    playerHorseIndex: C_Int[c_int32]
    overridePlayerHorseIndex: C_Int[c_int32]
    playerTeamMemberArray: GenericArrayPtr[C_Ptr[HorseDataObject]]
    playerTeamTopFinishOrderHorse: C_Ptr[HorseDataObject]
    isGateInPopularityInitialized: C_Bool[c_bool]
    raceHorse: GenericArrayPtr[C_Ptr[HorseDataObject]]
    _ignored_2: ArrayType[C_UDeclPtr, L[3]]  # omitted: raceBibMaster, raceMaster, raceInstanceMaster
    simDataBase64: SystemStringObjectPtr
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # omitted: simData, simReader
    episodeRaceReplayId: C_Int[c_int32]
    isNotSimulateExport: C_Bool[c_bool]
    laneDistanceMax: C_Float[c_float]
    _ignored_4: ArrayType[C_UDeclPtr, L[3]]  # omitted: replayCheckInfo, replayCheckInfoDaily, replayCheckInfoLegend
    isDailyLegendRace: C_Bool[c_bool]
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # omitted: replayCheckInfoChallengeMatch, raceRewardSingle
    resultHorseIndex: C_Int[c_int32]
    prevGradeType: C_Enum[CharaGradeType]
    mainStoryRaceGimmickType: C_Enum[MainStoryRaceGimmickType]
    isMainStoryRaceMatchGimmick: C_Bool[c_bool]
    unlockFlags: C_Int[c_uint32]
    _ignored_6: C_UDeclPtr  # omitted: phaseCalculator
    horseIndexByFinishOrder: GenericArrayPtr[c_int32]
    horseIndexByPopularity: GenericArrayPtr[c_int32]


@register_runtime_validatable('Gallop::RaceInfo')
class RaceInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceInfoFields


# ---------------------------------------------------------------------------
# Gallop.RaceManager object hierarchy
# ---------------------------------------------------------------------------

class RaceManagerStaticFields(CStructureDataclass):
    raceInfo: C_Ptr[RaceInfoObject]


class RaceManagerFields(CStructureDataclass):
    pass  # stub - we don't need fields for now


@register_runtime_validatable('Gallop::RaceManager')
class RaceManagerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceManagerFields


class RaceManagerSingletonStaticFields(CStructureDataclass):
    _isApplicationQuit: C_Bool[c_bool]
    _instance: C_Ptr[RaceManagerObject]
    _parentObject: C_UDeclPtr


@register_runtime_validatable('Gallop::MonoSingleton`1<Gallop::RaceManager>')
class RaceManagerSingleton(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
