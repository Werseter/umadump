from __future__ import annotations

from ctypes import c_bool, c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Bool, C_Enum, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr, GenericDictionary, GenericIntDictionaryEntry, GenericList
from game_structs.enums import RoundResultType, SingleModeParameterType, TeamEditFlag, TeamParameterRank
from game_structs.obscured import ObscuredInt, ObscuredStringPtr
from game_structs.race import RaceHorseDataObject
from game_structs.skills import SkillDataObject, SkillTipsObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


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


class TeamSoulSkillDictionaryEntry(GenericIntDictionaryEntry):
    value: C_Ptr[WorkSingleModeScenarioTeamRaceSoulSkillInfoObject]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeScenarioTeamRace.RunRaceDeckData
# ---------------------------------------------------------------------------

class WorkSingleModeScenarioTeamRaceRunRaceDeckDataFields(CStructureDataclass):
    distanceType: ObscuredInt
    memberId: ObscuredInt
    charaId: ObscuredInt
    runningStyle: ObscuredInt
    round: ObscuredInt
    raceFrameOrder: ObscuredInt
    _ignored_1: C_UDeclPtr  # omitted: playerTeamMember
    motivation: ObscuredInt
    _ignored_2: ArrayType[c_bool, L[4]]  # omitted: isPlayerTeam, isSingleModeChara, isRivalChara, isMobChara
    _ignored_3: ArrayType[c_int32, L[5]]  # omitted: mobId, mobCharaId, npcUniqueCharaSupCardId, npcCharaDressId, npcId
    opponentInfo: C_Ptr[SingleModeTeamRandomInfoObject]


@register_runtime_validatable('Gallop::WorkSingleModeScenarioTeamRace.RunRaceDeckData')
class WorkSingleModeScenarioTeamRaceRunRaceDeckDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeScenarioTeamRaceRunRaceDeckDataFields


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
    _ignored_5: C_UDeclPtr  # omitted: teamRaceDeckTeamMemberList
    runRaceDeckDataList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioTeamRaceRunRaceDeckDataObject]]]
    _ignored_6: c_int32  # omitted: selectedTeamRaceSetId
    singleTeamResultList: C_Ptr[GenericList[C_Ptr[WorkSingleModeScenarioTeamRaceSingleTeamRaceResultObject]]]
    teamFrameOrderArray: GenericArrayPtr[C_Ptr[SingleModeTeamFrameOrderObject]]
    opponentListArray: GenericArrayPtr[C_Ptr[SingleModeTeamOpponentListObject]]
    selectedOpponent: C_Ptr[SingleModeTeamOpponentListObject]
    teamEventEffectInfo: C_Ptr[SingleModeTeamEventEffectInfoObject]
    teamRaceHistoryArray: GenericArrayPtr[C_Ptr[SingleModeTeamRaceHistoryObject]]
    skillTipsArray: GenericArrayPtr[C_Ptr[SkillTipsObject]]
    soulSkillTipsDictionary: C_Ptr[GenericDictionary[TeamSoulSkillDictionaryEntry]]
    spSoulSkillTipsDictionary: C_Ptr[GenericDictionary[TeamSoulSkillDictionaryEntry]]
    _ignored_7: C_UDeclPtr  # omitted: deckBuilder
    _ignored_8: ArrayType[c_int32, L[2]]  # omitted: playerMemberCount, gameQuality
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
