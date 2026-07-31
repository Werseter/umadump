from __future__ import annotations

from ctypes import c_bool, c_int32, c_int64
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredLong
from game_structs.skills import SkillDataObject, SkillTipsObject
from game_structs.strings import SystemStringObjectPtr
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
    _ignored_1: c_int32  # training_partner_state
    owner_viewer_id: C_Int[c_int64]
    _ignored_2: c_int32  # rental_type


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
# Gallop.WorkSingleModeData.RaceStartResultInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataRaceStartResultInfoFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # startInfo, raceScenario, rewardInfo
    charaInfo: C_Ptr[SingleModeCharaObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[2]]  # addTrophyInfo, trophyRewardInfo
    _ignored_3: c_int32  # prevCharaGrade


@register_runtime_validatable('Gallop::WorkSingleModeData.RaceStartResultInfo')
class WorkSingleModeDataRaceStartResultInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataRaceStartResultInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData
# ---------------------------------------------------------------------------

class WorkSingleModeDataFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # storyInfoListDic
    _ignored_2: ArrayType[c_bool, L[2]]  # isExistPlayingData, isPlaying
    totalTurnNum: ObscuredInt
    _ignored_3: ArrayType[C_UDeclPtr, L[3]]  # character, raceConditions, homeInfo
    _ignored_4: ArrayType[ObscuredInt, L[3]]  # addMusicId, state, playingState
    _ignored_5: ArrayType[C_UDeclPtr, L[6]]  # scenarioIdList … groupLogPool
    _ignored_6: ArrayType[ObscuredBool, L[4]]  # isStepTurn … isForceChangeViewMonthStartView
    _ignored_7: ArrayType[ObscuredInt, L[2]]  # selectedTrainingCommandId, rentalCount
    _ignored_8: ObscuredLong  # prevFreeRentalTime
    _ignored_9: C_UDeclPtr  # successionEventInfo
    raceStartResultInfoData: C_Ptr[WorkSingleModeDataRaceStartResultInfoObject]
    _ignored_10: ArrayType[C_UDeclPtr, L[5]]  # racePieceCampaignInfoList … eventChoiceRewardDict
    _ignored_11: c_int32  # cachedRewardEventId
    _ignored_12: C_UDeclPtr  # defaultRunningStyleArray
    _ignored_13: ObscuredBool  # isUmaplan
    _ignored_14: C_UDeclPtr  # logAdditiveBuffer


@register_runtime_validatable('Gallop::WorkSingleModeData')
class WorkSingleModeDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataFields
