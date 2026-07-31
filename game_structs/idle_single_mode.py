from __future__ import annotations

from ctypes import c_int32, c_int64
from typing import Annotated

from ctypes_utils import CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr
from game_structs.enums import IdleSingleModePlayingState
from game_structs.obscured import ObscuredBool, ObscuredInt
from game_structs.single_mode import SingleModeCharaObject
from game_structs.skills import SkillTipsObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.ObscuredCharaEffectLog
# ---------------------------------------------------------------------------

class ObscuredCharaEffectLogFields(CStructureDataclass):
    charaEffectId: ObscuredInt
    isActive: ObscuredBool


@register_runtime_validatable('Gallop::ObscuredCharaEffectLog')
class ObscuredCharaEffectLogObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredCharaEffectLogFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeSignedInt
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeSignedIntFields(CStructureDataclass):
    sign: ObscuredInt
    value: ObscuredInt


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeSignedInt')
class ObscuredIdleSingleModeSignedIntObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeSignedIntFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeGainInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeGainInfoFields(CStructureDataclass):
    speed: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    stamina: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    power: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    wiz: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    guts: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    maxSpeed: ObscuredInt
    maxStamina: ObscuredInt
    maxPower: ObscuredInt
    maxWiz: ObscuredInt
    maxGuts: ObscuredInt
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
    skillPoint: ObscuredInt
    skillTipsArray: GenericArrayPtr[C_Ptr[SkillTipsObject]]


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeGainInfo')
class ObscuredIdleSingleModeGainInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeGainInfoFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeSupportCardGainInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeSupportCardGainInfoFields(CStructureDataclass):
    supportCardId: ObscuredInt
    gainInfo: C_Ptr[ObscuredIdleSingleModeGainInfoObject]


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeSupportCardGainInfo')
class ObscuredIdleSingleModeSupportCardGainInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeSupportCardGainInfoFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredFactorInfo
# ---------------------------------------------------------------------------

class ObscuredFactorInfoFields(CStructureDataclass):
    factorId: ObscuredInt
    level: ObscuredInt


@register_runtime_validatable('Gallop::ObscuredFactorInfo')
class ObscuredFactorInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredFactorInfoFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeSuccessionFactorGainInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeSuccessionFactorGainInfoFields(CStructureDataclass):
    year: ObscuredInt
    gainFactorInfoArray: GenericArrayPtr[C_Ptr[ObscuredFactorInfoObject]]


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeSuccessionFactorGainInfo')
class ObscuredIdleSingleModeSuccessionFactorGainInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeSuccessionFactorGainInfoFields


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
    _ignored_1: C_UDeclPtr  # race_reward_limit
    gained_fans: C_Int[c_int32]
    campaign_id_array: GenericArrayPtr[c_int32]


@register_runtime_validatable('Gallop::CharaRaceReward')
class CharaRaceRewardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: CharaRaceRewardFields


# ---------------------------------------------------------------------------
# Gallop.IdleSingleModeRaceHistory
# ---------------------------------------------------------------------------

class IdleSingleModeRaceHistoryFields(CStructureDataclass):
    race_history: C_Ptr[SingleRaceHistoryObject]
    race_reward_info: C_Ptr[CharaRaceRewardObject]
    lose_tips_id: C_Int[c_int32]


@register_runtime_validatable('Gallop::IdleSingleModeRaceHistory')
class IdleSingleModeRaceHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: IdleSingleModeRaceHistoryFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeProgressLogInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeProgressLogInfoFields(CStructureDataclass):
    charaEffectLogArray: GenericArrayPtr[C_Ptr[ObscuredCharaEffectLogObject]]
    supportCardGainInfoArray: GenericArrayPtr[C_Ptr[ObscuredIdleSingleModeSupportCardGainInfoObject]]
    eventGainInfo: C_Ptr[ObscuredIdleSingleModeGainInfoObject]
    successionGainInfo: C_Ptr[ObscuredIdleSingleModeGainInfoObject]
    successionFactorGainArray: GenericArrayPtr[C_Ptr[ObscuredIdleSingleModeSuccessionFactorGainInfoObject]]
    raceHistoryArray: GenericArrayPtr[C_Ptr[IdleSingleModeRaceHistoryObject]]
    gainSkillIdArray: GenericArrayPtr[ObscuredInt]
    totalSkillPoint: ObscuredInt


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeProgressLogInfo')
class ObscuredIdleSingleModeProgressLogInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeProgressLogInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkIdleSingleModeData
# ---------------------------------------------------------------------------

class WorkIdleSingleModeDataFields(CStructureDataclass):
    state: Annotated[ObscuredInt, IdleSingleModePlayingState]
    charaInfo: C_Ptr[SingleModeCharaObject]
    startTime: C_Int[c_int64]
    endTime: C_Int[c_int64]
    _ignored_1: ObscuredInt  # singleModePlayingState
    _ignored_2: c_int32  # trainingEventType
    progressLogInfo: C_Ptr[ObscuredIdleSingleModeProgressLogInfoObject]
    _ignored_3: C_UDeclPtr  # workCharaData


@register_runtime_validatable('Gallop::WorkIdleSingleModeData')
class WorkIdleSingleModeDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkIdleSingleModeDataFields
