from __future__ import annotations

from ctypes import c_bool, c_int32, c_int64
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Enum, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr
from game_structs.enums import RoundResultType
from game_structs.obscured import ObscuredInt, ObscuredLong, ObscuredStringPtr
from game_structs.race import RaceHorseDataObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumResultBonusData
# ---------------------------------------------------------------------------

class TeamStadiumResultBonusDataFields(CStructureDataclass):
    score_bonus_id: C_Int[c_int32]
    bonus_score: C_Int[c_int32]
    condition_type: C_Int[c_int32]
    condition_value_1: C_Int[c_int32]
    condition_value_2: C_Int[c_int32]
    score_rate: C_Int[c_int32]


@register_runtime_validatable('Gallop::TeamStadiumResultBonusData')
class TeamStadiumResultBonusDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumResultBonusDataFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumResultScoreData
# ---------------------------------------------------------------------------

class TeamStadiumResultScoreDataFields(CStructureDataclass):
    raw_score_id: C_Int[c_int32]
    num: C_Int[c_int32]
    score: C_Int[c_int32]
    bonus_array: GenericArrayPtr[C_Ptr[TeamStadiumResultBonusDataObject]]


@register_runtime_validatable('Gallop::TeamStadiumResultScoreData')
class TeamStadiumResultScoreDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumResultScoreDataFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumRaceCharaResult
# ---------------------------------------------------------------------------

class TeamStadiumRaceCharaResultFields(CStructureDataclass):
    viewer_id: C_Int[c_int64]
    frame_order: C_Int[c_int32]
    trained_chara_id: C_Int[c_int32]
    team_id: C_Int[c_int32]
    finish_order: C_Int[c_int32]
    finish_time: C_Int[c_int32]
    score_array: GenericArrayPtr[C_Ptr[TeamStadiumResultScoreDataObject]]


@register_runtime_validatable('Gallop::TeamStadiumRaceCharaResult')
class TeamStadiumRaceCharaResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumRaceCharaResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData.OpponentData
# ---------------------------------------------------------------------------

class WorkTeamStadiumOpponentDataFields(CStructureDataclass):
    _ignored_1: ObscuredLong  # opponentViewerId
    evaluationPoint: ObscuredInt
    _ignored_2: ArrayType[C_UDeclPtr, L[2]]  # userData, deckInfo
    winningRewardGuaranteeStatus: ObscuredInt
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # serverData, trainedCharaDic


@register_runtime_validatable('Gallop::WorkTeamStadiumData.OpponentData')
class WorkTeamStadiumOpponentDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTeamStadiumOpponentDataFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumSupportCardBonusInfo
# ---------------------------------------------------------------------------

class TeamStadiumSupportCardBonusInfoFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # supportCardBonusList
    totalSupportCardBonus: C_Int[c_int32]


@register_runtime_validatable('Gallop::TeamStadiumSupportCardBonusInfo')
class TeamStadiumSupportCardBonusInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumSupportCardBonusInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData.TeamStadiumResult.RaceResult
# ---------------------------------------------------------------------------

class TeamStadiumRaceResultFields(CStructureDataclass):
    raceNum: ObscuredInt
    round: ObscuredInt
    raceInstanceId: ObscuredInt
    weather: ObscuredInt
    season: ObscuredInt
    groundCondition: ObscuredInt
    randomSeed: ObscuredInt
    raceScenario: ObscuredStringPtr
    teamTotalScore: ObscuredInt
    raceHorseDataArray: GenericArrayPtr[C_Ptr[RaceHorseDataObject]]
    charaResultArray: GenericArrayPtr[C_Ptr[TeamStadiumRaceCharaResultObject]]
    teamScoreArray: GenericArrayPtr[C_Ptr[TeamStadiumResultScoreDataObject]]
    roundResult: C_Enum[RoundResultType]
    currentConsecutiveWinCount: ObscuredInt
    bonusRateByNextWin: ObscuredInt


@register_runtime_validatable('Gallop::WorkTeamStadiumData.TeamStadiumResult.RaceResult')
class TeamStadiumRaceResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumRaceResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData.TeamStadiumResult
# ---------------------------------------------------------------------------

class TeamStadiumResultFields(CStructureDataclass):
    useItemIdArray: GenericArrayPtr[c_int32]
    raceResultArray: GenericArrayPtr[C_Ptr[TeamStadiumRaceResultObject]]
    isIncludeUnsupportedRace: C_Int[c_bool]
    _ignored_1: C_UDeclPtr  # winningRewardInfoArray


@register_runtime_validatable('Gallop::WorkTeamStadiumData.TeamStadiumResult')
class TeamStadiumResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumResultFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumStatus
# ---------------------------------------------------------------------------

class TeamStadiumStatusFields(CStructureDataclass):
    _ignored_1: c_int32  # currentState
    _ignored_2: C_UDeclPtr  # myDeckInfo
    opponentData: C_Ptr[WorkTeamStadiumOpponentDataObject]
    result: C_Ptr[TeamStadiumResultObject]
    _ignored_3: ArrayType[c_int32, L[2]]  # supportCartBonus, simulateRaceRound


@register_runtime_validatable('Gallop::TeamStadiumStatus')
class TeamStadiumStatusObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumStatusFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData
# ---------------------------------------------------------------------------

class WorkTeamStadiumDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # teamStadiumInfo, teamStadiumDeckInfo
    teamStadiumStatus: C_Ptr[TeamStadiumStatusObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[6]]  # opponentDataList … teamStadiumMenuBgmInfo
    teamStadiumSupportCardBonusInfo: C_Ptr[TeamStadiumSupportCardBonusInfoObject]
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # teamEvaluationUpdateRankRewardArray, updateTeamRankInfo
    _ignored_4: c_bool  # needNotifyBadge
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # stadiumRaceCharaIdArray, prevMemberList


@register_runtime_validatable('Gallop::WorkTeamStadiumData')
class WorkTeamStadiumDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTeamStadiumDataFields
