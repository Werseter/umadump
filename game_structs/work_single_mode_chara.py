from __future__ import annotations

from ctypes import c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Enum, C_EnumIn, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr, GenericDictionary, GenericDictionaryEntry, GenericList
from game_structs.enums import ProperGrade, RaceMotivation, RunningStyle, TrainingCommandId
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredStringPtr
from game_structs.single_mode_race import SingleModeRaceReserveContextObject, WorkSingleModeRaceDataObject
from game_structs.single_mode_scenarios import (WorkSingleModeScenarioFreeObject, WorkSingleModeScenarioLiveObject,
                                                WorkSingleModeScenarioTeamRaceObject, WorkSingleModeScenarioURAObject)
from game_structs.skills import AcquiredSkillObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


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

class WorkSingleModeCharaDataTrainingLevelDictionaryEntry(GenericDictionaryEntry):
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
