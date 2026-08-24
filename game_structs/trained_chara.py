from __future__ import annotations

from ctypes import c_bool, c_int32, c_int64
from typing import Annotated, Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Enum, C_EnumIn, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr, GenericDictionary, GenericList
from game_structs.enums import FinalTrainingRank, SuccessionCharaPosition, TrainedCharaUseType
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredLong, ObscuredStringPtr
from game_structs.skills import AcquiredSkillObject
from game_structs.strings import SystemStringObjectPtr
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData.UpgradeHistory
# ---------------------------------------------------------------------------

class FactorDataUpgradeHistoryFields(CStructureDataclass):
    factorId: ObscuredInt
    upgradeDate: ObscuredLong


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData'
                              '.FactorData.UpgradeHistory')
class FactorDataUpgradeHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorDataUpgradeHistoryFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData
# ---------------------------------------------------------------------------

class FactorDataFields(CStructureDataclass):
    factorLv: ObscuredInt
    factorId: ObscuredInt
    baseFactorId: ObscuredInt
    upgradeHistoryList: C_Ptr[GenericList[C_Ptr[FactorDataUpgradeHistoryObject]]]


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData')
class FactorDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.FavoriteData
# ---------------------------------------------------------------------------

class FavoriteDataFields(CStructureDataclass):
    trainedCharaId: C_Int[c_int32]
    type: C_Int[c_int32]
    memo: SystemStringObjectPtr


@register_runtime_validatable('Gallop::WorkTrainedCharaData.FavoriteData')
class FavoriteDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FavoriteDataFields


class FavoriteDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[FavoriteDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData
# ---------------------------------------------------------------------------

class SuccessionCharaDataFields(CStructureDataclass):
    positionId: C_EnumIn[SuccessionCharaPosition, ObscuredInt]
    cardId: ObscuredInt
    rarity: ObscuredInt
    level: ObscuredInt
    rank: C_EnumIn[FinalTrainingRank, ObscuredInt]
    factorDataArray: GenericArrayPtr[C_Ptr[FactorDataObject]]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # _sortedFactorList, _sortedFactorListForProfileCard / masterDataPtrs
    ownerViewerId: ObscuredLong
    isPlayer: C_Int[c_bool]
    _ignored_2: C_UDeclPtr  # winSaddleArray / masterDataPtr
    winSaddleIdArray: GenericArrayPtr[ObscuredInt]


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData')
class SuccessionCharaDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SuccessionCharaDataFields


# ---------------------------------------------------------------------------
# Gallop.SuccessionHistory
# ---------------------------------------------------------------------------

class SuccessionHistoryFields(CStructureDataclass):
    id: C_Int[c_int32]
    viewer_id: C_Int[c_int64]
    trained_chara_id: C_Int[c_int32]
    hisotry_type: C_Int[c_int32]
    succession_card_id: C_Int[c_int32]
    date: C_Int[c_int32]
    user_name: SystemStringObjectPtr
    circle_name: SystemStringObjectPtr


@register_runtime_validatable('Gallop::SuccessionHistory')
class SuccessionHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SuccessionHistoryFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.SupportCardData
# ---------------------------------------------------------------------------

class TrainedCharaSupportCardDataFields(CStructureDataclass):
    position: ObscuredInt
    supportCardId: ObscuredInt
    limitBreakCount: ObscuredInt
    exp: ObscuredInt


@register_runtime_validatable('Gallop::WorkTrainedCharaData.SupportCardData')
class TrainedCharaSupportCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainedCharaSupportCardDataFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeUtils.RaceHistoryInfo
# ---------------------------------------------------------------------------

class RaceHistoryInfoFields(CStructureDataclass):
    turn: ObscuredInt
    programId: ObscuredInt
    _ignored_1: ObscuredInt  # raceInstanceId
    _ignored_2: ObscuredInt  # frameOrder
    _ignored_3: ObscuredInt  # npcCount
    weather: ObscuredInt
    groundCondition: ObscuredInt
    runningStyle: ObscuredInt
    resultRank: ObscuredInt
    _ignored_4: ObscuredInt  # scenarioId


@register_runtime_validatable('Gallop::SingleModeUtils.RaceHistoryInfo')
class RaceHistoryInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceHistoryInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData
# ---------------------------------------------------------------------------

class TrainedCharaDataFields(CStructureDataclass):
    id: ObscuredInt
    isSaved: ObscuredBool
    viewerId: ObscuredLong
    ownerViewerId: ObscuredLong
    ownerTrainedCharaId: ObscuredInt
    useType: C_Enum[TrainedCharaUseType]
    cardId: ObscuredInt
    nickNameId: ObscuredInt
    nickNameIdArray: GenericArrayPtr[ObscuredInt]
    stamina: ObscuredInt
    speed: ObscuredInt
    power: ObscuredInt
    guts: ObscuredInt
    wiz: ObscuredInt
    fans: ObscuredInt
    rank: C_EnumIn[FinalTrainingRank, ObscuredInt]
    rankScore: ObscuredInt
    runningStyle: ObscuredInt
    properGroundTurf: ObscuredInt
    properGroundDirt: ObscuredInt
    properDistanceShort: ObscuredInt
    properDistanceMile: ObscuredInt
    properDistanceMiddle: ObscuredInt
    properDistanceLong: ObscuredInt
    properRunningStyleNige: ObscuredInt
    properRunningStyleSenko: ObscuredInt
    properRunningStyleSashi: ObscuredInt
    properRunningStyleOikomi: ObscuredInt
    successionCount: ObscuredInt
    factorDataArray: GenericArrayPtr[C_Ptr[FactorDataObject]]
    createTime: ObscuredStringPtr
    scenarioId: ObscuredInt
    talentLevel: ObscuredInt
    charaGrade: ObscuredInt
    rarity: ObscuredInt
    isLock: ObscuredBool
    favoriteData: C_Ptr[FavoriteDataObject]
    cachedCreateTimeTimeStamp: ObscuredLong
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # sortedFactorList … sortedFactorProfileCardList / masterDataPtrs
    successionCharaList: C_Ptr[GenericList[C_Ptr[SuccessionCharaDataObject]]]
    _ignored_2: c_bool  # isSuccessionHistoryInitialized
    _ignored_3: C_UDeclPtr  # successionHistoryList
    acquiredSkillArray: GenericArrayPtr[C_Ptr[AcquiredSkillObject]]
    supportCardArray: GenericArrayPtr[C_Ptr[TrainedCharaSupportCardDataObject]]
    singleModeRaceResultArray: GenericArrayPtr[C_Ptr[RaceHistoryInfoObject]]
    _ignored_4: C_UDeclPtr  # winSaddleArray / masterDataPtr
    winSaddleIdArray: GenericArrayPtr[ObscuredInt]
    cacheCharaId: ObscuredInt
    _ignored_5: ArrayType[C_UDeclPtr, L[3]]  # masterCardData, masterCharaData, masterCardRarityData / masterDataPtrs
    singleTotalRaceNum: C_Int[c_int32]
    singleWinNum: ObscuredInt
    _ignored_6: C_UDeclPtr  # trainedCharaDataAccessor


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData')
class TrainedCharaDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainedCharaDataFields


class TrainedCharaDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[TrainedCharaDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData
# ---------------------------------------------------------------------------

class WorkTrainedCharaDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[TrainedCharaDataDictionaryEntry]]
    allDataDic: C_Ptr[GenericDictionary[TrainedCharaDataDictionaryEntry]]
    _ignored_1: C_UDeclPtr  # list
    favoriteDataDict: C_Ptr[GenericDictionary[FavoriteDataDictionaryEntry]]


@register_runtime_validatable('Gallop::WorkTrainedCharaData')
class WorkTrainedCharaDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTrainedCharaDataFields


# ---------------------------------------------------------------------------
# Gallop.FactorInfo
# ---------------------------------------------------------------------------

class FactorInfoFields(CStructureDataclass):
    factor_id: C_Int[c_int32]
    level: C_Int[c_int32]


@register_runtime_validatable('Gallop::FactorInfo')
class FactorInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorInfoFields


# ---------------------------------------------------------------------------
# Gallop.FactorExtend
# ---------------------------------------------------------------------------

class FactorExtendFields(CStructureDataclass):
    position_id: Annotated[C_Int[c_int32], SuccessionCharaPosition]
    base_factor_id: C_Int[c_int32]
    factor_id: C_Int[c_int32]
    register_time: SystemStringObjectPtr


@register_runtime_validatable('Gallop::FactorExtend')
class FactorExtendObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorExtendFields
