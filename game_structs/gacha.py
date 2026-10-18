"""Retained gacha executions and history-dialog records."""
from __future__ import annotations

from ctypes import c_bool, c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Bool, C_Enum, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr, GenericList
from game_structs.enums import GachaCardType, GachaConsumptionType, GachaDrawType, GachaExecutionType, ItemCategory
from game_structs.strings import SystemStringObjectPtr
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.GachaItemReward
# ---------------------------------------------------------------------------

class GachaItemRewardFields(CStructureDataclass):
    itemCategory: C_Enum[ItemCategory]
    itemId: C_Int[c_int32]
    itemNum: C_Int[c_int32]
    _ignored_1: ArrayType[c_int32, L[2]]  # omitted: beforeNum, afterNum


@register_runtime_validatable('Gallop::GachaItemReward')
class GachaItemRewardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaItemRewardFields


# ---------------------------------------------------------------------------
# Gallop.GachaCardResult
# ---------------------------------------------------------------------------

class GachaCardResultFields(CStructureDataclass):
    cardType: C_Enum[GachaCardType]
    cardId: C_Int[c_int32]
    convertPiece: C_Ptr[GachaItemRewardObject]
    convertItem: C_Ptr[GachaItemRewardObject]
    order: C_Int[c_int32]
    isNew: C_Bool[c_bool]


@register_runtime_validatable('Gallop::GachaCardResult')
class GachaCardResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaCardResultFields


# ---------------------------------------------------------------------------
# Gallop.GachaConsumption
# ---------------------------------------------------------------------------

class GachaConsumptionFields(CStructureDataclass):
    itemType: C_Enum[GachaConsumptionType]
    itemId: C_Int[c_int32]
    cost: C_Int[c_int32]
    drawType: C_Enum[GachaDrawType]


@register_runtime_validatable('Gallop::GachaConsumption')
class GachaConsumptionObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaConsumptionFields


# ---------------------------------------------------------------------------
# Gallop.GachaExecutableUnit
# ---------------------------------------------------------------------------

class GachaExecutableUnitFields(CStructureDataclass):
    parentGachaId: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: drawCount
    consumption: C_Ptr[GachaConsumptionObject]
    _ignored_2: C_UDeclPtr  # omitted: guarantee
    _ignored_3: ArrayType[c_bool, L[3]]  # omitted: isDrawEnd, isOnlyOnce, isFree
    _ignored_4: c_int32  # omitted: stockCount
    _ignored_5: ArrayType[c_bool, L[2]]  # omitted: isPointLimit, canMultipleExecute


@register_runtime_validatable('Gallop::GachaExecutableUnit')
class GachaExecutableUnitObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaExecutableUnitFields


# ---------------------------------------------------------------------------
# Gallop.GachaExecutionResult
# ---------------------------------------------------------------------------

class GachaExecutionResultFields(CStructureDataclass):
    parentGachaId: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: cardType
    executionType: C_Enum[GachaExecutionType]
    _ignored_2: ArrayType[c_bool, L[2]]  # omitted: isRetryable, isPointLimit
    gachaData: C_UDeclPtr
    executable: C_Ptr[GachaExecutableUnitObject]
    _ignored_3: C_UDeclPtr  # omitted: exchangeable


@register_runtime_validatable('Gallop::GachaExecutionResult')
class GachaExecutionResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaExecutionResultFields


# ---------------------------------------------------------------------------
# Gallop.GachaLimitPointResult
# ---------------------------------------------------------------------------

class GachaLimitPointResultFields(CStructureDataclass):
    gachaId: C_Int[c_int32]
    before: C_Int[c_int32]
    after: C_Int[c_int32]


@register_runtime_validatable('Gallop::GachaLimitPointResult')
class GachaLimitPointResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaLimitPointResultFields


# ---------------------------------------------------------------------------
# Gallop.GachaPrizeReward
# ---------------------------------------------------------------------------

class GachaPrizeRewardFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # omitted: gachaData
    winPrize: C_Int[c_int32]
    _ignored_2: C_UDeclPtr  # omitted: rewardItemList


@register_runtime_validatable('Gallop::GachaPrizeReward')
class GachaPrizeRewardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaPrizeRewardFields


# ---------------------------------------------------------------------------
# Gallop.GachaResultSet
# ---------------------------------------------------------------------------

class GachaResultSetFields(CStructureDataclass):
    gachaData: C_UDeclPtr
    cardResultArray: GenericArrayPtr[C_Ptr[GachaCardResultObject]]
    prizeResultArray: GenericArrayPtr[C_Ptr[GachaPrizeRewardObject]]
    _ignored_1: C_UDeclPtr  # omitted: bonusResultArray
    limitPointResult: C_Ptr[GachaLimitPointResultObject]
    drawCount: C_Int[c_int32]
    _ignored_2: c_bool  # omitted: isSentPresent


@register_runtime_validatable('Gallop::GachaResultSet')
class GachaResultSetObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaResultSetFields


# ---------------------------------------------------------------------------
# Gallop.TempData.GachaResultTempData
# ---------------------------------------------------------------------------

class GachaResultTempDataFields(CStructureDataclass):
    executionResult: C_Ptr[GachaExecutionResultObject]
    resultSet: C_Ptr[GachaResultSetObject]


@register_runtime_validatable('Gallop::TempData.GachaResultTempData')
class GachaResultTempDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaResultTempDataFields


# ---------------------------------------------------------------------------
# Gallop.GachaHistoryRewardData
# ---------------------------------------------------------------------------

class GachaHistoryRewardFields(CStructureDataclass):
    execHistoryId: C_Int[c_int32]
    dispOrder: C_Int[c_int32]
    cardType: C_Int[c_int32]
    cardId: C_Int[c_int32]
    pieceId: C_Int[c_int32]
    commonItemCategory: C_Int[c_int32]
    commonItemId: C_Int[c_int32]
    convertPieceNum: C_Int[c_int32]
    convertCommonItemNum: C_Int[c_int32]
    additionalPieceNum: C_Int[c_int32]


@register_runtime_validatable('Gallop::GachaHistoryRewardData')
class GachaHistoryRewardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaHistoryRewardFields


# ---------------------------------------------------------------------------
# Gallop.GachaHistoryExecData
# ---------------------------------------------------------------------------

class GachaHistoryExecFields(CStructureDataclass):
    execHistoryId: C_Int[c_int32]
    gachaId: C_Int[c_int32]
    cardType: C_Int[c_int32]
    costId: C_Int[c_int32]
    costCount: C_Int[c_int32]
    drawNum: C_Int[c_int32]
    drawType: C_Int[c_int32]
    createTime: SystemStringObjectPtr
    rewardArray: GenericArrayPtr[C_Ptr[GachaHistoryRewardObject]]


@register_runtime_validatable('Gallop::GachaHistoryExecData')
class GachaHistoryExecObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GachaHistoryExecFields


# ---------------------------------------------------------------------------
# Gallop.DialogGachaHistory
# ---------------------------------------------------------------------------

class DialogGachaHistoryFields(CStructureDataclass):
    m_CachedPtr: C_UDeclPtr
    _ignored_1: C_UDeclPtr  # omitted: m_CancellationTokenSource
    dialogData: C_UDeclPtr
    _ignored_2: c_int32  # omitted: overrideDialogHash
    _ignored_3: ArrayType[C_UDeclPtr, L[4]]  # omitted: loopScrollArray … flickableObject
    cardHistoryList: C_Ptr[GenericList[C_Ptr[GachaHistoryExecObject]]]
    supportCardHistoryList: C_Ptr[GenericList[C_Ptr[GachaHistoryExecObject]]]
    _ignored_4: c_int32  # omitted: tab


@register_runtime_validatable('Gallop::DialogGachaHistory')
class DialogGachaHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: DialogGachaHistoryFields
