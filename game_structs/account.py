"""Account currency and item storage exposed by WorkDataManager."""
from __future__ import annotations

from ctypes import c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericDictionary
from game_structs.obscured import ObscuredInt, ObscuredLong, ObscuredULong
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkUserData.CarrotStoneInfo
# ---------------------------------------------------------------------------

class CarrotStoneInfoFields(CStructureDataclass):
    chargeCoin: ObscuredInt
    freeCoin: ObscuredInt
    _ignored_1: C_UDeclPtr  # omitted: updateSubject


@register_runtime_validatable('Gallop::WorkUserData.CarrotStoneInfo')
class CarrotStoneInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: CarrotStoneInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkUserData
# ---------------------------------------------------------------------------

class WorkUserDataFields(CStructureDataclass):
    viewerId: ObscuredLong
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # omitted: userName, honorIconModel, lastLoginTime
    carrotStone: C_Ptr[CarrotStoneInfoObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[3]]  # omitted: trainerPoint, racePoint, progress
    _ignored_3: ArrayType[ObscuredInt, L[6]]  # omitted: tutorialStep … supportCardId
    _ignored_4: ObscuredULong  # omitted: fan
    _ignored_5: ObscuredInt  # omitted: birth
    _ignored_6: ArrayType[C_UDeclPtr, L[2]]  # omitted: comment, createTime
    _ignored_7: ArrayType[ObscuredInt, L[3]]  # omitted: directoryLevel, directoryScore, gender
    _ignored_8: C_UDeclPtr  # omitted: trainerBirthDay
    _ignored_9: ArrayType[ObscuredInt, L[3]]  # omitted: bestTeamEvaluationPoint, optinUserBirth, dmaState
    _ignored_10: ArrayType[c_int32, L[2]]  # omitted: countryType, parentalConsent


@register_runtime_validatable('Gallop::WorkUserData')
class WorkUserDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkUserDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkItemData.ItemData
# ---------------------------------------------------------------------------

class WorkItemDataItemFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # omitted: masterItemData
    itemId: ObscuredInt
    itemNum: ObscuredInt
    _ignored_2: ObscuredInt  # omitted: sortNum
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # omitted: name, comment
    _ignored_4: ObscuredInt  # omitted: category


@register_runtime_validatable('Gallop::WorkItemData.ItemData')
class WorkItemDataItemObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkItemDataItemFields


class WorkItemDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Int[c_int32]
    value: C_Ptr[WorkItemDataItemObject]


# ---------------------------------------------------------------------------
# Gallop.WorkItemData
# ---------------------------------------------------------------------------

class WorkItemDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[WorkItemDataDictionaryEntry]]
    _ignored_1: ArrayType[c_int32, L[2]]  # omitted: dailyRaceTicketPurchaseNum, legendRaceTicketPurchaseNum


@register_runtime_validatable('Gallop::WorkItemData')
class WorkItemDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkItemDataFields
