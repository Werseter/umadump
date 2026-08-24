from __future__ import annotations

from ctypes import c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Enum, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr, GenericDictionary
from game_structs.enums import TrainingType
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredLong
from game_structs.skills import AcquirableSkillObject, AcquiredSkillObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkCardData.CardData
# ---------------------------------------------------------------------------

class HintLevelDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: ObscuredInt
    value: ObscuredInt


class CardDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # masterCard … masterChara / masterDataPtrs
    cardId: ObscuredInt
    talentLevel: ObscuredInt
    rarity: ObscuredInt
    hintLevelDic: C_Ptr[GenericDictionary[HintLevelDictionaryEntry]]
    _ignored_2: ObscuredInt  # changedModelDressId
    createTime: ObscuredLong
    _ignored_3: ArrayType[ObscuredInt, L[5]]  # speed … wiz
    uniqueSkill: C_Ptr[AcquiredSkillObject]
    acquirableSkillArray: GenericArrayPtr[C_Ptr[AcquirableSkillObject]]


@register_runtime_validatable('Gallop::WorkCardData.CardData')
class CardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: CardDataFields


class CardDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[CardDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkCardData
# ---------------------------------------------------------------------------

class WorkCardDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[CardDataDictionaryEntry]]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # releaseCardIdList, BackableStateStack


@register_runtime_validatable('Gallop::WorkCardData')
class WorkCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkCardDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkSupportCardData.SupportCardData
# ---------------------------------------------------------------------------

class SupportCardDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[6]]  # masterSupportCard … masterUniqueEffect
    supportCardId: ObscuredInt
    level: ObscuredInt
    limitBreakCount: ObscuredInt
    maxLevel: ObscuredInt
    createTime: ObscuredLong
    exp: ObscuredInt
    stock: ObscuredInt
    isFavoriteLock: ObscuredBool
    bestTraining: C_Enum[TrainingType]
    _ignored_2: C_UDeclPtr  # SkillTriggerTagArray


@register_runtime_validatable('Gallop::WorkSupportCardData.SupportCardData')
class SupportCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SupportCardDataFields


class SupportCardDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[SupportCardDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkSupportCardData
# ---------------------------------------------------------------------------

class WorkSupportCardDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[SupportCardDataDictionaryEntry]]
    _ignored_1: C_UDeclPtr  # BackableStateStack


@register_runtime_validatable('Gallop::WorkSupportCardData')
class WorkSupportCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSupportCardDataFields
