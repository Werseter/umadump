from __future__ import annotations

from ctypes import c_bool, c_int32

from ctypes_utils import CStructureDataclass, C_Int, C_Ptr
from game_structs.collections import GenericDictionary, GenericList
from game_structs.obscured import ObscuredInt
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkTrophyData.CharaIdList
# ---------------------------------------------------------------------------

class TrophyDataCharaIdListFields(CStructureDataclass):
    charaId: ObscuredInt
    winCount: ObscuredInt


@register_runtime_validatable('Gallop::WorkTrophyData.CharaIdList')
class TrophyDataCharaIdListObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrophyDataCharaIdListFields


class TrophyDataCharaIdListDictionaryInnerEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[TrophyDataCharaIdListObject]


class TrophyDataCharaIdListDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[GenericDictionary[TrophyDataCharaIdListDictionaryInnerEntry]]


# ---------------------------------------------------------------------------
# Gallop.WorkTrophyData.TrophyData
# ---------------------------------------------------------------------------

class TrophyDataFields(CStructureDataclass):
    trophyId: ObscuredInt
    charaIdList: C_Ptr[GenericList[c_int32]]
    raceCharaDataDic: C_Ptr[GenericDictionary[TrophyDataCharaIdListDictionaryEntry]]
    _ignored_1: c_bool  # isNew


@register_runtime_validatable('Gallop::WorkTrophyData.TrophyData')
class TrophyDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrophyDataFields


class TrophyDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[TrophyDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkTrophyData
# ---------------------------------------------------------------------------

class WorkTrophyDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[TrophyDataDictionaryEntry]]
    _ignored_1: c_bool  # isNew


@register_runtime_validatable('Gallop::WorkTrophyData')
class WorkTrophyDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTrophyDataFields
