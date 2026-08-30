from __future__ import annotations

from ctypes import c_bool, c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericDictionary, GenericList
from game_structs.obscured import ObscuredInt
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkGalleryData
# ---------------------------------------------------------------------------

class GalleryEventDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: next
    key: C_Int[c_int32]
    value: C_Ptr[GenericList[ObscuredInt]]


class WorkGalleryDataFields(CStructureDataclass):
    _ignored_1: c_bool  # omitted: isPlayingEventGallery
    _ignored_2: C_UDeclPtr  # omitted: Character
    _ignored_3: ObscuredInt  # omitted: scenarioId
    _ignored_4: c_int32  # omitted: isPreSpeedType
    eventDataDict: C_Ptr[GenericDictionary[GalleryEventDataDictionaryEntry]]
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # omitted: newFlagDict, updateNewFlagIDList
    _ignored_6: c_int32  # omitted: OverrideSupportCardID


@register_runtime_validatable('Gallop::WorkGalleryData')
class WorkGalleryDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkGalleryDataFields
