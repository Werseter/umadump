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


# ---------------------------------------------------------------------------
# Gallop.WorkAlreadyReadData
# ---------------------------------------------------------------------------

class WorkAlreadyReadDataFields(CStructureDataclass):
    readHomeStoryIdList: C_Ptr[GenericList[c_int32]]
    _ignored_1: ArrayType[C_UDeclPtr, L[5]]  # omitted: readShortStoryIdList … readHomeBannerIdList


@register_runtime_validatable('Gallop::WorkAlreadyReadData')
class WorkAlreadyReadDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkAlreadyReadDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkTalkGalleryData.NewTriiger
# ---------------------------------------------------------------------------

class WorkTalkGalleryDataNewTriigerFields(CStructureDataclass):
    id: C_Int[c_int32]
    charaId: C_Int[c_int32]


@register_runtime_validatable('Gallop::WorkTalkGalleryData.NewTriiger')
class WorkTalkGalleryDataNewTriigerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTalkGalleryDataNewTriigerFields


# ---------------------------------------------------------------------------
# Gallop.WorkTalkGalleryData
# ---------------------------------------------------------------------------

class WorkTalkGalleryDataFields(CStructureDataclass):
    newInfoList: C_Ptr[GenericList[C_Ptr[WorkTalkGalleryDataNewTriigerObject]]]


@register_runtime_validatable('Gallop::WorkTalkGalleryData')
class WorkTalkGalleryDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTalkGalleryDataFields
